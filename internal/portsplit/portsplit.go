// Package portsplit serves CEDAR and HTTPS on one shared-port endpoint.
//
// When SHARED_PORT_HTTP_FORWARDING_ID names a daemon's endpoint,
// condor_shared_port passes that endpoint two kinds of connection: CEDAR
// commands addressed to it (?sock=<id>), and every connection whose first
// bytes look like a TLS ClientHello or an HTTP/1 request line. It decides by
// peeking, so the bytes are still unread when the descriptor arrives.
//
// Split classifies each accepted connection the same way, by peeking at its
// first bytes without consuming them, and hands the connection itself, not a
// wrapper, to one of two listeners: Web for TLS and HTTP, CEDAR for the rest.
// The CEDAR server therefore still sees a *net.TCPConn and applies its
// keepalives and timeouts to it.
package portsplit

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ClassifyTimeout bounds how long a connection may take to send the bytes
// that classify it.
const ClassifyTimeout = 20 * time.Second

// maxPeek is the most bytes classification needs: the longest HTTP method
// with its space ("OPTIONS ", "CONNECT ").
const maxPeek = 8

// httpMethods are the request-line prefixes HTCondor's shared port forwards
// as HTTP (daemon_command.cpp LooksLikeHttpRequest).
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("TRACE "), []byte("CONNECT "), []byte("PATCH "),
}

// Kind is what a connection speaks.
type Kind int

// Connection kinds.
const (
	CEDAR Kind = iota
	TLS
	HTTP
)

func (k Kind) String() string {
	switch k {
	case TLS:
		return "tls"
	case HTTP:
		return "http"
	default:
		return "cedar"
	}
}

// Classify reports what a connection whose first bytes are b speaks, and
// whether b is enough to tell. It applies HTCondor's tests: a TLS record of
// type handshake (0x16) with major version 3 and minor version at most 4,
// or one of the HTTP methods followed by a space. Anything else is CEDAR,
// whose first byte, a frame's end flag, is 0 or 1.
func Classify(b []byte) (Kind, bool) {
	if len(b) == 0 {
		return CEDAR, false
	}
	switch c := b[0]; {
	case c == 0x16:
		if len(b) < 3 {
			return CEDAR, false
		}
		if b[1] == 0x03 && b[2] <= 0x04 {
			return TLS, true
		}
		return CEDAR, true
	case c >= 'A' && c <= 'Z':
		undecided := false
		for _, m := range httpMethods {
			if bytes.HasPrefix(b, m) {
				return HTTP, true
			}
			if bytes.HasPrefix(m, b) {
				undecided = true
			}
		}
		return CEDAR, !undecided
	default:
		return CEDAR, true
	}
}

// errClosed is returned by Accept on a closed listener.
var errClosed = net.ErrClosed

// Splitter divides one listener's connections between CEDAR and Web.
type Splitter struct {
	ln    net.Listener
	log   *slog.Logger
	cedar *sub
	web   *sub

	closeOnce sync.Once
	done      chan struct{}
	// err is why the underlying listener stopped, when it was not closed.
	err atomic.Pointer[error]
}

// Split starts accepting on ln. Closing the CEDAR listener closes ln; closing
// the Web listener only stops it receiving connections, which are then
// closed as they arrive.
func Split(ln net.Listener, log *slog.Logger) *Splitter {
	if log == nil {
		log = slog.Default()
	}
	s := &Splitter{ln: ln, log: log, done: make(chan struct{})}
	s.cedar = newSub(s, true)
	s.web = newSub(s, false)
	go s.acceptLoop()
	return s
}

// CEDAR is the listener for CEDAR connections.
func (s *Splitter) CEDAR() net.Listener { return s.cedar }

// Web is the listener for TLS and HTTP connections.
func (s *Splitter) Web() net.Listener { return s.web }

// Close closes the underlying listener and both sub-listeners.
func (s *Splitter) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.ln.Close()
	})
	return err
}

func (s *Splitter) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			select {
			case <-s.done:
			default:
				s.err.Store(&err)
			}
			_ = s.Close()
			return
		}
		go s.route(c)
	}
}

func (s *Splitter) route(c net.Conn) {
	kind, err := classifyConn(c, ClassifyTimeout)
	if err != nil {
		s.log.Debug("shared port: closing a connection that sent nothing to classify",
			"remote", remote(c), "err", err)
		_ = c.Close()
		return
	}
	dst := s.cedar
	if kind != CEDAR {
		dst = s.web
	}
	dst.deliver(c, kind)
}

// classifyConn peeks at c's first bytes, waiting up to timeout for enough of
// them, and leaves them unread.
func classifyConn(c net.Conn, timeout time.Duration) (Kind, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return CEDAR, err
	}
	kind, err := peekKind(c)
	if derr := c.SetReadDeadline(time.Time{}); err == nil && derr != nil {
		err = derr
	}
	return kind, err
}

type sub struct {
	s      *Splitter
	cedar  bool
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSub(s *Splitter, cedar bool) *sub {
	return &sub{s: s, cedar: cedar, conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *sub) deliver(c net.Conn, kind Kind) {
	select {
	case l.conns <- c:
	case <-l.closed:
		if !l.cedar {
			l.s.log.Debug("shared port: no web UI here; closing a forwarded connection",
				"remote", remote(c), "kind", kind.String())
		}
		_ = c.Close()
	case <-l.s.done:
		_ = c.Close()
	}
}

func (l *sub) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errClosed
	case <-l.s.done:
		if err := l.s.err.Load(); err != nil {
			return nil, *err
		}
		return nil, errClosed
	}
}

func (l *sub) Close() error {
	l.once.Do(func() { close(l.closed) })
	if l.cedar {
		return l.s.Close()
	}
	return nil
}

func (l *sub) Addr() net.Addr { return l.s.ln.Addr() }

// remote is c's peer for a log line. A forwarded connection whose peer has
// already gone has none.
func remote(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return "unknown"
}

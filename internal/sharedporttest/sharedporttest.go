//go:build unix

// Package sharedporttest stands in for condor_shared_port in tests: it
// accepts TCP connections and passes each one, unread, to a daemon's
// shared-port endpoint over its Unix socket, with the handshake
// condor_shared_port uses.
package sharedporttest

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/sharedport"
)

// Endpoint is a daemon's shared-port endpoint and the port in front of it.
type Endpoint struct {
	// Listener is what the daemon accepts forwarded connections on.
	Listener *sharedport.Listener
	// Addr is the TCP address clients connect to.
	Addr string
}

// New creates an endpoint socket in a temporary directory, as condor_master
// does for a daemon, and a TCP port on loopback that forwards every
// connection to it. Both are closed when the test ends.
func New(t *testing.T) *Endpoint {
	t.Helper()
	// A short directory: a Unix socket path is limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "ep")
	ln, err := sharedport.Listen(path, sharedport.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	front, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close() })
	go func() {
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			go forward(path, c)
		}
	}()
	return &Endpoint{Listener: ln, Addr: front.Addr().String()}
}

func forward(path string, c net.Conn) {
	defer func() { _ = c.Close() }()
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return
	}
	defer func() { _ = u.Close() }()
	if err := sharedport.SendForwardedConn(ctx, u.(*net.UnixConn), f.Fd()); err != nil {
		return
	}
	// Keep this side's copy open until the endpoint has received the
	// descriptor and closed the Unix connection: on macOS, closing the last
	// copy while the descriptor is in flight ends the connection.
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, u)
}

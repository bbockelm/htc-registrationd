//go:build unix

package portsplit

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/sharedporttest"
)

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		in      string
		kind    Kind
		decided bool
	}{
		{"", CEDAR, false},
		{"\x00\x00\x00\x00\x08", CEDAR, true},
		{"\x01\x00\x00\x00\x08", CEDAR, true},
		{"\x16", CEDAR, false},
		{"\x16\x03", CEDAR, false},
		{"\x16\x03\x01", TLS, true},
		{"\x16\x03\x04", TLS, true},
		{"\x16\x03\x05", CEDAR, true},
		{"\x16\x02\x01", CEDAR, true},
		{"G", CEDAR, false},
		{"GET", CEDAR, false},
		{"GET ", HTTP, true},
		{"GET /", HTTP, true},
		{"GETX", CEDAR, true},
		{"P", CEDAR, false},
		{"PO", CEDAR, false},
		{"PATCH /", HTTP, true},
		{"OPTIONS", CEDAR, false},
		{"OPTIONS ", HTTP, true},
		{"OPTIONSX", CEDAR, true},
		{"CONNECT ", HTTP, true},
		{"get / HTTP/1.1", CEDAR, true},
		{"X", CEDAR, true},
	} {
		k, d := Classify([]byte(tc.in))
		if k != tc.kind || d != tc.decided {
			t.Errorf("Classify(%q) = %v, %v; want %v, %v", tc.in, k, d, tc.kind, tc.decided)
		}
	}
}

// accept returns the next connection on ln, or nil after a short wait.
func accept(t *testing.T, ln net.Listener, wait time.Duration) net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			ch <- c
		}
	}()
	select {
	case c := <-ch:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(wait):
		return nil
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSplitForwarded sends each kind of connection through a stand-in for
// condor_shared_port and checks where it lands and that its bytes arrive
// unread, on the forwarded *net.TCPConn itself.
func TestSplitForwarded(t *testing.T) {
	ep := sharedporttest.New(t)
	s := Split(ep.Listener, nil)
	t.Cleanup(func() { _ = s.Close() })

	for _, tc := range []struct {
		name   string
		chunks []string
		want   Kind
	}{
		{"cedar", []string{"\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x01\x2c\xd0"}, CEDAR},
		{"tls", []string{"\x16\x03\x01\x00\x05hello"}, TLS},
		{"http", []string{"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"}, HTTP},
		// The method arrives in pieces: classification waits for it.
		{"http in pieces", []string{"OPT", "IONS * HTTP/1.1\r\n\r\n"}, HTTP},
		{"tls in pieces", []string{"\x16", "\x03\x03\x00\x01x"}, TLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, ep.Addr)
			for i, chunk := range tc.chunks {
				if i > 0 {
					time.Sleep(50 * time.Millisecond)
				}
				if _, err := io.WriteString(c, chunk); err != nil {
					t.Fatal(err)
				}
			}
			want, other := s.CEDAR(), s.Web()
			if tc.want != CEDAR {
				want, other = other, want
			}
			got := accept(t, want, 5*time.Second)
			if got == nil {
				if accept(t, other, time.Second) != nil {
					t.Fatalf("routed to the wrong listener")
				}
				t.Fatal("not delivered")
			}
			if _, ok := got.(*net.TCPConn); !ok {
				t.Errorf("delivered a %T, not the forwarded *net.TCPConn", got)
			}
			all := []byte{}
			for _, chunk := range tc.chunks {
				all = append(all, chunk...)
			}
			buf := make([]byte, len(all))
			_ = got.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(got, buf); err != nil || !bytes.Equal(buf, all) {
				t.Fatalf("read %q, %v; want %q", buf, err, all)
			}
		})
	}
}

// TestWebClosed: with the web listener closed, forwarded HTTP connections
// are closed and CEDAR is still served.
func TestWebClosed(t *testing.T) {
	ep := sharedporttest.New(t)
	s := Split(ep.Listener, nil)
	t.Cleanup(func() { _ = s.Close() })
	_ = s.Web().Close()

	c := dial(t, ep.Addr)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("HTTP connection not closed: %d, %v", n, err)
	}

	c = dial(t, ep.Addr)
	_, _ = io.WriteString(c, "\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x01\x2c\xd0")
	if accept(t, s.CEDAR(), 5*time.Second) == nil {
		t.Fatal("CEDAR not delivered")
	}
}

// TestSilentPeer: a connection that never sends is closed after the timeout
// without holding up others.
func TestSilentPeer(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := Split(ln, nil)
	t.Cleanup(func() { _ = s.Close() })
	silent := dial(t, ln.Addr().String())
	c := dial(t, ln.Addr().String())
	_, _ = io.WriteString(c, "\x00\x00\x00\x00\x08")
	if accept(t, s.CEDAR(), 5*time.Second) == nil {
		t.Fatal("a silent peer held up another connection")
	}
	_ = silent
	// Closing the CEDAR listener closes the underlying one.
	_ = s.CEDAR().Close()
	if _, err := s.Web().Accept(); err == nil {
		t.Fatal("Accept after Close succeeded")
	}
}

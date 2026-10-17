package ce

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

// refusedAddr is a loopback address nothing listens on.
func refusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "<" + addr + ">"
}

func newOfflineManager(t *testing.T, method string) *Manager {
	t.Helper()
	m, err := NewManager(Config{Name: "ce.example.org", Method: method, Registrar: refusedAddr(t),
		StateDir: t.TempDir(), TokenFile: "token", ConnectTimeout: 2 * time.Second,
		ClientSecurity:     func() *security.SecurityConfig { return &security.SecurityConfig{} },
		SSLServerAvailable: func() (bool, string) { return true, "" },
		CallbackAddress:    func() (string, error) { return "", errors.New("callback path taken") }})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRequestApprovalForcesApproval(t *testing.T) {
	// Configured for callback, a forced request still goes to approval:
	// the attempt reaches the registrar as REG_REQUEST and its failure is
	// reported to the waiter.
	m := newOfflineManager(t, MethodCallback)
	m.Step(context.Background())
	if e := m.Status().LastError; !strings.Contains(e, "callback path taken") {
		t.Fatalf("unforced step: %q", e)
	}
	done := m.RequestApproval()
	m.Step(context.Background())
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "connecting to registrar") {
			t.Fatalf("forced step: %v", err)
		}
	default:
		t.Fatal("the waiter was not answered")
	}
	if st := m.State(); st.RequestID != "" {
		t.Fatalf("a failed request left state behind: %+v", st)
	}
}

func TestRequestApprovalReportsPendingRequest(t *testing.T) {
	m := newOfflineManager(t, MethodAuto)
	if err := m.update(func(s *State) {
		s.Method, s.RequestID, s.Nonce, s.UserCode = MethodApproval, "rid", "nonce", "BCDF-GHJK"
		s.VerificationURIComplete = "https://registrar.example.org/approve?code=BCDF-GHJK"
		s.RequestExpires = time.Now().Add(time.Hour).Unix()
	}); err != nil {
		t.Fatal(err)
	}
	done := m.RequestApproval()
	m.Step(context.Background())
	if err := <-done; err != nil {
		t.Fatalf("pending request: %v", err)
	}
	if s := m.Status(); s.ApprovalURL != "https://registrar.example.org/approve?code=BCDF-GHJK" || s.UserCode != "BCDF-GHJK" {
		t.Fatalf("status: %+v", s)
	}
	if m.State().RequestID != "rid" {
		t.Fatal("the pending request was replaced")
	}
}

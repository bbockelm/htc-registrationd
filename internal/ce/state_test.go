package ce

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

func TestStateRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	in := &State{Method: MethodApproval, RegistrationID: "r", Current: "c", Pending: "p", TokenExpiry: 99}
	if err := SaveState(dir, in); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, RegistrationFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("registration.json: %v %v", fi, err)
	}
	out, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Fatalf("round trip %+v != %+v", out, in)
	}
	if out.Newest() != "p" {
		t.Fatalf("newest %q, want pending", out.Newest())
	}
	out.Pending = ""
	if out.Newest() != "c" {
		t.Fatalf("newest %q, want current", out.Newest())
	}
	empty, err := LoadState(t.TempDir())
	if err != nil || *empty != (State{}) {
		t.Fatalf("missing file: %+v %v", empty, err)
	}
}

func TestRenewAt(t *testing.T) {
	st := &State{TokenIssuedAt: 1000, TokenExpiry: 1000 + 72*3600}
	if got := st.RenewAt(0.5).Unix(); got != 1000+36*3600 {
		t.Fatalf("RenewAt = %d", got)
	}
	if !st.HasToken(time.Unix(1000, 0)) || st.HasToken(time.Unix(1000+72*3600, 0)) {
		t.Fatal("HasToken")
	}
}

func newBareManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(Config{
		Name: "ce.test", Registrar: "<192.0.2.1:9619>", StateDir: t.TempDir(),
		TokenFile:      filepath.Join(t.TempDir(), "tok"),
		ClientSecurity: func() *security.SecurityConfig { return &security.SecurityConfig{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A callback can beat the registrar's first reply; claimLive waits for the
// request id instead of refusing, and answers a request only once.
func TestClaimLiveWaitsForRequestID(t *testing.T) {
	m := newBareManager(t)
	lr := m.addLive("nonce")
	go func() {
		time.Sleep(200 * time.Millisecond)
		m.setRequestID(lr, "rid")
	}()
	got := m.claimLive(context.Background(), "rid")
	if got != lr {
		t.Fatal("the callback did not wait for the request id")
	}
	if m.claimLive(context.Background(), "rid") != nil {
		t.Fatal("a live request was claimed twice")
	}
	if m.claimLive(context.Background(), "other") != nil {
		t.Fatal("an unknown request id was claimed")
	}
}

func TestNewManagerValidates(t *testing.T) {
	base := Config{Name: "n", Registrar: "r", StateDir: t.TempDir(), TokenFile: "f",
		ClientSecurity: func() *security.SecurityConfig { return nil }}
	bad := base
	bad.Method = "carrier-pigeon"
	if _, err := NewManager(bad); err == nil {
		t.Error("bad method accepted")
	}
	bad = base
	bad.Name = ""
	if _, err := NewManager(bad); err == nil {
		t.Error("empty name accepted")
	}
	bad = base
	bad.Registrar = ""
	if _, err := NewManager(bad); err == nil {
		t.Error("empty registrar accepted")
	}
}

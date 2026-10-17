package ce

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// approve runs the CE's approval request through to an installed token.
func (p *pair) approve() State {
	p.t.Helper()
	p.step()
	st := p.mgr.State()
	ack := p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: st.UserCode, Name: ceName})
	if s, _ := ack[0].EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusOK {
		p.t.Fatalf("approve: %v", ack[0])
	}
	time.Sleep(1100 * time.Millisecond)
	p.step()
	return p.mgr.State()
}

// TestExpiredTokenRefreshes: an approval-mode CE whose token expired renews
// with its refresh secret, keeping the registration, rather than starting a
// new request that needs a human.
func TestExpiredTokenRefreshes(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	st := p.approve()
	first := p.verifyToken()
	if err := p.mgr.update(func(s *State) {
		s.TokenExpiry, s.TokenRenewAt = time.Now().Unix()-60, time.Now().Unix()-120
	}); err != nil {
		t.Fatal(err)
	}
	p.step()
	after := p.mgr.State()
	if after.RegistrationID != st.RegistrationID || after.RequestID != "" {
		t.Fatalf("an expired token dropped the registration: before %+v after %+v", st, after)
	}
	if after.Current != st.Pending {
		t.Fatal("the renewal did not prove the stored secret")
	}
	if second := p.verifyToken(); second.Raw["jti"] == first.Raw["jti"] {
		t.Fatal("no new token")
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want the one approval", len(reqs))
	}
}

// TestApprovalSurvivesFailedInstall: an approval whose token cannot be
// installed (the token directory is a file, which root cannot write into
// either) keeps the registration, and the next step installs a token by
// renewing with the stored secret.
func TestApprovalSurvivesFailedInstall(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	dir := filepath.Dir(p.tokenFile)
	p.step()
	st := p.mgr.State()
	p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: st.UserCode, Name: ceName})
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	p.step() // claims the approval; the install fails
	claimed := p.mgr.State()
	if claimed.RegistrationID == "" || claimed.Pending == "" || claimed.RequestID != "" {
		t.Fatalf("after the failed install: %+v", claimed)
	}
	if _, err := os.Stat(p.tokenFile); err == nil {
		t.Fatal("a token file was installed")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	p.step()
	after := p.mgr.State()
	if after.RegistrationID != claimed.RegistrationID {
		t.Fatalf("the registration was discarded: %+v", after)
	}
	p.verifyToken()
	if p.reconfigs.Load() == 0 {
		t.Fatal("no reconfig after the install")
	}
}

// TestLateCallbackInstallReconfigures: a token the callback handler installs
// with no request waiting for it (the request gave up) is reconfigured for at
// the next step.
func TestLateCallbackInstallReconfigures(t *testing.T) {
	p := newPair(t, pairOptions{})
	nonce, _ := secret.NewSecret()
	lr := p.mgr.addLive(nonce)
	defer p.mgr.removeLive(lr)
	cl := sslClient(t, p.ca, p.regAddr, registrarName, protocol.RegRequest)
	ctx := context.Background()
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.Request{
		Name: ceName, Method: protocol.MethodCallback, CallbackAddress: "<" + p.ceAddr + ">", Nonce: nonce,
	}); err != nil {
		t.Fatal(err)
	}
	first, err := protocol.RecvAd(ctx, cl.GetStream())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := first.EvaluateAttrString(protocol.AttrRequestID)
	p.mgr.setRequestID(lr, id)
	if err := <-lr.done; err != nil {
		t.Fatal(err)
	}
	if !p.mgr.State().NeedsReconfig() || p.reconfigs.Load() != 0 {
		t.Fatalf("after a callback install with nobody waiting: needs %v, reconfigs %d",
			p.mgr.State().NeedsReconfig(), p.reconfigs.Load())
	}
	p.step()
	if p.reconfigs.Load() != 1 || p.mgr.State().NeedsReconfig() {
		t.Fatalf("after the next step: reconfigs %d, needs %v", p.reconfigs.Load(), p.mgr.State().NeedsReconfig())
	}
}

// TestRenewalJitter: each token's renewal time is drawn between 40% and 60%
// of its lifetime.
func TestRenewalJitter(t *testing.T) {
	m := newBareManager(t)
	seen := map[int64]bool{}
	for i := 0; i < 200; i++ {
		at := m.renewAt(1000, 1000+100000)
		if at < 1000+40000 || at > 1000+60000 {
			t.Fatalf("renewal at %d%% of the lifetime", (at-1000)/1000)
		}
		seen[at] = true
	}
	if len(seen) < 50 {
		t.Fatalf("only %d distinct renewal times in 200 draws", len(seen))
	}
}

// TestCallbackDialErrorNotRevealed: when the callback cannot connect, the
// requester is told only that it failed, not how (connection refused versus a
// timeout would make the registrar a port prober).
func TestCallbackDialErrorNotRevealed(t *testing.T) {
	p := newPair(t, pairOptions{})
	nonce, _ := secret.NewSecret()
	closed := p.closedPort()
	_, outcome := rawRequest(t, p, "<"+closed+">", nonce)
	if outcome == nil {
		t.Fatal("no outcome")
	}
	msg, _ := outcome.EvaluateAttrString(protocol.AttrErrorString)
	for _, leak := range []string{"refused", "timeout", closed, "dial"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("the outcome %q reveals %q", msg, leak)
		}
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) == 0 || !strings.Contains(reqs[0].Reason, "refused") {
		t.Fatalf("the registrar did not record the detail: %+v", reqs)
	}
}

// TestAdminCommandsRequireEncryption: an administrator who will not encrypt
// cannot list or decide.
func TestAdminCommandsRequireEncryption(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	p.step()
	st := p.mgr.State()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sc := &security.SecurityConfig{
		Command:        protocol.RegAdminApprove,
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		Token:          p.adminToken,
		TokenDir:       t.TempDir(),
		TrustDomain:    trustDomain,
		SessionCache:   security.NewSessionCache(),
	}
	cl, err := client.ConnectAndAuthenticate(ctx, p.regAddr, sc)
	if err == nil {
		defer func() { _ = cl.Close() }()
		_ = protocol.Send(ctx, cl.GetStream(), &protocol.AdminTarget{UserCode: st.UserCode, Name: ceName})
		var ack protocol.Ack
		if err := protocol.Recv(ctx, cl.GetStream(), &ack); err == nil && ack.Status == protocol.StatusOK {
			t.Fatal("an unencrypted REG_ADMIN_APPROVE was served")
		}
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) != 1 || reqs[0].Status != "pending" {
		t.Fatalf("request %+v", reqs)
	}
}

// TestApproveNeedsTheName: the command-line approval names the CE; a request
// for another name is refused, showing the request's name.
func TestApproveNeedsTheName(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	p.step()
	st := p.mgr.State()
	for _, tc := range []struct{ name, want string }{
		{"", "CE name"},
		{"evil.test", "for " + ceName},
	} {
		ack := p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: st.UserCode, Name: tc.name})
		if s, _ := ack[0].EvaluateAttrString(protocol.AttrStatus); s == protocol.StatusOK {
			t.Fatalf("approved with name %q", tc.name)
		}
		if msg, _ := ack[0].EvaluateAttrString(protocol.AttrErrorString); !strings.Contains(msg, tc.want) {
			t.Fatalf("name %q: refusal %q does not mention %q", tc.name, msg, tc.want)
		}
	}
	ack := p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: st.UserCode, Name: strings.ToUpper(ceName)})
	if s, _ := ack[0].EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusOK {
		t.Fatalf("approving with the name in upper case: %v", ack[0])
	}
}

// closedPort returns a loopback address nothing listens on.
func (p *pair) closedPort() string {
	p.t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		p.t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestStartupRemovesTemps: temporary files a crash left beside the state
// files and the token file are removed when the manager starts.
func TestStartupRemovesTemps(t *testing.T) {
	stateDir, tokenDir := t.TempDir(), t.TempDir()
	stale := []string{filepath.Join(stateDir, ".registration.json.tmp-1"), filepath.Join(stateDir, ".status.json.tmp-2"),
		filepath.Join(tokenDir, ".50-htc-registration.tmp-3")}
	other := filepath.Join(tokenDir, "50-site-token")
	for _, f := range append(stale, other) {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewManager(Config{Name: ceName, Registrar: "<128.104.1.1:9619>", StateDir: stateDir,
		TokenFile:      filepath.Join(tokenDir, "50-htc-registration"),
		ClientSecurity: func() *security.SecurityConfig { return &security.SecurityConfig{} }}); err != nil {
		t.Fatal(err)
	}
	for _, f := range stale {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s was kept", f)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another token was removed: %v", err)
	}
}

// TestManagerReconfigure: new settings take effect for the next connection;
// a new token file gets a token, and the old copy is removed.
func TestManagerReconfigure(t *testing.T) {
	p := newPair(t, pairOptions{})
	p.step()
	p.verifyToken()
	if err := p.mgr.Reconfigure(Settings{Method: "bogus", Registrar: p.regAddr, TokenFile: p.tokenFile}); err == nil {
		t.Fatal("an invalid method was accepted")
	}
	oldFile := p.tokenFile
	p.tokenFile = filepath.Join(t.TempDir(), "tokens.d", "50-htc-registration")
	if err := p.mgr.Reconfigure(Settings{Method: MethodCallback, Registrar: p.regAddr,
		RegistrarServerName: registrarName, TokenFile: p.tokenFile}); err != nil {
		t.Fatal(err)
	}
	p.step()
	p.verifyToken()
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("the token in the old directory was kept: %v", err)
	}
	// A wrong registrar name is used from the next connection on.
	if err := p.mgr.Reconfigure(Settings{Method: MethodCallback, Registrar: p.regAddr,
		RegistrarServerName: "someone-else.test", TokenFile: p.tokenFile}); err != nil {
		t.Fatal(err)
	}
	p.mgr.RenewNow()
	p.step()
	if s := p.mgr.Status(); !strings.Contains(s.LastError, "registrar") {
		t.Fatalf("the reconfigured registrar name was not used: %+v", s)
	}
}

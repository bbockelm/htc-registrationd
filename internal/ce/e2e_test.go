package ce

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/secret"
	"github.com/bbockelm/htc-registrationd/internal/ssrf"
	"github.com/bbockelm/htc-registrationd/internal/testpki"
)

const (
	ceName        = "ce.test"
	registrarName = "registrar.test"
	trustDomain   = "pool.test"
	adminUser     = "admin@pool.test"
)

// pair is an in-process registrar and CE, each a cedar server on loopback,
// authenticating with certificates from a test CA.
type pair struct {
	t         *testing.T
	ca        *testpki.CA
	keyDir    string
	svc       *registrar.Service
	store     *registrar.Store
	regAddr   string
	ceAddr    string
	mgr       *Manager
	stateDir  string
	tokenFile string
	reconfigs atomic.Int32
	// failReconfig makes the master's reconfig fail.
	failReconfig atomic.Bool
	adminToken   string
}

type pairOptions struct {
	method string
	// allow is HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS; loopback by default.
	allow    string
	noSSL    bool // the CE has no SSL server credential
	lifetime time.Duration
}

func authorizer(perm, _, user string) bool {
	switch perm {
	case "ALLOW", "READ":
		return true
	case "ADMINISTRATOR":
		return user == adminUser
	}
	return false
}

// serve starts srv on a loopback listener and returns its address.
func serve(t *testing.T, srv *cedarserver.Server) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

func serverSecurity(certFile, keyFile, keyDir string) *security.SecurityConfig {
	return &security.SecurityConfig{
		AuthMethods:        []security.AuthMethod{security.AuthSSL, security.AuthToken},
		Authentication:     security.SecurityOptional,
		CryptoMethods:      []security.CryptoMethod{security.CryptoAES},
		Encryption:         security.SecurityOptional,
		Integrity:          security.SecurityOptional,
		CertFile:           certFile,
		KeyFile:            keyFile,
		TokenSigningKeyDir: keyDir,
		TrustDomain:        trustDomain,
		SessionCache:       security.NewSessionCache(),
	}
}

func newPair(t *testing.T, opts pairOptions) *pair {
	t.Helper()
	if opts.method == "" {
		opts.method = MethodCallback
	}
	if opts.allow == "" {
		opts.allow = "127.0.0.0/8"
	}
	if opts.allow == "none" {
		opts.allow = ""
	}
	if opts.lifetime == 0 {
		opts.lifetime = 72 * time.Hour
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	p := &pair{t: t, ca: testpki.NewCA(t), keyDir: t.TempDir()}
	if err := security.GenerateSigningKey(filepath.Join(p.keyDir, "ce-registration")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(p.keyDir, "ce-registration", adminUser, trustDomain, now, now+3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.adminToken = tok

	// Registrar.
	store, err := registrar.OpenStore(filepath.Join(t.TempDir(), "registrar.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	allow, err := ssrf.ParseAllowList(opts.allow)
	if err != nil {
		t.Fatal(err)
	}
	policy := ssrf.New(allow)
	policy.LocalAddrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil }
	svc, err := registrar.New(registrar.Config{
		Minter: &mint.Minter{
			KeyDir: p.keyDir, KeyID: "ce-registration", Issuer: trustDomain, Domain: "users.test",
			Limits: []string{"ADVERTISE_SCHEDD"}, Lifetime: opts.lifetime, ReadKey: os.ReadFile,
		},
		SSRF:  policy,
		Names: registrar.AnyName{},
		CallbackSecurity: func() *security.SecurityConfig {
			return &security.SecurityConfig{CAFile: p.ca.CertFile}
		},
		Tunables: registrar.Tunables{
			CallbackConnectTimeout: 5 * time.Second,
			CallbackTimeout:        15 * time.Second,
			CallbackBackoff:        time.Millisecond,
			PollInterval:           time.Second,
			VerificationURI:        "https://registrar.test/approve",
		},
		Logger: logger,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	p.svc, p.store = svc, store
	rc, rk := p.ca.ServerCert(t, registrarName)
	rsrv := cedarserver.New(serverSecurity(rc, rk, p.keyDir))
	rsrv.Authorizer = authorizer
	svc.Register(rsrv)
	cedarx.HardenCommands(rsrv, protocol.RegRequest, protocol.RegPoll, protocol.RegRenew)
	cedarx.RequireEncryption(rsrv, protocol.AdminCommands...)
	p.regAddr = serve(t, rsrv)

	// CE.
	cc, ck := p.ca.ServerCert(t, ceName)
	csrv := cedarserver.New(serverSecurity(cc, ck, p.keyDir))
	csrv.Authorizer = authorizer
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ceAddr = ln.Addr().String()
	_ = ln.Close()
	p.stateDir = t.TempDir()
	p.tokenFile = filepath.Join(t.TempDir(), "tokens.d", "50-htc-registration")
	mgr, err := NewManager(Config{
		Name:                ceName,
		Method:              opts.method,
		Registrar:           p.regAddr,
		RegistrarServerName: registrarName,
		StateDir:            p.stateDir,
		TokenFile:           p.tokenFile,
		Version:             "test",
		CallbackAddress:     func() (string, error) { return "<" + p.ceAddr + ">", nil },
		SSLServerAvailable: func() (bool, string) {
			if opts.noSSL {
				return false, "no SSL server certificate configured"
			}
			return true, ""
		},
		ClientSecurity: func() *security.SecurityConfig { return &security.SecurityConfig{CAFile: p.ca.CertFile} },
		Reconfig: func(context.Context) error {
			if p.failReconfig.Load() {
				return errors.New("the master is not answering")
			}
			p.reconfigs.Add(1)
			return nil
		},
		RetryMin: 10 * time.Millisecond,
		Logger:   logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	p.mgr = mgr
	mgr.Register(csrv)
	cedarx.HardenCommands(csrv, protocol.RegCallback)
	ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", p.ceAddr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = csrv.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return p
}

// verifyToken checks the installed token with cedar's verifier.
func (p *pair) verifyToken() *security.IDTokenClaims {
	p.t.Helper()
	raw, err := os.ReadFile(p.tokenFile)
	if err != nil {
		p.t.Fatalf("no token installed: %v", err)
	}
	st, err := os.Stat(p.tokenFile)
	if err != nil {
		p.t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		p.t.Errorf("token mode %o, want 600", st.Mode().Perm())
	}
	claims, err := security.VerifyIDToken(string(raw), &security.SecurityConfig{TokenSigningKeyDir: p.keyDir})
	if err != nil {
		p.t.Fatalf("installed token does not verify: %v", err)
	}
	if claims.Subject != ceName+"@users.test" || claims.Issuer != trustDomain || claims.Scope != "condor:/ADVERTISE_SCHEDD" {
		p.t.Fatalf("claims %+v", claims)
	}
	return claims
}

func (p *pair) step() time.Duration {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return p.mgr.Step(ctx)
}

// adminCall runs an ADMINISTRATOR command on the registrar as adminUser,
// authenticating with an IDTOKEN.
func (p *pair) adminCall(cmd int, req any) []*classad.ClassAd {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sc := &security.SecurityConfig{
		Command:        cmd,
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityOptional,
		Token:          p.adminToken,
		TokenDir:       p.t.TempDir(),
		TrustDomain:    trustDomain,
		SessionCache:   security.NewSessionCache(),
	}
	cl, err := client.ConnectAndAuthenticate(ctx, p.regAddr, sc)
	if err != nil {
		p.t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = cl.Close() }()
	if req != nil {
		if err := protocol.Send(ctx, cl.GetStream(), req); err != nil {
			p.t.Fatal(err)
		}
	}
	var out []*classad.ClassAd
	for {
		ad, err := protocol.RecvAd(ctx, cl.GetStream())
		if err != nil {
			p.t.Fatalf("admin reply: %v", err)
		}
		out = append(out, ad)
		if cmd != protocol.RegAdminList {
			return out
		}
		if end, ok := ad.EvaluateAttrBool(protocol.AttrEnd); ok && end {
			return out
		}
	}
}

// sslClient dials addr for cmd as an anonymous SSL client verifying serverName.
func sslClient(t *testing.T, ca *testpki.CA, addr, serverName string, cmd int) *client.HTCondorClient {
	t.Helper()
	sc := cedarx.SSLOnly(&security.SecurityConfig{CAFile: ca.CertFile}, cmd, serverName, addr)
	cl, err := cedarx.DialSSL(context.Background(), &client.ClientConfig{Address: addr, Security: sc, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

// TestCallbackIssuanceAndRenewal: callback mode issues a token that cedar
// verifies, installs it 0600, reconfigures, and renews with a fresh exchange.
func TestCallbackIssuanceAndRenewal(t *testing.T) {
	p := newPair(t, pairOptions{})
	wait := p.step()
	first := p.verifyToken()
	if got := p.reconfigs.Load(); got != 1 {
		t.Fatalf("reconfigs %d, want 1", got)
	}
	st := p.mgr.State()
	if st.Method != MethodCallback || st.TokenExpiry != first.Expiry {
		t.Fatalf("state %+v", st)
	}
	if want := time.Until(time.Unix(first.IssuedAt+(first.Expiry-first.IssuedAt)/2, 0)); wait != 0 && (wait > want+time.Minute) {
		t.Fatalf("next step in %s, want about %s", wait, want)
	}
	// The next step only waits for the renewal point.
	if w := p.step(); w < 28*time.Hour || w > 44*time.Hour {
		t.Fatalf("idle step waits %s, want 40-60%% of 72h", w)
	}
	regs, err := p.store.ListRegistrations(context.Background())
	if err != nil || len(regs) != 1 || regs[0].Status != registrar.RegActive || regs[0].Method != protocol.MethodCallback {
		t.Fatalf("registrations %+v %v", regs, err)
	}
	if s := p.mgr.Status(); s.State != StateRegistered {
		t.Fatalf("status %+v", s)
	}

	// Renewal: a fresh full exchange, a new token.
	p.mgr.RenewNow()
	p.step()
	second := p.verifyToken()
	if second.Raw["jti"] == first.Raw["jti"] {
		t.Fatal("renewal did not install a new token")
	}
	if got := p.reconfigs.Load(); got != 2 {
		t.Fatalf("reconfigs %d, want 2", got)
	}
	if n, _ := p.store.IssuedTokenCount(context.Background(), regs[0].ID); n != 2 {
		t.Fatalf("issued tokens %d, want 2", n)
	}
	if _, err := os.Stat(filepath.Join(p.stateDir, StatusFile)); err != nil {
		t.Fatalf("status.json: %v", err)
	}
}

// TestTokenNeverOnRequestConnection drives REG_REQUEST by hand and checks no
// ad on the request connection carries a Token, while the CE received one on
// the callback.
func TestTokenNeverOnRequestConnection(t *testing.T) {
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
	second, err := protocol.RecvAd(ctx, cl.GetStream())
	if err != nil {
		t.Fatal(err)
	}
	for i, ad := range []*classad.ClassAd{first, second} {
		if _, ok := ad.Lookup(protocol.AttrToken); ok {
			t.Fatalf("reply %d on the request connection carries a Token", i)
		}
		if _, ok := ad.Lookup(protocol.AttrRefreshSecret); ok {
			t.Fatalf("reply %d on the request connection carries a RefreshSecret", i)
		}
	}
	if s, _ := second.EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusIssued {
		t.Fatalf("outcome %q", s)
	}
	if err := <-lr.done; err != nil {
		t.Fatalf("callback install: %v", err)
	}
	p.verifyToken()
}

// fakeCE serves REG_CALLBACK with a handler under test, presenting a valid
// certificate for ceName.
func fakeCE(t *testing.T, ca *testpki.CA, keyDir string, h cedarserver.HandlerFunc) string {
	t.Helper()
	cc, ck := ca.ServerCert(t, ceName)
	srv := cedarserver.New(serverSecurity(cc, ck, keyDir))
	srv.Authorizer = authorizer
	srv.Handle(protocol.RegCallback, h, "ALLOW")
	cedarx.HardenCommands(srv, protocol.RegCallback)
	return serve(t, srv)
}

func rawRequest(t *testing.T, p *pair, callback, nonce string) (*classad.ClassAd, *classad.ClassAd) {
	t.Helper()
	ctx := context.Background()
	cl := sslClient(t, p.ca, p.regAddr, registrarName, protocol.RegRequest)
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.Request{
		Name: ceName, Method: protocol.MethodCallback, CallbackAddress: callback, Nonce: nonce,
	}); err != nil {
		t.Fatal(err)
	}
	first, err := protocol.RecvAd(ctx, cl.GetStream())
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := first.EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusCallbackPending {
		return first, nil
	}
	second, err := protocol.RecvAd(ctx, cl.GetStream())
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

// TestWrongNonceRejected: a CE endpoint that answers the callback with a
// different Nonce than the request carried gets no token. This is the victim
// case: someone files a request naming a host whose real CE then answers.
func TestWrongNonceRejected(t *testing.T) {
	p := newPair(t, pairOptions{})
	delivered := make(chan bool, 1)
	addr := fakeCE(t, p.ca, p.keyDir, func(ctx context.Context, c *cedarserver.Conn) error {
		var hello protocol.CallbackHello
		if err := protocol.Recv(ctx, c.Stream, &hello); err != nil {
			return err
		}
		other, _ := secret.NewSecret()
		if err := protocol.Send(ctx, c.Stream, &protocol.CallbackProof{Status: protocol.StatusOK, Nonce: other}); err != nil {
			return err
		}
		var d protocol.CallbackDelivery
		err := protocol.Recv(ctx, c.Stream, &d)
		delivered <- err == nil && d.Token != ""
		return nil
	})
	nonce, _ := secret.NewSecret()
	_, outcome := rawRequest(t, p, "<"+addr+">", nonce)
	if outcome == nil {
		t.Fatal("no outcome")
	}
	if s, _ := outcome.EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusFailed {
		t.Fatalf("outcome %q, want failed", s)
	}
	if msg, _ := outcome.EvaluateAttrString(protocol.AttrErrorString); !strings.Contains(msg, "Nonce") {
		t.Fatalf("outcome error %q", msg)
	}
	if <-delivered {
		t.Fatal("a token was delivered after a wrong Nonce")
	}
	regs, _ := p.store.ListRegistrations(context.Background())
	if len(regs) != 0 {
		t.Fatalf("registrations created: %d", len(regs))
	}
}

// TestCEChecksRequestID: the CE refuses a callback whose RequestId is not one
// of its live requests, and never reveals the Nonce for it.
func TestCEChecksRequestID(t *testing.T) {
	p := newPair(t, pairOptions{})
	nonce, _ := secret.NewSecret()
	lr := p.mgr.addLive(nonce)
	defer p.mgr.removeLive(lr)
	p.mgr.setRequestID(lr, "the-real-request-id")
	ctx := context.Background()

	cl := sslClient(t, p.ca, p.ceAddr, ceName, protocol.RegCallback)
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.CallbackHello{RequestID: "a-guessed-request-id"}); err != nil {
		t.Fatal(err)
	}
	var proof protocol.CallbackProof
	if err := protocol.Recv(ctx, cl.GetStream(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Status != protocol.StatusError || proof.Nonce != "" {
		t.Fatalf("wrong RequestId answered %+v", proof)
	}

	// The right one is answered, once.
	cl = sslClient(t, p.ca, p.ceAddr, ceName, protocol.RegCallback)
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.CallbackHello{RequestID: "the-real-request-id"}); err != nil {
		t.Fatal(err)
	}
	if err := protocol.Recv(ctx, cl.GetStream(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Status != protocol.StatusOK || proof.Nonce != nonce {
		t.Fatalf("right RequestId answered %+v", proof)
	}
	// A pushed token that is not for this CE is refused and not installed.
	other := &mint.Minter{KeyDir: p.keyDir, KeyID: "ce-registration", Domain: "users.test",
		Lifetime: time.Hour, ReadKey: os.ReadFile}
	bad, err := other.Mint("evil.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.CallbackDelivery{Token: bad.Raw}); err != nil {
		t.Fatal(err)
	}
	var ack protocol.Ack
	if err := protocol.Recv(ctx, cl.GetStream(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status == protocol.StatusOK {
		t.Fatal("a token for another name was installed")
	}
	if _, err := os.Stat(p.tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file present: %v", err)
	}
	cl = sslClient(t, p.ca, p.ceAddr, ceName, protocol.RegCallback)
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.CallbackHello{RequestID: "the-real-request-id"}); err != nil {
		t.Fatal(err)
	}
	if err := protocol.Recv(ctx, cl.GetStream(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Status == protocol.StatusOK {
		t.Fatal("a live request was answered twice")
	}
}

// TestCallbackWrongCertificateName: the registrar verifies the CE's
// certificate against the requested name, so a CE whose certificate is for
// another name gets nothing.
func TestCallbackWrongCertificateName(t *testing.T) {
	p := newPair(t, pairOptions{})
	cc, ck := p.ca.ServerCert(t, "someone-else.test")
	srv := cedarserver.New(serverSecurity(cc, ck, p.keyDir))
	srv.Authorizer = authorizer
	called := make(chan struct{}, 1)
	srv.Handle(protocol.RegCallback, func(context.Context, *cedarserver.Conn) error {
		called <- struct{}{}
		return nil
	}, "ALLOW")
	cedarx.HardenCommands(srv, protocol.RegCallback)
	addr := serve(t, srv)
	nonce, _ := secret.NewSecret()
	_, outcome := rawRequest(t, p, "<"+addr+">", nonce)
	if s, _ := outcome.EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusFailed {
		t.Fatalf("outcome %q, want failed", s)
	}
	if msg, _ := outcome.EvaluateAttrString(protocol.AttrErrorString); !strings.Contains(msg, "certificate") {
		t.Fatalf("outcome error %q does not name the certificate", msg)
	}
	select {
	case <-called:
		t.Fatal("the handler ran behind a certificate for the wrong name")
	default:
	}
}

// TestSSRFDeniesLoopback: without the allow list, a loopback callback address
// is refused before any dial, with an explicit reason; a callback-only CE
// reports the error and an auto CE falls back to approval.
func TestSSRFDeniesLoopback(t *testing.T) {
	p := newPair(t, pairOptions{allow: "none"})
	nonce, _ := secret.NewSecret()
	first, _ := rawRequest(t, p, "<"+p.ceAddr+">", nonce)
	if code, _ := first.EvaluateAttrInt(protocol.AttrErrorCode); code != protocol.ErrCallbackDenied {
		t.Fatalf("error code %d, want %d", code, protocol.ErrCallbackDenied)
	}
	if msg, _ := first.EvaluateAttrString(protocol.AttrErrorString); !strings.Contains(msg, "loopback") {
		t.Fatalf("reason %q", msg)
	}
	p.step()
	if s := p.mgr.Status(); !strings.Contains(s.LastError, "loopback") {
		t.Fatalf("CE status %+v", s)
	}
	if _, err := os.Stat(p.tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a token was installed")
	}

	auto := newPair(t, pairOptions{allow: "none", method: MethodAuto})
	auto.step()
	if st := auto.mgr.State(); st.RequestID == "" || st.Method != MethodApproval {
		t.Fatalf("auto mode did not fall back to approval: %+v", st)
	}
}

// TestAutoWithoutSSLUsesApproval: auto mode with no SSL server credential
// goes straight to approval.
func TestAutoWithoutSSLUsesApproval(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodAuto, noSSL: true})
	p.step()
	if st := p.mgr.State(); st.RequestID == "" {
		t.Fatalf("no approval request: %+v", st)
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) != 1 || reqs[0].Method != protocol.MethodApproval {
		t.Fatalf("requests %+v", reqs)
	}
}

// TestApprovalFlow: request, publish, poll, admin approve over CEDAR, first
// issuance, renewal with secret rotation, status, revocation.
func TestApprovalFlow(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	ctx := context.Background()

	if wait := p.step(); wait != time.Second {
		t.Fatalf("first poll in %s, want the 1s interval", wait)
	}
	st := p.mgr.State()
	if st.RequestID == "" || st.Nonce == "" || len(st.UserCode) != 9 {
		t.Fatalf("state %+v", st)
	}
	url, err := os.ReadFile(filepath.Join(p.stateDir, ApprovalURLFile))
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://registrar.test/approve?code=" + st.UserCode; strings.TrimSpace(string(url)) != want {
		t.Fatalf("approval-url %q, want %q", url, want)
	}
	// registration.json holds the request (and is private).
	if fi, err := os.Stat(filepath.Join(p.stateDir, RegistrationFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("registration.json: %v %v", fi, err)
	}
	if s := p.statusCall(); s.State != StateApprovalPending || s.UserCode != st.UserCode {
		t.Fatalf("REG_STATUS %+v", s)
	}
	time.Sleep(1100 * time.Millisecond)
	p.step() // still pending
	if p.mgr.State().RequestID == "" {
		t.Fatal("request dropped while pending")
	}

	// An unauthenticated or non-admin caller cannot approve.
	ack := p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: strings.ToLower(st.UserCode), Name: ceName})
	if s, _ := ack[0].EvaluateAttrString(protocol.AttrStatus); s != protocol.StatusOK {
		t.Fatalf("approve: %v", ack[0])
	}
	reqs, _ := p.store.ListRequests(ctx, time.Time{})
	if reqs[0].Status != registrar.ReqApproved || reqs[0].DecidedBy != "cedar:"+adminUser {
		t.Fatalf("request %+v", reqs[0])
	}

	time.Sleep(1100 * time.Millisecond)
	p.step()
	first := p.verifyToken()
	st = p.mgr.State()
	if st.RegistrationID == "" || st.Pending == "" || st.Current != "" || st.RequestID != "" {
		t.Fatalf("after approval: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(p.stateDir, ApprovalURLFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("approval-url not removed")
	}
	if p.reconfigs.Load() != 1 {
		t.Fatalf("reconfigs %d", p.reconfigs.Load())
	}

	// Renewal: the pending secret is proven and becomes current.
	firstSecret := st.Pending
	p.mgr.RenewNow()
	p.step()
	second := p.verifyToken()
	if second.Raw["jti"] == first.Raw["jti"] {
		t.Fatal("no new token")
	}
	st = p.mgr.State()
	if st.Current != firstSecret || st.Pending == "" || st.Pending == firstSecret {
		t.Fatalf("secrets after renewal: %+v", st)
	}
	reg, err := p.store.Registration(ctx, st.RegistrationID)
	if err != nil {
		t.Fatal(err)
	}
	if ss := reg.Secrets(); ss.Current != secret.Hash(st.Current) || ss.Pending != secret.Hash(st.Pending) {
		t.Fatal("registrar and CE secrets differ")
	}

	checkListAndRevoke(t, p)
}

// checkListAndRevoke: listing shows the request and the registration, never
// secrets; revocation makes the next renewal fail and the CE drop the
// registration.
func checkListAndRevoke(t *testing.T, p *pair) {
	t.Helper()
	ads := p.adminCall(protocol.RegAdminList, nil)
	var kinds []string
	for _, ad := range ads {
		k, _ := ad.EvaluateAttrString("Kind")
		kinds = append(kinds, k)
		for _, attr := range []string{protocol.AttrRefreshSecret, protocol.AttrNonce, protocol.AttrToken, "current_hash"} {
			if _, ok := ad.Lookup(attr); ok {
				t.Fatalf("list ad carries %s", attr)
			}
		}
	}
	if strings.Join(kinds, ",") != "request,registration," {
		t.Fatalf("list kinds %v", kinds)
	}

	// Revocation: the next renewal is refused and the CE drops the
	// registration.
	ack := p.adminCall(protocol.RegAdminRevoke, &protocol.AdminTarget{Name: ceName, Reason: "test"})
	if hint, _ := ack[0].EvaluateAttrString(protocol.AttrHint); !strings.Contains(hint, "DENY_ADVERTISE_SCHEDD") {
		t.Fatalf("revoke hint %q", hint)
	}
	p.mgr.RenewNow()
	p.step()
	if st := p.mgr.State(); st.RegistrationID != "" {
		t.Fatalf("revoked registration kept: %+v", st)
	}
}

// TestApprovalResumesAfterRestart: the request persisted before the URL was
// published survives a restart and is polled again.
func TestApprovalResumesAfterRestart(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	p.step()
	before := p.mgr.State()
	// "Restart": a new manager over the same state directory.
	cfg := p.mgr.cfg
	m2, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.State(); got.RequestID != before.RequestID || got.Nonce != before.Nonce {
		t.Fatalf("restarted state %+v", got)
	}
	p.adminCall(protocol.RegAdminApprove, &protocol.AdminTarget{UserCode: before.UserCode, Name: ceName})
	p.mgr = m2
	p.step()
	p.verifyToken()
}

// TestDenied: a denied request is abandoned and the URL withdrawn.
func TestDenied(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodApproval})
	p.step()
	st := p.mgr.State()
	p.adminCall(protocol.RegAdminDeny, &protocol.AdminTarget{UserCode: st.UserCode, Reason: "not ours"})
	time.Sleep(1100 * time.Millisecond)
	if wait := p.step(); wait != p.mgr.cfg.DeniedRetry {
		t.Fatalf("after denial waits %s", wait)
	}
	if p.mgr.State().RequestID != "" {
		t.Fatal("denied request kept")
	}
	if _, err := os.Stat(filepath.Join(p.stateDir, ApprovalURLFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("approval-url not removed")
	}
}

// TestUnencryptedRefused: a client that will not encrypt cannot run a
// registration command.
func TestUnencryptedRefused(t *testing.T) {
	p := newPair(t, pairOptions{})
	sc := &security.SecurityConfig{
		Command:        protocol.RegRequest,
		AuthMethods:    []security.AuthMethod{security.AuthSSL},
		Authentication: security.SecurityRequired,
		Encryption:     security.SecurityNever,
		Integrity:      security.SecurityNever,
		CAFile:         p.ca.CertFile,
		ServerName:     registrarName,
		SessionCache:   security.NewSessionCache(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := client.ConnectAndAuthenticate(ctx, p.regAddr, sc)
	if err == nil {
		defer func() { _ = cl.Close() }()
		_ = protocol.Send(ctx, cl.GetStream(), &protocol.Request{Name: ceName, Method: protocol.MethodApproval,
			Nonce: strings.Repeat("n", 43)})
		var reply protocol.RequestReply
		if err := protocol.Recv(ctx, cl.GetStream(), &reply); err == nil && reply.Status == protocol.StatusPending {
			t.Fatal("an unencrypted REG_REQUEST was served")
		}
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) != 0 {
		t.Fatalf("requests recorded: %d", len(reqs))
	}
}

// TestReconfigRetried: a token installed after the local master's last
// reconfig (here: before a crash) is reconfigured at the next step, and a
// failed reconfig is retried, with the wait capped, until it succeeds.
func TestReconfigRetried(t *testing.T) {
	p := newPair(t, pairOptions{})
	now := time.Now().Unix()
	if err := p.mgr.update(func(s *State) {
		s.Method, s.TokenIssuedAt, s.TokenExpiry, s.TokenRenewAt = MethodCallback, now, now+72*3600, now+36*3600
		s.TokenGeneration, s.ReconfiguredGeneration = 2, 1
	}); err != nil {
		t.Fatal(err)
	}
	p.failReconfig.Store(true)
	if w := p.step(); w > time.Second {
		t.Fatalf("with a failed reconfig the step waits %s, want the short retry delay", w)
	}
	if !p.mgr.State().NeedsReconfig() {
		t.Fatal("a failed reconfig was recorded as done")
	}
	p.failReconfig.Store(false)
	if w := p.step(); w < 30*time.Hour {
		t.Fatalf("after the reconfig succeeded the step waits %s, want the renewal time", w)
	}
	if p.reconfigs.Load() != 1 || p.mgr.State().NeedsReconfig() {
		t.Fatalf("reconfigs %d, needs %v", p.reconfigs.Load(), p.mgr.State().NeedsReconfig())
	}
	p.step()
	if p.reconfigs.Load() != 1 {
		t.Fatal("reconfigured again with nothing new installed")
	}
}

// TestStateFromBeforeGenerations: a state file written before reconfig
// generations were kept still reconfigures for a token installed after the
// last reconfig, and only then.
func TestStateFromBeforeGenerations(t *testing.T) {
	for _, tc := range []struct {
		installed, reconfigured int64
		need                    bool
	}{{200, 100, true}, {200, 200, true}, {200, 300, false}, {0, 0, false}} {
		dir := t.TempDir()
		if err := SaveState(dir, &State{TokenInstalledAt: tc.installed, LastReconfig: tc.reconfigured}); err != nil {
			t.Fatal(err)
		}
		st, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.NeedsReconfig() != tc.need {
			t.Errorf("installed %d, reconfigured %d: needs reconfig %v, want %v",
				tc.installed, tc.reconfigured, st.NeedsReconfig(), tc.need)
		}
	}
}

func (p *pair) statusCall() *StatusReply {
	p.t.Helper()
	ctx := context.Background()
	cl := sslClient(p.t, p.ca, p.ceAddr, ceName, protocol.RegStatus)
	var s StatusReply
	if err := protocol.Recv(ctx, cl.GetStream(), &s); err != nil {
		p.t.Fatal(err)
	}
	return &s
}

// TestRequestApprovalOverridesCallback: a CE configured for callback starts
// an approval request when asked to, and reports its URL.
func TestRequestApprovalOverridesCallback(t *testing.T) {
	p := newPair(t, pairOptions{method: MethodCallback})
	done := p.mgr.RequestApproval()
	p.step()
	if err := <-done; err != nil {
		t.Fatalf("forced approval request: %v", err)
	}
	st := p.mgr.State()
	if st.RequestID == "" || st.Method != MethodApproval {
		t.Fatalf("no approval request: %+v", st)
	}
	reqs, _ := p.store.ListRequests(context.Background(), time.Time{})
	if len(reqs) != 1 || reqs[0].Method != protocol.MethodApproval || reqs[0].UserCode != st.UserCode {
		t.Fatalf("requests %+v", reqs)
	}
	if s := p.mgr.Status(); s.ApprovalURL != "https://registrar.test/approve?code="+st.UserCode {
		t.Fatalf("status %+v", s)
	}
}

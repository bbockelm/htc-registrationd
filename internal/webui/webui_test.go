package webui

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/authz"
	"github.com/bbockelm/htc-registrationd/internal/knobs"
	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	os.Exit(m.Run())
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeResolver struct{}

func (fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if addr == "192.0.2.10" {
		return []string{"ce1.example.edu."}, nil
	}
	return nil, errors.New("no PTR")
}

func (fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if host == "ce1.example.edu" {
		return []string{"192.0.2.10"}, nil
	}
	return nil, errors.New("no such host")
}

// harness is a registrar store, a mock identity provider, a mapfile policy
// and the web UI served over plain HTTP on loopback.
type harness struct {
	t      *testing.T
	clock  *fakeClock
	store  *registrar.Store
	idp    *mockIDP
	srv    *Server
	web    *httptest.Server
	policy *authz.Policy
	mf     *authz.Mapfile
	mapf   string
}

const testCE = "ce1.example.edu"

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	store, err := registrar.OpenStore(filepath.Join(t.TempDir(), "registrar.db"), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	idp := newMockIDP(t)
	mapPath := filepath.Join(t.TempDir(), "authz.map")
	// Configuration names users by subject; carol by a regular expression.
	content := `OIDC alice ` + testCE + `,*.grid.example.org` + "\n" +
		`OIDC /^carol$/ other.example.edu` + "\n"
	if err := os.WriteFile(mapPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	mf, err := authz.NewMapfile(mapPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := authz.NewPolicy([]authz.Backend{mf}, []string{"root"})
	policy.SetSubjectIssuer(idp.URL())

	var handler atomic.Value
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(web.Close)
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(idp.clientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(context.Background(), Config{
		PublicURL:        web.URL,
		HTTPAddr:         "127.0.0.1:0",
		OIDC:             OIDCConfig{Issuer: idp.URL(), ClientID: idp.clientID},
		ClientSecretFile: secretFile,
		Store:            store,
		Authz:            policy,
		ReadCredential:   os.ReadFile,
		Resolver:         fakeResolver{},
		Now:              clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(srv.Handler())
	return &harness{t: t, clock: clock, store: store, idp: idp, srv: srv, web: web, policy: policy, mf: mf, mapf: mapPath}
}

// browser is a client with its own cookies that follows redirects.
func (h *harness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

// login signs a browser in as sub.
func (h *harness) login(c *http.Client, sub string) {
	h.t.Helper()
	h.idp.setClaims(map[string]any{"sub": sub, "name": "User " + sub})
	body, code := h.get(c, "/login")
	if code != http.StatusOK || !strings.Contains(body, "Enter the code your CE shows") {
		h.t.Fatalf("login as %s: %d\n%s", sub, code, body)
	}
}

func (h *harness) get(c *http.Client, path string) (string, int) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.web.URL+path, nil)
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

func (h *harness) post(c *http.Client, path string, form url.Values, hdr map[string]string) (string, int) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.web.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in\n%s", body)
	}
	return m[1]
}

// pending records an approval-mode request and returns its user code.
func (h *harness) pending(name, code string) {
	h.t.Helper()
	id, _ := secret.NewID()
	if _, err := h.store.CreateRequest(context.Background(), registrar.NewRequest{
		RequestIDHash: secret.Hash(id),
		NonceHash:     secret.Hash("nonce-" + code),
		Name:          name,
		Method:        protocol.MethodApproval,
		SourceIP:      "192.0.2.10",
		CEVersion:     "$CondorVersion: 25.0.0 2026-01-01 $ htc-registrationd/test",
		UserCode:      code,
		Status:        registrar.ReqPending,
		TTL:           30 * time.Minute,
		PollInterval:  5 * time.Second,
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) status(code string) *registrar.RequestRecord {
	h.t.Helper()
	r, err := h.store.RequestByUserCode(context.Background(), code)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func TestLoginThenApprove(t *testing.T) {
	h := newHarness(t)
	h.pending(testCE, "BCDF-GHJK")
	c := h.browser()
	h.idp.setClaims(map[string]any{"sub": "alice", "name": "Alice Admin"})

	// Not signed in: the request page sends the browser through the
	// provider and back to the same page.
	body, code := h.get(c, "/approve?code=bcdf+ghjk")
	if code != http.StatusOK {
		t.Fatalf("approve page: %d\n%s", code, body)
	}
	for _, want := range []string{
		"BCDF-GHJK",
		"Confirm this matches the code shown on your CE",
		testCE,
		"192.0.2.10",
		"ce1.example.edu, which resolves back to this address",
		"2027-01-15 08:00 UTC", // requested at
		"htc-registrationd/test",
		"You are authorized to approve " + testCE,
		"Allowed by the registrar&#39;s map file",
		`value="approve"`,
		"Alice Admin",
		// The footer names the user as configuration does: the subject.
		"<code>alice</code>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("approve page lacks %q", want)
		}
	}
	if strings.Contains(body, h.idp.URL()+",alice") {
		t.Error("approve page shows the issuer-qualified principal")
	}
	if strings.Contains(body, "line 1") || strings.Contains(body, h.mapf) {
		t.Error("approve page shows where in the map file the user is listed")
	}
	if h.idp.pkceRejections != 0 || len(h.idp.challenges) != 1 {
		t.Errorf("PKCE: %d challenges, %d rejections", len(h.idp.challenges), h.idp.pkceRejections)
	}
	if h.status("BCDF-GHJK").Status != registrar.ReqPending {
		t.Fatal("GET changed the request")
	}

	// GET with decision parameters changes nothing.
	h.get(c, "/approve?code=BCDF-GHJK&decision=approve&csrf="+csrfFrom(t, body))
	if h.status("BCDF-GHJK").Status != registrar.ReqPending {
		t.Fatal("GET changed the request")
	}

	body, code = h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"BCDF-GHJK"}, "decision": {"approve"}},
		map[string]string{"Origin": h.web.URL})
	if code != http.StatusOK || !strings.Contains(body, "was approved by you") {
		t.Fatalf("after approving: %d\n%s", code, body)
	}
	r := h.status("BCDF-GHJK")
	if r.Status != registrar.ReqApproved || r.DecidedBy != "oidc:"+h.idp.URL()+",alice" || r.Reason != "Allowed by the registrar's map file ("+h.mapf+" line 1)" {
		t.Fatalf("request after approval: %+v", r)
	}

	// The code cannot be decided twice.
	body, _ = h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"BCDF-GHJK"}, "decision": {"deny"}}, nil)
	if h.status("BCDF-GHJK").Status != registrar.ReqApproved || !strings.Contains(body, "Request approved") {
		t.Fatalf("second decision changed the request:\n%s", body)
	}
}

func TestDeny(t *testing.T) {
	h := newHarness(t)
	h.pending("x.grid.example.org", "BBBB-CCCC")
	c := h.browser()
	h.login(c, "alice")
	body, _ := h.get(c, "/approve?code=BBBB-CCCC")
	if !strings.Contains(body, "You are authorized") {
		t.Fatalf("glob line should authorize:\n%s", body)
	}
	h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"BBBB-CCCC"}, "decision": {"deny"}}, nil)
	if r := h.status("BBBB-CCCC"); r.Status != registrar.ReqDenied {
		t.Fatalf("status %s", r.Status)
	}
}

func TestUnauthorizedUserGetsNoButtons(t *testing.T) {
	h := newHarness(t)
	h.pending(testCE, "DDDD-FFFF")
	c := h.browser()
	h.login(c, "mallory")
	body, code := h.get(c, "/approve?code=DDDD-FFFF")
	if code != http.StatusOK || !strings.Contains(body, "You are not authorized to approve "+testCE) ||
		!strings.Contains(body, "The registrar&#39;s map file does not name you") {
		t.Fatalf("%d\n%s", code, body)
	}
	if strings.Contains(body, `value="approve"`) || strings.Contains(body, `value="deny"`) {
		t.Fatal("unauthorized user offered a decision")
	}
	// A forged POST is refused too.
	body, code = h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"DDDD-FFFF"}, "decision": {"approve"}}, nil)
	if code != http.StatusForbidden || h.status("DDDD-FFFF").Status != registrar.ReqPending {
		t.Fatalf("forged approval: %d\n%s", code, body)
	}
	// So is a deny.
	_, code = h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"DDDD-FFFF"}, "decision": {"deny"}}, nil)
	if code != http.StatusForbidden || h.status("DDDD-FFFF").Status != registrar.ReqPending {
		t.Fatalf("forged denial: %d", code)
	}
}

func TestAdminMayApproveAnyName(t *testing.T) {
	h := newHarness(t)
	h.pending("unlisted.example.edu", "GGGG-HHHH")
	c := h.browser()
	h.login(c, "root")
	body, _ := h.get(c, "/approve?code=GGGG-HHHH")
	if !strings.Contains(body, "Registrar administrator") || !strings.Contains(body, `value="approve"`) {
		t.Fatalf("admin page:\n%s", body)
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	h := newHarness(t)
	h.pending(testCE, "JJJJ-KKKK")
	c := h.browser()
	h.login(c, "alice")
	body, _ := h.get(c, "/approve?code=JJJJ-KKKK")
	tok := csrfFrom(t, body)
	for desc, tc := range map[string]struct {
		form url.Values
		hdr  map[string]string
	}{
		"no token":      {url.Values{"code": {"JJJJ-KKKK"}, "decision": {"approve"}}, nil},
		"wrong token":   {url.Values{"csrf": {tok + "x"}, "code": {"JJJJ-KKKK"}, "decision": {"approve"}}, nil},
		"cross origin":  {url.Values{"csrf": {tok}, "code": {"JJJJ-KKKK"}, "decision": {"approve"}}, map[string]string{"Origin": "https://evil.example"}},
		"null origin":   {url.Values{"csrf": {tok}, "code": {"JJJJ-KKKK"}, "decision": {"approve"}}, map[string]string{"Origin": "null"}},
		"other session": {url.Values{"csrf": {"not-this-sessions-token"}, "code": {"JJJJ-KKKK"}, "decision": {"approve"}}, nil},
	} {
		if _, code := h.post(c, "/approve", tc.form, tc.hdr); code != http.StatusForbidden {
			t.Errorf("%s: %d", desc, code)
		}
	}
	// Signed out: refused, not redirected.
	if _, code := h.post(h.browser(), "/approve", url.Values{"csrf": {tok}, "code": {"JJJJ-KKKK"}, "decision": {"approve"}}, nil); code != http.StatusForbidden {
		t.Errorf("signed out: %d", code)
	}
	if h.status("JJJJ-KKKK").Status != registrar.ReqPending {
		t.Fatal("a refused POST changed the request")
	}
}

func TestCodePages(t *testing.T) {
	h := newHarness(t)
	h.pending(testCE, "LLLL-MMMM")
	h.pending(testCE, "NNNN-PPPP")
	c := h.browser()
	h.login(c, "alice")

	if body, code := h.get(c, "/approve?code=ZZZZ-ZZZZ"); code != http.StatusNotFound || !strings.Contains(body, "No request has the code ZZZZ-ZZZZ") {
		t.Errorf("unknown: %d\n%s", code, body)
	}
	if body, code := h.get(c, "/approve?code=12"); code != http.StatusBadRequest || !strings.Contains(body, "eight letters") {
		t.Errorf("malformed: %d\n%s", code, body)
	}
	body, _ := h.get(c, "/approve?code=NNNN-PPPP")
	h.post(c, "/approve", url.Values{"csrf": {csrfFrom(t, body)}, "code": {"NNNN-PPPP"}, "decision": {"deny"}}, nil)
	if body, code := h.get(c, "/approve?code=NNNN-PPPP"); code != http.StatusOK || !strings.Contains(body, "was denied by you") ||
		strings.Contains(body, `value="approve"`) {
		t.Errorf("decided: %d\n%s", code, body)
	}

	h.clock.Advance(31 * time.Minute)
	body, code := h.get(c, "/approve?code=LLLL-MMMM")
	if code != http.StatusGone || !strings.Contains(body, "expired") || strings.Contains(body, `value="approve"`) {
		t.Errorf("expired: %d\n%s", code, body)
	}
}

func TestStateMismatchRejected(t *testing.T) {
	h := newHarness(t)
	h.idp.setClaims(map[string]any{"sub": "alice"})
	noFollow := func(c *http.Client) *http.Client {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	// step starts a login and returns the provider's redirect back to the
	// registrar, without following it.
	step := func(c *http.Client) *url.URL {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.web.URL+"/login", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		auth, _ := url.Parse(resp.Header.Get("Location"))
		if auth.Query().Get("code_challenge_method") != "S256" || auth.Query().Get("code_challenge") == "" {
			t.Fatalf("authorization request lacks PKCE: %s", auth)
		}
		req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, auth.String(), nil)
		resp, err = c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		back, _ := url.Parse(resp.Header.Get("Location"))
		return back
	}
	signedIn := func(c *http.Client) bool {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.web.URL+"/registrations", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	call := func(c *http.Client, u *url.URL) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// A tampered state.
	victim := noFollow(h.browser())
	back := step(victim)
	q := back.Query()
	q.Set("state", q.Get("state")+"x")
	back.RawQuery = q.Encode()
	if code := call(victim, back); code != http.StatusBadRequest || signedIn(victim) {
		t.Fatalf("tampered state: %d", code)
	}

	// A callback carried to another browser (login CSRF): the state is
	// genuine but not bound to that browser.
	attacker := noFollow(h.browser())
	back = step(attacker)
	other := noFollow(h.browser())
	if code := call(other, back); code != http.StatusBadRequest || signedIn(other) {
		t.Fatalf("unbound state: %d", code)
	}
	if h.idp.tokenRequests != 0 {
		t.Fatalf("a rejected callback still redeemed the code (%d token requests)", h.idp.tokenRequests)
	}

	// The genuine callback works, once.
	if code := call(attacker, back); code != http.StatusSeeOther || !signedIn(attacker) {
		t.Fatalf("genuine callback: %d", code)
	}
	replay := noFollow(h.browser())
	if code := call(replay, back); code != http.StatusBadRequest {
		t.Fatalf("replayed callback: %d", code)
	}
}

func TestPKCEVerifierIsChecked(t *testing.T) {
	h := newHarness(t)
	h.idp.setClaims(map[string]any{"sub": "alice"})
	c := h.browser()
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		// Swap the stored verifier just before the callback is handled.
		if req.URL.Path == "/oidc/callback" {
			l := h.srv.logins
			l.mu.Lock()
			for e := l.order.Front(); e != nil; e = e.Next() {
				e.Value.(*pendingLogin).verifier = "wrong-verifier-wrong-verifier-wrong-verifier"
			}
			l.mu.Unlock()
		}
		return nil
	}
	body, code := h.get(c, "/login")
	if code != http.StatusBadGateway || h.idp.pkceRejections != 1 {
		t.Fatalf("wrong verifier: %d, %d rejections\n%s", code, h.idp.pkceRejections, body)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	h := newHarness(t)
	h.idp.mu.Lock()
	h.idp.issuer = "https://impostor.example.org"
	h.idp.mu.Unlock()
	if _, code := h.get(h.browser(), "/login"); code != http.StatusServiceUnavailable {
		t.Fatalf("issuer mismatch: %d", code)
	}
}

func TestPrincipalClaim(t *testing.T) {
	p := newOIDCProvider(OIDCConfig{PrincipalClaim: "osgid"})
	ep := &oidcEndpoints{Issuer: "https://cilogon.org"}
	id, err := p.identityFrom(ep, map[string]any{"sub": "http://cilogon.org/serverA/users/1", "osgid": "1234"})
	if err != nil || id.Principal != "1234" {
		t.Fatalf("osgid: %+v, %v", id, err)
	}
	if _, err := p.identityFrom(ep, map[string]any{"sub": "x"}); err == nil {
		t.Fatal("missing claim accepted")
	}
	if _, err := p.identityFrom(ep, map[string]any{"osgid": 1234}); err == nil {
		t.Fatal("non-string claim accepted")
	}
	p = newOIDCProvider(OIDCConfig{})
	id, _ = p.identityFrom(ep, map[string]any{"sub": "abc", "email": "a@example.org"})
	if id.Principal != "https://cilogon.org,abc" || id.Display != "a@example.org" {
		t.Fatalf("sub: %+v", id)
	}
}

func TestOpenRedirectRefused(t *testing.T) {
	h := newHarness(t)
	h.idp.setClaims(map[string]any{"sub": "alice"})
	for _, next := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)"} {
		c := h.browser()
		var final *url.URL
		c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
			final = req.URL
			return nil
		}
		h.get(c, "/login?next="+url.QueryEscape(next))
		if final == nil || final.Host != strings.TrimPrefix(h.web.URL, "http://") || final.Path != "/approve" {
			t.Errorf("next=%q ended at %v", next, final)
		}
	}
	for next, want := range map[string]bool{
		"/approve?code=BCDF-GHJK": true,
		"/registrations":          true,
		"":                        false,
		"approve":                 false,
		"//evil":                  false,
		"/\\evil":                 false,
		"/ok\nbad":                false,
		"/ok\r\nSet-Cookie: x":    false,
		"https://x/":              false,
	} {
		if got := safeNext(next); got != want {
			t.Errorf("safeNext(%q) = %v", next, got)
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t)
	c := h.browser()
	h.login(c, "alice")
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if _, code := h.get(c, "/registrations"); code != http.StatusOK {
		t.Fatalf("signed in: %d", code)
	}
	h.clock.Advance(59 * time.Minute)
	if _, code := h.get(c, "/registrations"); code != http.StatusOK {
		t.Fatalf("within idle timeout: %d", code)
	}
	h.clock.Advance(61 * time.Minute)
	if _, code := h.get(c, "/registrations"); code != http.StatusSeeOther {
		t.Fatalf("past idle timeout: %d", code)
	}

	// Absolute lifetime, even when active.
	c = h.browser()
	h.login(c, "alice")
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for i := 1; i <= 14; i++ {
		h.clock.Advance(55 * time.Minute)
		if _, code := h.get(c, "/registrations"); code != http.StatusOK {
			if age := time.Duration(i) * 55 * time.Minute; age <= 12*time.Hour {
				t.Fatalf("expired early, at %s", age)
			}
			return
		}
	}
	t.Fatal("session outlived its lifetime")
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	c := h.browser()
	h.login(c, "alice")
	body, _ := h.get(c, "/approve")
	if body, code := h.post(c, "/logout", url.Values{"csrf": {csrfFrom(t, body)}}, nil); code != http.StatusOK || !strings.Contains(body, "You are signed out") {
		t.Fatalf("logout: %d", code)
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if _, code := h.get(c, "/registrations"); code != http.StatusSeeOther {
		t.Fatalf("after logout: %d", code)
	}
}

func fakeMint(name string) (*mint.Token, error) {
	jti, _ := secret.NewID()
	now := time.Unix(1_800_000_000, 0)
	return &mint.Token{Raw: "tok", JTI: jti, Subject: name + "@users.test", IssuedAt: now, Expiry: now.Add(72 * time.Hour)}, nil
}

// register runs an approval to a registration, approved by approver.
func (h *harness) register(name, code string, by registrar.Identity) string {
	return h.registerFull(name, code, by).RegistrationID
}

func (h *harness) registerFull(name, code string, by registrar.Identity) *registrar.PollResult {
	h.t.Helper()
	ctx := context.Background()
	id, _ := secret.NewID()
	n, err := h.store.CreateRequest(ctx, registrar.NewRequest{RequestIDHash: secret.Hash(id), NonceHash: secret.Hash("n"),
		Name: name, Method: protocol.MethodApproval, UserCode: code, Status: registrar.ReqPending, TTL: time.Hour})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.Decide(ctx, n, true, by, ""); err != nil {
		h.t.Fatal(err)
	}
	res, err := h.store.Poll(ctx, id, "n", registrar.PollOptions{}, fakeMint)
	if err != nil || res.RegistrationID == "" {
		h.t.Fatalf("poll: %+v, %v", res, err)
	}
	return res
}

func TestRenewalRechecksWebApprover(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	alice := registrar.Identity{Kind: authz.IdentityKind, Principal: h.idp.URL() + ",alice"}
	reg := h.registerFull(testCE, "XXXX-ZZZZ", alice)
	cli := h.registerFull(testCE, "XXXX-BBBB", registrar.Identity{Kind: "cedar", Principal: "admin@pool"})
	opts := registrar.RenewOptions{Recheck: registrar.TrustCEDARApprovers{Backend: h.policy}.StillAuthorized}

	res, err := h.store.Renew(ctx, reg.RegistrationID, reg.RefreshSecret, opts, fakeMint)
	if err != nil {
		t.Fatalf("renewal while authorized: %v", err)
	}

	// alice loses the name.
	if err := os.WriteFile(h.mapf, []byte("OIDC someone-else "+testCE+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.mf.Reload(""); err != nil {
		t.Fatal(err)
	}
	var rerr *registrar.RenewError
	if _, err := h.store.Renew(ctx, reg.RegistrationID, res.RefreshSecret, opts, fakeMint); !errors.As(err, &rerr) ||
		rerr.Code != protocol.ErrNotAuthorized {
		t.Fatalf("renewal after losing authorization: %v", err)
	}
	// A command-line (CEDAR ADMINISTRATOR) approval is not re-checked.
	if _, err := h.store.Renew(ctx, cli.RegistrationID, cli.RefreshSecret, opts, fakeMint); err != nil {
		t.Fatalf("CLI-approved renewal: %v", err)
	}
}

func TestRegistrationsAndRevoke(t *testing.T) {
	h := newHarness(t)
	alice := registrar.Identity{Kind: "oidc", Principal: h.idp.URL() + ",alice"}
	byAlice := h.register(testCE, "QQQQ-RRRR", alice)
	byCLI := h.register("x.grid.example.org", "SSSS-TTTT", registrar.Identity{Kind: "cedar", Principal: "admin@pool"})
	other := h.register("other.example.edu", "VVVV-WWWW", registrar.Identity{Kind: "cedar", Principal: "admin@pool"})

	c := h.browser()
	h.login(c, "alice")
	body, _ := h.get(c, "/registrations")
	if !strings.Contains(body, testCE) || !strings.Contains(body, "x.grid.example.org") || strings.Contains(body, "other.example.edu") {
		t.Fatalf("alice sees the wrong registrations:\n%s", body)
	}
	if !strings.Contains(body, "admin@pool (command line)") {
		t.Errorf("CLI approver not shown:\n%s", body)
	}

	m := h.browser()
	h.login(m, "mallory")
	mbody, _ := h.get(m, "/registrations")
	if strings.Contains(mbody, testCE) || !strings.Contains(mbody, "No registrations.") {
		t.Fatalf("mallory sees registrations:\n%s", mbody)
	}
	if _, code := h.post(m, "/registrations/revoke", url.Values{"csrf": {csrfFrom(t, mbody)}, "id": {byAlice}}, nil); code != http.StatusNotFound {
		t.Fatalf("mallory revoked: %d", code)
	}

	root := h.browser()
	h.login(root, "root")
	rbody, _ := h.get(root, "/registrations")
	if !strings.Contains(rbody, "other.example.edu") || !strings.Contains(rbody, "All registrations") {
		t.Fatalf("admin does not see everything:\n%s", rbody)
	}

	body, code := h.post(c, "/registrations/revoke", url.Values{"csrf": {csrfFrom(t, body)}, "id": {byCLI}}, nil)
	if code != http.StatusOK || !strings.Contains(body, "Revoked the registration of <code>x.grid.example.org</code>") {
		t.Fatalf("revoke: %d\n%s", code, body)
	}
	reg, _ := h.store.Registration(context.Background(), byCLI)
	if reg.Status != registrar.RegRevoked || reg.RevokedBy != alice.String() {
		t.Fatalf("after revoke: %+v", reg)
	}
	if r, _ := h.store.Registration(context.Background(), other); r.Status != registrar.RegActive {
		t.Fatal("revoked the wrong registration")
	}

	// alice loses her map file line: she still sees what she approved, but
	// may no longer revoke it.
	if err := os.WriteFile(h.mapf, []byte("OIDC someone-else "+testCE+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.mf.Reload(""); err != nil {
		t.Fatal(err)
	}
	body, _ = h.get(c, "/registrations")
	if !strings.Contains(body, testCE) || strings.Contains(body, `value="`+byAlice+`"`) {
		t.Fatalf("former approver's view:\n%s", body)
	}
	if _, code := h.post(c, "/registrations/revoke", url.Values{"csrf": {csrfFrom(t, body)}, "id": {byAlice}}, nil); code != http.StatusForbidden {
		t.Fatalf("former approver revoked: %d", code)
	}
	if r, _ := h.store.Registration(context.Background(), byAlice); r.Status != registrar.RegActive {
		t.Fatal("a former approver revoked a registration")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/healthz", "/approve", "/login"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(rec, req)
		hd := rec.Header()
		if csp := hd.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
			!strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if hd.Get("X-Frame-Options") != "DENY" || hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, hd)
		}
		if hd.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS on plain HTTP", path)
		}
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") == "" || rec.Body.String() != "ok\n" {
		t.Errorf("HTTPS healthz: %v %q", rec.Header(), rec.Body.String())
	}
	body, _ := h.get(h.browser(), "/static/style.css")
	if !strings.Contains(body, "--accent") {
		t.Error("stylesheet not served")
	}
}

func TestSecureCookies(t *testing.T) {
	h := newHarness(t)
	srv, err := New(context.Background(), Config{
		PublicURL: "https://registrar.example.org",
		OIDC:      OIDCConfig{Issuer: h.idp.URL(), ClientID: h.idp.clientID},
		Store:     h.store,
		Authz:     h.policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login?next=/registrations", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d", rec.Code)
	}
	sc := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"__Host-hrd_login=", "Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age=600"} {
		if !strings.Contains(sc, want) {
			t.Errorf("login cookie %q lacks %q", sc, want)
		}
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("redirect_uri") != "https://registrar.example.org/oidc/callback" {
		t.Errorf("redirect_uri %q", loc.Query().Get("redirect_uri"))
	}
	if got := strings.Fields(loc.Query().Get("scope")); strings.Join(got, " ") != "openid email profile" {
		t.Errorf("scope %q", got)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t)
	c := h.browser()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	limited := false
	for i := 0; i < loginPerMinute+1; i++ {
		if _, code := h.get(c, "/login"); code == http.StatusTooManyRequests {
			limited = true
			if i < loginPerMinute {
				t.Fatalf("limited after %d logins", i)
			}
		}
	}
	if !limited {
		t.Fatal("login not rate-limited")
	}
	h.clock.Advance(time.Minute)
	if _, code := h.get(c, "/login"); code == http.StatusTooManyRequests {
		t.Fatal("limit did not recover")
	}

	// Approve requests have their own budget, keyed by the forwarded
	// address on the loopback HTTP listener.
	l := newIPLimiter(2, 2, h.clock.Now)
	for i, want := range []bool{true, true, false} {
		if got := l.allow("a"); got != want {
			t.Fatalf("request %d from a: %v", i, got)
		}
	}
	if !l.allow("b") {
		t.Fatal("buckets are not per address")
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	def, err := parseProxies(DefaultTrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	custom, err := parseProxies([]string{"127.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		desc    string
		proxies []netip.Prefix
		peer    string
		xff     []string
		tls     bool
		want    string
	}{
		{"behind the proxy", def, "127.0.0.1:5555", []string{"203.0.113.9, 198.51.100.7"}, false, "198.51.100.7"},
		{"IPv6 loopback proxy", def, "[::1]:5555", []string{"198.51.100.7"}, false, "198.51.100.7"},
		{"a trusted hop is skipped", def, "127.0.0.1:5555", []string{"198.51.100.7, 127.0.0.1"}, false, "198.51.100.7"},
		{"several headers", def, "127.0.0.1:5555", []string{"203.0.113.9", "198.51.100.7"}, false, "198.51.100.7"},
		{"trusted chain", custom, "127.0.0.1:5555", []string{"203.0.113.9, 198.51.100.7, 10.1.2.3"}, false, "198.51.100.7"},
		{"forged hop past the last untrusted one", custom, "127.0.0.1:5555", []string{"10.9.9.9, 198.51.100.7, 10.1.2.3"}, false, "198.51.100.7"},
		{"unparsable hop", def, "127.0.0.1:5555", []string{"198.51.100.7, garbage"}, false, "127.0.0.1"},
		{"no header", def, "127.0.0.1:5555", nil, false, "127.0.0.1"},
		{"HTTPS listener", def, "127.0.0.1:5555", []string{"198.51.100.7"}, true, "127.0.0.1"},
		{"untrusted peer", def, "192.0.2.1:5555", []string{"198.51.100.7"}, false, "192.0.2.1"},
		{"loopback outside the list", def, "127.0.0.2:5555", []string{"198.51.100.7"}, false, "127.0.0.2"},
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = tc.peer
		for _, v := range tc.xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		if tc.tls {
			req.TLS = &tls.ConnectionState{}
		}
		if got := clientIP(req, tc.proxies); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.desc, got, tc.want)
		}
	}
	if _, err := parseProxies([]string{"proxy.example.org"}); err == nil {
		t.Error("a host name was accepted as a proxy")
	}
	c, err := FromConfig(knobs.Map{"HTC_REGISTRATIOND_TRUSTED_PROXIES": "192.0.2.5, 2001:db8::/32"})
	if err != nil || len(c.TrustedProxies) != 2 || !trustedProxy(netip.MustParseAddr("2001:db8::7"), c.TrustedProxies) {
		t.Errorf("TRUSTED_PROXIES: %v, %v", c, err)
	}
	if _, err := FromConfig(knobs.Map{"HTC_REGISTRATIOND_TRUSTED_PROXIES": "nope"}); err == nil {
		t.Error("a bad TRUSTED_PROXIES was accepted")
	}
}

func TestFromConfig(t *testing.T) {
	ok := knobs.Map{
		"HTC_REGISTRATIOND_HTTPS_ADDR":     ":8443",
		"HTC_REGISTRATIOND_HTTPS_CERTFILE": "/etc/c.pem",
		"HTC_REGISTRATIOND_HTTPS_KEYFILE":  "/etc/k.pem",
		"HTC_REGISTRATIOND_PUBLIC_URL":     "https://registrar.example.org/",
		"HTC_REGISTRATIOND_OIDC_ISSUER":    "https://cilogon.org",
		"HTC_REGISTRATIOND_OIDC_CLIENT_ID": "cid",
		"HTC_REGISTRATIOND_OIDC_SCOPES":    "openid email profile org.cilogon.userinfo",
	}
	c, err := FromConfig(ok)
	if err != nil || !c.Enabled() || c.VerificationURI() != "https://registrar.example.org/approve" || len(c.OIDC.Scopes) != 4 {
		t.Fatalf("%+v, %v", c, err)
	}
	if c, err := FromConfig(knobs.Map{}); err != nil || c.Enabled() {
		t.Fatalf("no listener: %+v, %v", c, err)
	}
	with := func(k, v string) knobs.Map {
		m := knobs.Map{}
		for a, b := range ok {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for desc, m := range map[string]knobs.Map{
		"no public URL":       with("HTC_REGISTRATIOND_PUBLIC_URL", ""),
		"http public URL":     with("HTC_REGISTRATIOND_PUBLIC_URL", "http://registrar.example.org"),
		"public URL path":     with("HTC_REGISTRATIOND_PUBLIC_URL", "https://registrar.example.org/reg"),
		"no cert":             with("HTC_REGISTRATIOND_HTTPS_CERTFILE", ""),
		"no issuer":           with("HTC_REGISTRATIOND_OIDC_ISSUER", ""),
		"http issuer":         with("HTC_REGISTRATIOND_OIDC_ISSUER", "http://cilogon.org"),
		"no client":           with("HTC_REGISTRATIOND_OIDC_CLIENT_ID", ""),
		"public HTTP":         with("HTC_REGISTRATIOND_HTTP_ADDR", "0.0.0.0:8080"),
		"wildcard HTTP":       with("HTC_REGISTRATIOND_HTTP_ADDR", ":8080"),
		"bad session timeout": with("HTC_REGISTRATIOND_SESSION_IDLE", "soon"),
		"email principal":     with("HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM", "email"),
		"Email principal":     with("HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM", "Email"),
		// Even with the web UI off.
		"email, no listener": {"HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM": "email"},
	} {
		if _, err := FromConfig(m); err == nil {
			t.Errorf("%s: accepted", desc)
		}
	}
	if c, err := FromConfig(with("HTC_REGISTRATIOND_PUBLIC_URL", "HTTPS://Registrar.Example.org:443")); err != nil ||
		c.VerificationURI() != "https://registrar.example.org/approve" {
		t.Errorf("non-canonical public URL: %v", err)
	}
	if _, err := FromConfig(with("HTC_REGISTRATIOND_HTTP_ADDR", "127.0.0.1:8080")); err != nil {
		t.Errorf("loopback HTTP: %v", err)
	}
	if _, err := FromConfig(knobs.Map{
		"HTC_REGISTRATIOND_HTTP_ADDR":      "[::1]:8080",
		"HTC_REGISTRATIOND_PUBLIC_URL":     "http://localhost:8080",
		"HTC_REGISTRATIOND_OIDC_ISSUER":    "https://cilogon.org",
		"HTC_REGISTRATIOND_OIDC_CLIENT_ID": "cid",
	}); err != nil {
		t.Errorf("loopback-only setup: %v", err)
	}
}

func TestLoginStartWritesNothingToTheDatabase(t *testing.T) {
	h := newHarness(t)
	c := h.browser()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	db := h.store.DB()
	var before, after int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM web_sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, code := h.get(c, "/login"); code != http.StatusFound {
			t.Fatalf("login: %d", code)
		}
	}
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM web_sessions`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	var tables int
	if err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sqlite_master WHERE name = 'web_logins'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if before != after || tables != 0 || h.srv.logins.len() != 5 {
		t.Fatalf("sessions %d -> %d, web_logins tables %d, logins in memory %d", before, after, tables, h.srv.logins.len())
	}
}

func TestLoginStoreIsBounded(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newLoginStore(clock.Now, 3)
	for _, st := range []string{"a", "b", "c", "d"} {
		l.save(st, "v-"+st, "/"+st)
	}
	if l.len() != 3 {
		t.Fatalf("holding %d logins, want 3", l.len())
	}
	if _, _, ok := l.take("a"); ok {
		t.Error("the oldest login was not dropped")
	}
	if v, next, ok := l.take("d"); !ok || v != "v-d" || next != "/d" {
		t.Errorf("newest login: %q %q %v", v, next, ok)
	}
	if _, _, ok := l.take("d"); ok {
		t.Error("a login was taken twice")
	}
	clock.Advance(loginTTL + time.Second)
	if _, _, ok := l.take("b"); ok {
		t.Error("an expired login was taken")
	}
	l.save("e", "v-e", "/e")
	if l.len() != 1 {
		t.Errorf("expired logins kept: %d held", l.len())
	}
}

func TestLimiterNetworks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newIPLimiter(1, 1, clock.Now)
	for _, tc := range []struct {
		ip    string
		allow bool
	}{
		{"2001:db8:1:2::1", true},
		{"2001:db8:1:2:ffff::9", false}, // same /64
		{"2001:db8:1:3::1", true},       // next /64
		{"192.0.2.1", true},
		{"::ffff:192.0.2.1", false}, // the same IPv4 address
		{"192.0.2.2", true},
	} {
		if got := l.allow(tc.ip); got != tc.allow {
			t.Errorf("allow(%s) = %v, want %v", tc.ip, got, tc.allow)
		}
	}
}

func TestLimiterEvictsLeastRecent(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newIPLimiter(1, 1, clock.Now)
	l.max = 2
	l.allow("192.0.2.1") // spends 192.0.2.1's token
	l.allow("192.0.2.2")
	if l.allow("192.0.2.1") { // and touches it
		t.Fatal("192.0.2.1 was not limited")
	}
	l.allow("192.0.2.3") // full: forgets 192.0.2.2, the least recent
	if l.allow("192.0.2.1") {
		t.Error("a full limiter forgot a recent client")
	}
	if len(l.clients) != 2 || l.lru.Len() != 2 {
		t.Errorf("holding %d/%d clients, want 2", len(l.clients), l.lru.Len())
	}
	if !l.allow("192.0.2.2") {
		t.Error("the evicted client was not forgotten")
	}
}

func TestPublicURLIsCanonical(t *testing.T) {
	for raw, want := range map[string]string{
		"https://registrar.example.org":         "https://registrar.example.org",
		"HTTPS://Registrar.Example.ORG:443/":    "https://registrar.example.org",
		"https://registrar.example.org:8443":    "https://registrar.example.org:8443",
		"http://LocalHost:80":                   "http://localhost",
		"http://[::1]:8080":                     "http://[::1]:8080",
		"https://[2001:DB8::1]:443":             "https://[2001:db8::1]",
		"https://registrar.example.org:80":      "https://registrar.example.org:80",
		"http://registrar.example.org:443/path": "http://registrar.example.org:443",
	} {
		if got, err := canonicalOrigin(raw); err != nil || got != want {
			t.Errorf("canonicalOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}

	// A form posted by a browser, whose Origin is canonical, is accepted
	// when PUBLIC_URL is not written canonically.
	h := newHarness(t)
	srv, err := New(context.Background(), Config{
		PublicURL: "https://Registrar.Example.ORG:443/",
		OIDC:      OIDCConfig{Issuer: h.idp.URL(), ClientID: h.idp.clientID},
		Store:     h.store,
		Authz:     h.policy,
		Now:       h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.redirectURL(); got != "https://registrar.example.org/oidc/callback" {
		t.Errorf("redirect URI %q", got)
	}
	id, sess, err := srv.sessions.create(context.Background(), h.idp.URL()+",alice", "")
	if err != nil {
		t.Fatal(err)
	}
	// Signing out ends the session, so the accepted origin comes last.
	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"https://evil.example", http.StatusForbidden},
		{"https://registrar.example.org:443", http.StatusForbidden}, // browsers never send this
		{"https://registrar.example.org", http.StatusOK},
	} {
		origin, want := tc.origin, tc.want
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout",
			strings.NewReader(url.Values{"csrf": {sess.CSRF}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.AddCookie(&http.Cookie{Name: "__Host-" + sessionCookie, Value: id, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Origin %s: %d, want %d", origin, rec.Code, want)
		}
	}
}

func TestDiscoveryOutlivesTheBrowserThatStartedIt(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "userinfo_endpoint": srv.URL + "/userinfo",
		})
	}))
	t.Cleanup(srv.Close)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock) // runs before srv.Close, which waits for the handler
	p := newOIDCProvider(OIDCConfig{Issuer: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := p.endpoints(ctx)
		first <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("discovery did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The provider's lock is free while discovery runs.
	done := make(chan struct{})
	go func() {
		p.setSecret("new-secret")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the lock is held across discovery")
	}

	// The browser that started discovery goes away; it stops waiting...
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled caller: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a canceled caller kept waiting")
	}
	// ...but discovery completes, once, for everyone else.
	unblock()
	ep, err := p.endpoints(context.Background())
	if err != nil || ep.AuthURL != srv.URL+"/authorize" {
		t.Fatalf("after the first browser left: %+v, %v", ep, err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("discovery ran %d times", n)
	}
}

func TestCodeFormAfterSessionEnds(t *testing.T) {
	h := newHarness(t)
	h.pending(testCE, "BCDF-GHJK")
	c := h.browser()
	h.login(c, "alice")
	body, _ := h.get(c, "/approve")
	if !strings.Contains(body, `name="via" value="form"`) {
		t.Fatalf("the code form does not mark itself:\n%s", body)
	}
	h.clock.Advance(2 * time.Hour)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// Submitted from the form: a page with a sign-in link, not a redirect
	// that form-action 'self' would block on its way to the provider.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/approve?code=BCDF-GHJK&via=form", nil)
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" {
		t.Fatalf("signed-out form submission: %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), `<a href="/login?next=%2Fapprove%3Fcode%3DBCDF-GHJK">Sign in to continue</a>`) {
		t.Errorf("no sign-in link:\n%s", rec.Body.String())
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("CSP %q", csp)
	}

	// Following a link (the CE's verification URI) still redirects.
	if _, code := h.get(c, "/approve?code=BCDF-GHJK"); code != http.StatusSeeOther {
		t.Errorf("signed-out link: %d", code)
	}
}

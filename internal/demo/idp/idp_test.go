package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const redirect = "http://localhost:9999/oidc/callback"

func newProvider(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	p := New(Config{Issuer: srv.URL, ClientID: "client", ClientSecret: "secret", RedirectURI: redirect,
		Users: []User{{Sub: "alice", Name: "Alice"}}, EmailDomain: "example.org"})
	srv.Config.Handler = p.Handler()
	return srv
}

// noFollow is a client that returns redirects instead of following them.
var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// result is a response, read and closed.
type result struct {
	status int
	header http.Header
	body   []byte
}

func (r result) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("%v: %s", err, r.body)
	}
	return m
}

func do(t *testing.T, method, u string, form url.Values, setup func(*http.Request)) result {
	t.Helper()
	var req *http.Request
	var err error
	if form != nil {
		req, err = http.NewRequestWithContext(context.Background(), method, u, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(context.Background(), method, u, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(req)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return result{resp.StatusCode, resp.Header, body}
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// login signs in as sub and returns the authorization code.
func login(t *testing.T, srv *httptest.Server, sub, verifier string) string {
	t.Helper()
	resp := do(t, http.MethodPost, srv.URL+"/authorize", url.Values{
		"client_id": {"client"}, "redirect_uri": {redirect}, "state": {"st"},
		"code_challenge": {challenge(verifier)}, "user": {sub},
	}, nil)
	if resp.status != http.StatusFound {
		t.Fatalf("login: HTTP %d", resp.status)
	}
	loc, err := url.Parse(resp.header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), redirect) || loc.Query().Get("state") != "st" {
		t.Fatalf("login redirected to %q", resp.header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func exchange(t *testing.T, srv *httptest.Server, code, verifier, secret string) result {
	t.Helper()
	return do(t, http.MethodPost, srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	}, func(r *http.Request) { r.SetBasicAuth("client", secret) })
}

func TestDiscovery(t *testing.T) {
	srv := newProvider(t)
	resp := do(t, http.MethodGet, srv.URL+"/.well-known/openid-configuration", nil, nil)
	if doc := resp.json(t); doc["issuer"] != srv.URL || doc["userinfo_endpoint"] != srv.URL+"/userinfo" {
		t.Errorf("discovery: %v", doc)
	}
}

func TestAuthorizeChecksRequest(t *testing.T) {
	srv := newProvider(t)
	q := url.Values{"client_id": {"client"}, "redirect_uri": {"http://evil.example/cb"}, "response_type": {"code"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	if resp := do(t, http.MethodGet, srv.URL+"/authorize?"+q.Encode(), nil, nil); resp.status != http.StatusBadRequest {
		t.Errorf("unregistered redirect URI: HTTP %d, want 400", resp.status)
	}
	q.Set("redirect_uri", redirect)
	q.Del("code_challenge")
	resp := do(t, http.MethodGet, srv.URL+"/authorize?"+q.Encode(), nil, nil)
	if loc := resp.header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("no PKCE challenge: redirected to %q, want error=invalid_request", loc)
	}
	q.Set("code_challenge", "x")
	if resp := do(t, http.MethodGet, srv.URL+"/authorize?"+q.Encode(), nil, nil); resp.status != http.StatusOK {
		t.Errorf("login page: HTTP %d", resp.status)
	}
}

// TestLoginPageFormAction: browsers apply form-action to the redirect that
// answers the login form, so it must allow the client's origin.
func TestLoginPageFormAction(t *testing.T) {
	srv := newProvider(t)
	q := url.Values{"client_id": {"client"}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	resp := do(t, http.MethodGet, srv.URL+"/authorize?"+q.Encode(), nil, nil)
	csp := resp.header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://localhost:9999") || strings.Contains(csp, "/oidc") {
		t.Errorf("login page CSP %q", csp)
	}
	for _, attr := range []string{`required`, `pattern="[A-Za-z0-9._@\-]{1,64}"`, `formnovalidate`} {
		if !strings.Contains(string(resp.body), attr) {
			t.Errorf("login page lacks %s", attr)
		}
	}
}

func TestTokenAndUserinfo(t *testing.T) {
	srv := newProvider(t)
	const verifier = "the-verifier-0123456789-0123456789-0123456789"

	code := login(t, srv, "alice", verifier)
	if resp := exchange(t, srv, code, "another-verifier-0123456789-0123456789", "secret"); resp.status != http.StatusBadRequest {
		t.Errorf("wrong PKCE verifier: HTTP %d, want 400", resp.status)
	}
	if resp := exchange(t, srv, code, verifier, "secret"); resp.status != http.StatusBadRequest {
		t.Errorf("reused code: HTTP %d, want 400", resp.status)
	}

	code = login(t, srv, "alice", verifier)
	if resp := exchange(t, srv, code, verifier, "wrong"); resp.status != http.StatusUnauthorized {
		t.Errorf("wrong client secret: HTTP %d, want 401", resp.status)
	}

	code = login(t, srv, "alice", verifier)
	resp := exchange(t, srv, code, verifier, "secret")
	tok := resp.json(t)
	access, _ := tok["access_token"].(string)
	if resp.status != http.StatusOK || access == "" {
		t.Fatalf("token: HTTP %d %v", resp.status, tok)
	}
	resp = do(t, http.MethodGet, srv.URL+"/userinfo", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+access) })
	if claims := resp.json(t); claims["sub"] != "alice" || claims["name"] != "Alice" || claims["email"] != "alice@example.org" {
		t.Errorf("userinfo: %s", resp.body)
	}
	if resp := do(t, http.MethodGet, srv.URL+"/userinfo", nil, nil); resp.status != http.StatusUnauthorized {
		t.Errorf("userinfo without a token: HTTP %d, want 401", resp.status)
	}
}

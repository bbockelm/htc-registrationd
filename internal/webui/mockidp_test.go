package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockIDP is an in-process OpenID provider: discovery, an authorization
// endpoint that signs in a configured user at once, a token endpoint that
// enforces PKCE (S256) and client authentication, and a userinfo endpoint.
type mockIDP struct {
	t   *testing.T
	srv *httptest.Server

	clientID, clientSecret string

	mu sync.Mutex
	// claims are returned by userinfo for tokens issued from now on.
	claims map[string]any
	codes  map[string]mockGrant
	tokens map[string]map[string]any
	// issuer, when set, is what discovery claims instead of the real URL.
	issuer string
	// Observations.
	challenges     []string
	pkceRejections int
	tokenRequests  int
	issued         int
}

type mockGrant struct {
	challenge   string
	redirectURI string
	claims      map[string]any
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	m := &mockIDP{
		t:            t,
		clientID:     "registrar-client",
		clientSecret: "registrar-secret",
		codes:        map[string]mockGrant{},
		tokens:       map[string]map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", m.discovery)
	mux.HandleFunc("GET /authorize", m.authorize)
	mux.HandleFunc("POST /token", m.token)
	mux.HandleFunc("GET /userinfo", m.userinfo)
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIDP) URL() string { return m.srv.URL }

func (m *mockIDP) setClaims(c map[string]any) {
	m.mu.Lock()
	m.claims = c
	m.mu.Unlock()
}

func (m *mockIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	iss := m.issuer
	m.mu.Unlock()
	if iss == "" {
		iss = m.srv.URL
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 iss,
		"authorization_endpoint": m.srv.URL + "/authorize",
		"token_endpoint":         m.srv.URL + "/token",
		"userinfo_endpoint":      m.srv.URL + "/userinfo",
	})
}

func (m *mockIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("response_type") != "code" || q.Get("client_id") != m.clientID || redirect == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	back, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	out := back.Query()
	out.Set("state", q.Get("state"))
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		out.Set("error", "invalid_request")
		back.RawQuery = out.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // test provider redirects to the registered client
		return
	}
	m.mu.Lock()
	m.challenges = append(m.challenges, q.Get("code_challenge"))
	m.issued++
	code := "code-" + strconv.Itoa(m.issued)
	m.codes[code] = mockGrant{challenge: q.Get("code_challenge"), redirectURI: redirect, claims: m.claims}
	m.mu.Unlock()
	out.Set("code", code)
	back.RawQuery = out.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // test provider redirects to the registered client
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (m *mockIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request")
		return
	}
	id, sec, ok := r.BasicAuth()
	if !ok {
		id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != m.clientID || sec != m.clientSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenRequests++
	code := r.PostForm.Get("code")
	g, found := m.codes[code]
	delete(m.codes, code)
	if r.PostForm.Get("grant_type") != "authorization_code" || !found || r.PostForm.Get("redirect_uri") != g.redirectURI {
		tokenError(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		m.pkceRejections++
		tokenError(w, "invalid_grant")
		return
	}
	access := "access-" + strconv.Itoa(len(m.tokens)+1)
	m.tokens[access] = g.claims
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600})
}

func (m *mockIDP) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Lock()
	claims, found := m.tokens[tok]
	m.mu.Unlock()
	if !ok || !found {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(claims)
}

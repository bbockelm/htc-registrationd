// Package idp is a small OpenID Connect provider for the laptop demo:
// discovery, an authorization endpoint whose login page lets the user pick
// (or type) an identity, a token endpoint that authenticates the client and
// enforces PKCE (S256, RFC 7636), and a userinfo endpoint. It holds no
// passwords: anyone who reaches the login page may sign in as anyone.
package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// User is an identity offered on the login page.
type User struct {
	// Sub is the subject claim, and what configuration names the user by.
	Sub string
	// Name is the display name claim.
	Name string
	// Note says what the identity may do; it is shown on the login page.
	Note string
}

// Config configures the provider.
type Config struct {
	// Issuer is the provider's URL, with no trailing slash; it must be the
	// URL the provider is served at.
	Issuer string
	// ClientID and ClientSecret are the one registered client's credentials.
	ClientID     string
	ClientSecret string
	// RedirectURI is the client's one registered redirect URI.
	RedirectURI string
	// Users are offered on the login page. Any other subject may be typed.
	Users []User
	// EmailDomain forms the email claim, <sub>@<EmailDomain>.
	EmailDomain string
	Logger      *slog.Logger
	Now         func() time.Time
}

// Lifetimes of an authorization code and an access token.
const (
	codeTTL   = 5 * time.Minute
	accessTTL = time.Hour
)

// Provider is the OpenID provider.
type Provider struct {
	cfg  Config
	page *template.Template
	csp  string

	mu     sync.Mutex
	codes  map[string]grant
	tokens map[string]grant
}

type grant struct {
	sub         string
	challenge   string
	redirectURI string
	expires     time.Time
}

//go:embed login.html
var files embed.FS

// New returns a provider.
func New(cfg Config) *Provider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	return &Provider{
		cfg:    cfg,
		page:   template.Must(template.ParseFS(files, "login.html")),
		csp:    loginCSP(cfg.RedirectURI),
		codes:  map[string]grant{},
		tokens: map[string]grant{},
	}
}

// Handler serves the provider's endpoints.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.loginPage)
	mux.HandleFunc("POST /authorize", p.login)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("htc-registrationd demo identity provider\n"))
	})
	return mux
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.cfg.Issuer,
		"authorization_endpoint":                p.cfg.Issuer + "/authorize",
		"token_endpoint":                        p.cfg.Issuer + "/token",
		"userinfo_endpoint":                     p.cfg.Issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported":                      []string{"sub", "name", "email", "preferred_username"},
	})
}

// authzRequest is the part of an authorization request the provider checks
// and carries through the login form.
type authzRequest struct {
	ClientID, RedirectURI, State, Challenge, Scope string
}

// check validates an authorization request (RFC 6749 section 4.1.1 with
// PKCE). It returns an error message for the user when the redirect URI
// cannot be trusted, and the OAuth error code to send back to the client
// otherwise.
func (p *Provider) check(q url.Values) (authzRequest, string, string) {
	r := authzRequest{
		ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope"),
	}
	if r.ClientID != p.cfg.ClientID {
		return r, "Unknown client " + r.ClientID + ".", ""
	}
	if r.RedirectURI != p.cfg.RedirectURI {
		return r, "The redirect URI " + r.RedirectURI + " is not registered for this client.", ""
	}
	if q.Get("response_type") != "code" {
		return r, "", "unsupported_response_type"
	}
	if q.Get("code_challenge_method") != "S256" || r.Challenge == "" {
		return r, "", "invalid_request"
	}
	return r, "", ""
}

func (p *Provider) redirect(w http.ResponseWriter, r *http.Request, req authzRequest, params url.Values) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "bad redirect URI", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // the redirect URI is the registered one
}

type loginView struct {
	Issuer string
	Req    authzRequest
	Users  []User
	Error  string
	Typed  string
}

// loginCSP is the login page's Content-Security-Policy. Browsers apply
// form-action to every redirect that follows a form submission, and the
// login form's answer is a redirect to the client's redirect URI, so its
// origin must be allowed as well as the provider's own.
func loginCSP(redirectURI string) string {
	formAction := "'self'"
	if u, err := url.Parse(redirectURI); err == nil && u.Scheme != "" && u.Host != "" {
		formAction += " " + u.Scheme + "://" + u.Host
	}
	return "default-src 'none'; style-src 'unsafe-inline'; form-action " + formAction
}

func (p *Provider) render(w http.ResponseWriter, status int, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", p.csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := p.page.Execute(w, v); err != nil {
		p.cfg.Logger.Error("idp: rendering the login page", "err", err)
	}
}

func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request) {
	req, fatal, oauthErr := p.check(r.URL.Query())
	switch {
	case fatal != "":
		http.Error(w, fatal, http.StatusBadRequest)
	case oauthErr != "":
		p.redirect(w, r, req, url.Values{"error": {oauthErr}})
	default:
		p.render(w, http.StatusOK, loginView{Issuer: p.cfg.Issuer, Req: req, Users: p.cfg.Users})
	}
}

// validSub is what may be typed as a subject.
var validSub = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func (p *Provider) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	q := url.Values{
		"client_id": {r.PostForm.Get("client_id")}, "redirect_uri": {r.PostForm.Get("redirect_uri")},
		"state": {r.PostForm.Get("state")}, "code_challenge": {r.PostForm.Get("code_challenge")},
		"code_challenge_method": {"S256"}, "response_type": {"code"}, "scope": {r.PostForm.Get("scope")},
	}
	req, fatal, oauthErr := p.check(q)
	if fatal != "" || oauthErr != "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Has("cancel") {
		p.redirect(w, r, req, url.Values{"error": {"access_denied"}})
		return
	}
	sub := strings.TrimSpace(r.PostForm.Get("user"))
	if sub == "" {
		sub = strings.TrimSpace(r.PostForm.Get("other"))
	}
	if !validSub.MatchString(sub) {
		p.render(w, http.StatusBadRequest, loginView{Issuer: p.cfg.Issuer, Req: req, Users: p.cfg.Users,
			Typed: sub, Error: "A subject is 1 to 64 letters, digits, '.', '_', '@' or '-'."})
		return
	}
	code := newSecret()
	p.mu.Lock()
	p.codes[code] = grant{sub: sub, challenge: req.Challenge, redirectURI: req.RedirectURI,
		expires: p.cfg.Now().Add(codeTTL)}
	p.mu.Unlock()
	p.cfg.Logger.Info("idp: signed in", "sub", sub)
	p.redirect(w, r, req, url.Values{"code": {code}})
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, sec, ok := r.BasicAuth()
	if ok {
		// client_secret_basic form-encodes the credentials (RFC 6749
		// section 2.3.1).
		id, _ = url.QueryUnescape(id)
		sec, _ = url.QueryUnescape(sec)
	} else {
		id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.cfg.ClientID || subtle.ConstantTimeCompare([]byte(sec), []byte(p.cfg.ClientSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, found := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	now := p.cfg.Now()
	if !found || now.After(g.expires) || r.PostForm.Get("redirect_uri") != g.redirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(g.challenge)) != 1 {
		p.cfg.Logger.Warn("idp: PKCE verifier does not match the challenge", "sub", g.sub)
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	access := newSecret()
	g.expires = now.Add(accessTTL)
	p.mu.Lock()
	for k, v := range p.tokens {
		if now.After(v.expires) {
			delete(p.tokens, k)
		}
	}
	p.tokens[access] = g
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access, "token_type": "Bearer", "expires_in": int(accessTTL / time.Second),
		"scope": "openid email profile",
	})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	g, found := p.tokens[tok]
	p.mu.Unlock()
	if !ok || !found || p.cfg.Now().After(g.expires) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	claims := map[string]any{"sub": g.sub, "preferred_username": g.sub, "name": g.sub}
	for _, u := range p.cfg.Users {
		if u.Sub == g.sub && u.Name != "" {
			claims["name"] = u.Name
		}
	}
	if p.cfg.EmailDomain != "" {
		claims["email"] = g.sub + "@" + p.cfg.EmailDomain
	}
	writeJSON(w, http.StatusOK, claims)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

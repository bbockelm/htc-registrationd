package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OIDCConfig configures login with an OpenID Connect provider: the
// authorization-code flow with PKCE, identity read from the userinfo
// endpoint.
type OIDCConfig struct {
	// Issuer is the provider's issuer URL; its
	// /.well-known/openid-configuration names the endpoints.
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes requested (default openid email profile).
	Scopes []string
	// PrincipalClaim names the userinfo claim that identifies the user.
	// For "sub" (the default) the principal is "<issuer>,<sub>", since a
	// subject is unique only within its issuer; for any other claim it is
	// the claim's value.
	PrincipalClaim string
	// HTTPClient talks to the provider (default: 30 s timeout, system
	// roots).
	HTTPClient *http.Client
}

// DefaultScopes are requested when OIDCConfig.Scopes is empty.
var DefaultScopes = []string{"openid", "email", "profile"}

// maxProviderResponse caps a discovery or userinfo document.
const maxProviderResponse = 1 << 20

// discoveryRetry is the least time between two failed discoveries.
const discoveryRetry = 10 * time.Second

type oidcEndpoints struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

type oidcProvider struct {
	cfg OIDCConfig

	mu       sync.Mutex
	ep       *oidcEndpoints
	failedAt time.Time
	lastErr  error
	secret   string
}

func newOIDCProvider(cfg OIDCConfig) *oidcProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = DefaultScopes
	}
	if cfg.PrincipalClaim == "" {
		cfg.PrincipalClaim = "sub"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &oidcProvider{cfg: cfg, secret: cfg.ClientSecret}
}

// setSecret replaces the client secret (on reconfig).
func (p *oidcProvider) setSecret(s string) {
	p.mu.Lock()
	p.secret = s
	p.mu.Unlock()
}

// endpoints returns the provider's endpoints, discovering them on first use.
// A failed discovery is retried, at most once per discoveryRetry.
func (p *oidcProvider) endpoints(ctx context.Context) (*oidcEndpoints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ep != nil {
		return p.ep, nil
	}
	if !p.failedAt.IsZero() && time.Since(p.failedAt) < discoveryRetry {
		return nil, p.lastErr
	}
	ep, err := p.discover(ctx)
	if err != nil {
		p.failedAt, p.lastErr = time.Now(), err
		return nil, err
	}
	p.ep = ep
	return ep, nil
}

func trimSlash(s string) string { return strings.TrimRight(s, "/") }

func (p *oidcProvider) discover(ctx context.Context) (*oidcEndpoints, error) {
	u := trimSlash(p.cfg.Issuer) + "/.well-known/openid-configuration"
	var ep oidcEndpoints
	if err := p.getJSON(ctx, u, "", &ep); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	// The document must describe the configured issuer (OpenID Connect
	// Discovery 1.0, section 4.3).
	if trimSlash(ep.Issuer) != trimSlash(p.cfg.Issuer) {
		return nil, fmt.Errorf("OIDC discovery: %s describes issuer %q, not %q", u, ep.Issuer, p.cfg.Issuer)
	}
	if ep.AuthURL == "" || ep.TokenURL == "" || ep.UserInfoURL == "" {
		return nil, fmt.Errorf("OIDC discovery: %s lacks an authorization, token or userinfo endpoint", u)
	}
	return &ep, nil
}

func (p *oidcProvider) getJSON(ctx context.Context, u, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse+1))
	if err != nil {
		return err
	}
	if len(body) > maxProviderResponse {
		return fmt.Errorf("%s returned more than %d bytes", u, maxProviderResponse)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: %w", u, err)
	}
	return nil
}

// oauth2Config is the client configuration for one login.
func (p *oidcProvider) oauth2Config(ep *oidcEndpoints, redirectURL string) *oauth2.Config {
	p.mu.Lock()
	secret := p.secret
	p.mu.Unlock()
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: secret,
		Endpoint:     oauth2.Endpoint{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL},
		RedirectURL:  redirectURL,
		Scopes:       p.cfg.Scopes,
	}
}

// exchange redeems an authorization code, proving possession of the PKCE
// verifier.
func (p *oidcProvider) exchange(ctx context.Context, ep *oidcEndpoints, redirectURL, code, verifier string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.cfg.HTTPClient)
	return p.oauth2Config(ep, redirectURL).Exchange(ctx, code, oauth2.VerifierOption(verifier))
}

// identity is who logged in.
type identity struct {
	Principal string
	Display   string
}

// userInfo reads the user's claims and derives the principal.
func (p *oidcProvider) userInfo(ctx context.Context, ep *oidcEndpoints, tok *oauth2.Token) (*identity, error) {
	if tok.AccessToken == "" {
		return nil, errors.New("the token response has no access token")
	}
	claims := map[string]any{}
	if err := p.getJSON(ctx, ep.UserInfoURL, tok.AccessToken, &claims); err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	return p.identityFrom(ep, claims)
}

func (p *oidcProvider) identityFrom(ep *oidcEndpoints, claims map[string]any) (*identity, error) {
	claim := p.cfg.PrincipalClaim
	v, _ := claims[claim].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("the identity provider returned no %q claim", claim)
	}
	id := &identity{Principal: v}
	if claim == "sub" {
		id.Principal = ep.Issuer + "," + v
	}
	for _, c := range []string{"name", "email", "preferred_username"} {
		if s, ok := claims[c].(string); ok && strings.TrimSpace(s) != "" {
			id.Display = strings.TrimSpace(s)
			break
		}
	}
	return id, nil
}

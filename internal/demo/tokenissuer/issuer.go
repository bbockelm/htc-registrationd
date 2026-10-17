// Package tokenissuer is a SciToken issuer for tests: it publishes OAuth
// discovery and a JWKS with one ES256 key, and mints a WLCG-profile token
// for any subject, audience and scope a caller asks for. It authenticates
// no one; it exists so an HTCondor-CE can validate tokens from an issuer it
// reaches over https.
package tokenissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DefaultScope is what a compute element needs to run a pilot.
const DefaultScope = "compute.create compute.read compute.modify compute.cancel"

// Config configures the issuer.
type Config struct {
	// Issuer is the issuer URL, with no trailing slash; it must be the
	// https:// URL the issuer is served at.
	Issuer string
	// Lifetime is a minted token's lifetime when the request names none.
	Lifetime time.Duration
	Logger   *slog.Logger
	Now      func() time.Time
}

// Issuer is the token issuer.
type Issuer struct {
	cfg Config
	key *ecdsa.PrivateKey
	kid string
}

// New returns an issuer with a fresh signing key.
func New(cfg Config) (*Issuer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = 20 * time.Minute
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &Issuer{cfg: cfg, key: key, kid: b64(sum[:8])}, nil
}

// Handler serves discovery, the JWKS and the mint endpoint.
func (s *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("POST /mint", s.mint)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("htc-registrationd demo SciToken issuer\n"))
	})
	return mux
}

func (s *Issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"jwks_uri":                              s.cfg.Issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

func (s *Issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	pub, err := s.key.PublicKey.Bytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// pub is 0x04 || X || Y, each 32 bytes.
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
		"x": b64(pub[1:33]), "y": b64(pub[33:65]),
	}}})
}

// Request names what a minted token says.
type Request struct {
	Subject  string
	Audience string
	// Scope is space-separated; empty means DefaultScope.
	Scope    string
	Lifetime time.Duration
}

// Mint returns a signed token.
func (s *Issuer) Mint(r Request) (string, error) {
	if r.Subject == "" || r.Audience == "" {
		return "", errors.New("a token needs a subject and an audience")
	}
	if r.Scope == "" {
		r.Scope = DefaultScope
	}
	if r.Lifetime <= 0 {
		r.Lifetime = s.cfg.Lifetime
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := s.cfg.Now().Unix()
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": s.cfg.Issuer, "sub": r.Subject, "aud": r.Audience, "scope": r.Scope,
		"wlcg.ver": "1.0", "iat": now, "nbf": now, "exp": now + int64(r.Lifetime/time.Second),
		"jti": fmt.Sprintf("%x", jti),
	})
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	der, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return "", err
	}
	// JWS carries R || S, each left-padded to 32 bytes (RFC 7518 3.4).
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return signing + "." + b64(raw), nil
}

// mint answers POST /mint with form fields sub, aud, scope (optional) and
// lifetime (optional, a Go duration) with the token as text.
func (s *Issuer) mint(w http.ResponseWriter, r *http.Request) {
	req := Request{Subject: r.PostFormValue("sub"), Audience: r.PostFormValue("aud"), Scope: r.PostFormValue("scope")}
	if v := r.PostFormValue("lifetime"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			http.Error(w, "lifetime: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Lifetime = d
	}
	tok, err := s.Mint(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Logger.Info("minted a token", "sub", req.Subject, "aud", req.Audience, "scope", req.Scope)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(tok + "\n"))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

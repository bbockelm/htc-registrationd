package tokenissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, u string, v any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", u, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func mint(t *testing.T, srv *httptest.Server, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/mint", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMintVerifiesWithPublishedKey follows discovery to the JWKS, as
// scitokens-cpp does, and checks a minted token's signature and claims.
func TestMintVerifiesWithPublishedKey(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	now := time.Unix(1_800_000_000, 0)
	iss, err := New(Config{Issuer: srv.URL + "/", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = iss.Handler()

	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	get(t, srv.URL+"/.well-known/openid-configuration", &disc)
	if disc.Issuer != srv.URL {
		t.Fatalf("issuer %q, want %q", disc.Issuer, srv.URL)
	}
	var set struct {
		Keys []struct{ Kty, Crv, Alg, Kid, X, Y string } `json:"keys"`
	}
	get(t, disc.JWKSURI, &set)
	if len(set.Keys) != 1 {
		t.Fatalf("%d keys, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
		t.Fatalf("key %+v, want an ES256 P-256 key", k)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, decode(t, k.X)...), decode(t, k.Y)...))
	if err != nil {
		t.Fatal(err)
	}

	code, tok := mint(t, srv, url.Values{"sub": {"pilot"}, "aud": {"ce1.test:9619"}, "lifetime": {"10m"}})
	if code != http.StatusOK {
		t.Fatalf("mint: %d %s", code, tok)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header map[string]string
	if err := json.Unmarshal(decode(t, parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != k.Kid {
		t.Fatalf("header %v, want ES256 with kid %s", header, k.Kid)
	}
	sig := decode(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify with the published key")
	}
	var claims map[string]any
	if err := json.Unmarshal(decode(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss": srv.URL, "sub": "pilot", "aud": "ce1.test:9619", "scope": DefaultScope, "wlcg.ver": "1.0",
		"iat": float64(now.Unix()), "nbf": float64(now.Unix()), "exp": float64(now.Add(10 * time.Minute).Unix()),
	}
	for c, v := range want {
		if claims[c] != v {
			t.Errorf("claim %s = %v, want %v", c, claims[c], v)
		}
	}
	if jti, _ := claims["jti"].(string); len(jti) != 32 {
		t.Errorf("jti %v, want 32 hex digits", claims["jti"])
	}
}

func TestMintNeedsSubjectAndAudience(t *testing.T) {
	iss, err := New(Config{Issuer: "https://issuer.test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(iss.Handler())
	t.Cleanup(srv.Close)
	for _, form := range []url.Values{{"sub": {"pilot"}}, {"aud": {"ce1.test:9619"}}, {"sub": {"p"}, "aud": {"a"}, "lifetime": {"soon"}}} {
		if code, body := mint(t, srv, form); code != http.StatusBadRequest {
			t.Errorf("mint %v: %d %s, want 400", form, code, body)
		}
	}
}

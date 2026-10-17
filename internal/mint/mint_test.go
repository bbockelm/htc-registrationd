package mint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

func newMinter(t *testing.T, keyID string) *Minter {
	t.Helper()
	dir := t.TempDir()
	if keyID == "POOL" {
		if err := security.GeneratePoolSigningKey(filepath.Join(dir, keyID)); err != nil {
			t.Fatal(err)
		}
	} else if err := security.GenerateSigningKey(filepath.Join(dir, keyID)); err != nil {
		t.Fatal(err)
	}
	return &Minter{
		KeyDir:      dir,
		PoolKeyFile: filepath.Join(dir, "POOL"),
		KeyID:       keyID,
		Issuer:      "users.htcondor.org",
		Domain:      "users.htcondor.org",
		Limits:      []string{"ADVERTISE_SCHEDD"},
		Lifetime:    72 * time.Hour,
		ReadKey:     os.ReadFile,
	}
}

// A minted token verifies with cedar's verifier, for a named key and for the
// POOL key (which HTCondor doubles before HKDF), and carries the expected sub,
// iss, scope, lifetime, back-dated nbf and jti claims.
func TestMintVerifiesWithCedar(t *testing.T) {
	for _, keyID := range []string{"ce-registration", "POOL"} {
		t.Run(keyID, func(t *testing.T) {
			m := newMinter(t, keyID)
			tok, err := m.Mint("ce.example.edu")
			if err != nil {
				t.Fatal(err)
			}
			cfg := &security.SecurityConfig{TokenSigningKeyDir: m.KeyDir}
			if keyID == "POOL" {
				cfg.TokenPoolSigningKeyFile = filepath.Join(m.KeyDir, "POOL")
			}
			claims, err := security.VerifyIDToken(tok.Raw, cfg)
			if err != nil {
				t.Fatalf("cedar rejects the minted token: %v", err)
			}
			if claims.Subject != "ce.example.edu@users.htcondor.org" {
				t.Errorf("sub = %q", claims.Subject)
			}
			if claims.Issuer != "users.htcondor.org" {
				t.Errorf("iss = %q", claims.Issuer)
			}
			if claims.Scope != "condor:/ADVERTISE_SCHEDD" {
				t.Errorf("scope = %q", claims.Scope)
			}
			if got := claims.Expiry - claims.IssuedAt; got != int64((72 * time.Hour).Seconds()) {
				t.Errorf("lifetime %ds", got)
			}
			nbf, _ := claims.Raw["nbf"].(float64)
			if int64(nbf) != claims.IssuedAt-10 {
				t.Errorf("nbf = %v, want iat-10", nbf)
			}
			if jti, _ := claims.Raw["jti"].(string); jti != tok.JTI || len(jti) != 32 {
				t.Errorf("jti = %q, recorded %q", jti, tok.JTI)
			}
			pc, err := ParseUnverified(tok.Raw)
			if err != nil {
				t.Fatal(err)
			}
			if pc.KeyID != keyID || pc.Subject != tok.Subject {
				t.Errorf("ParseUnverified = %+v", pc)
			}
		})
	}
}

// A token signed with one key does not verify under another of the same name.
func TestMintWrongKeyFails(t *testing.T) {
	m := newMinter(t, "ce-registration")
	tok, err := m.Mint("ce.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	other := newMinter(t, "ce-registration")
	if _, err := security.VerifyIDToken(tok.Raw, &security.SecurityConfig{TokenSigningKeyDir: other.KeyDir}); err == nil {
		t.Fatal("token verified under a different key")
	}
}

func TestMintRejectsBadKeyName(t *testing.T) {
	m := newMinter(t, "ce-registration")
	for _, bad := range []string{"", "../POOL", "a/b"} {
		m.KeyID = bad
		if _, err := m.Mint("x"); err == nil || !strings.Contains(err.Error(), "invalid signing key") {
			t.Errorf("key %q: err = %v", bad, err)
		}
	}
}

func TestMintMissingKey(t *testing.T) {
	m := newMinter(t, "ce-registration")
	m.KeyID = "absent"
	if err := m.Check(); err == nil {
		t.Fatal("Check passed with no key file")
	}
}

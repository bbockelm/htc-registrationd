//go:build !windows

package mint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

// The POOL key is read from SEC_TOKEN_POOL_SIGNING_KEY_FILE, as HTCondor
// reads it, not from SEC_PASSWORD_DIRECTORY.
func TestPoolKeyFile(t *testing.T) {
	poolFile := filepath.Join(t.TempDir(), "pool_signing_key")
	if err := security.GeneratePoolSigningKey(poolFile); err != nil {
		t.Fatal(err)
	}
	m := &Minter{KeyDir: t.TempDir(), PoolKeyFile: poolFile, KeyID: PoolKeyID, Issuer: "pool.test",
		Lifetime: 72 * time.Hour, ReadKey: os.ReadFile}
	if path, err := m.KeyFile(); err != nil || path != poolFile {
		t.Fatalf("KeyFile = %q, %v; want %q", path, err, poolFile)
	}
	tok, err := m.Mint("ce.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.VerifyIDToken(tok.Raw, &security.SecurityConfig{TokenPoolSigningKeyFile: poolFile}); err != nil {
		t.Fatalf("token signed with the POOL key file does not verify: %v", err)
	}
	m.PoolKeyFile = ""
	if _, err := m.Mint("ce.example.edu"); err == nil || !strings.Contains(err.Error(), "SEC_TOKEN_POOL_SIGNING_KEY_FILE") {
		t.Fatalf("POOL without SEC_TOKEN_POOL_SIGNING_KEY_FILE: %v", err)
	}
	if created, err := m.CreateKeyIfMissing(); created || err != nil {
		t.Fatalf("created a POOL key with nowhere to put it: %v %v", created, err)
	}
}

// The key file must pass HTCondor's read_secure_file checks: owned by the
// real uid and not accessible to group or others.
func TestReadSecure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ce-registration")
	if err := security.GenerateSigningKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecure(path); err != nil {
		t.Fatalf("a 0600 key owned by this uid was refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o610} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readSecure(path); err == nil || !strings.Contains(err.Error(), "group or others") {
			t.Errorf("mode %04o: %v, want refused", mode, err)
		}
	}
	m := &Minter{KeyDir: filepath.Dir(path), KeyID: "ce-registration", Lifetime: time.Hour}
	if err := m.Check(); err == nil {
		t.Fatal("the minter accepted a group-readable key")
	}
}

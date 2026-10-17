//go:build linux

package mint

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/testpriv"
)

// TestKeyAsRootAfterDrop is the registrar under a root master: with the
// effective uid dropped, it creates the signing key in a root-only
// directory as root, mode 0600, and mints with it through the default
// root read, which also enforces HTCondor's ownership check.
func TestKeyAsRootAfterDrop(t *testing.T) {
	dir := t.TempDir() // root:root 0700, like passwords.d
	uid, _, restore := testpriv.Drop(t)
	m := &Minter{KeyDir: dir, KeyID: "ce-registration", Issuer: "pool.test", Domain: "users.test",
		Limits: []string{"ADVERTISE_SCHEDD"}, Lifetime: time.Hour}
	if _, err := os.ReadDir(dir); err == nil {
		t.Fatalf("uid %d can read the root-only key directory; the test proves nothing", uid)
	}
	created, err := m.CreateKeyIfMissing()
	if err != nil || !created {
		t.Fatalf("CreateKeyIfMissing after the drop = %v, %v", created, err)
	}
	if os.Geteuid() != uid {
		t.Fatalf("euid %d after creating the key, want %d", os.Geteuid(), uid)
	}
	tok, err := m.Mint("ce.example.edu")
	if err != nil {
		t.Fatalf("minting with the root-only key: %v", err)
	}
	if created, err := m.CreateKeyIfMissing(); created || err != nil {
		t.Fatalf("a second CreateKeyIfMissing = %v, %v", created, err)
	}

	restore()
	path := filepath.Join(dir, "ce-registration")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key is %d:%d %04o, want 0:0 0600", st.Uid, st.Gid, fi.Mode().Perm())
	}
	if _, err := security.VerifyIDToken(tok.Raw, &security.SecurityConfig{TokenSigningKeyDir: dir, TrustDomain: "pool.test"}); err != nil {
		t.Fatalf("token does not verify with the key: %v", err)
	}
}

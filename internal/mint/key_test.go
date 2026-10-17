package mint

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

func keyMinter(t *testing.T) *Minter {
	t.Helper()
	return &Minter{
		KeyDir:   t.TempDir(),
		KeyID:    "ce-registration",
		Issuer:   "users.htcondor.org",
		Domain:   "users.htcondor.org",
		Limits:   []string{"ADVERTISE_SCHEDD"},
		Lifetime: time.Hour,
		ReadKey:  os.ReadFile,
	}
}

// A created key is 64 bytes, mode 0600, and reads back through cedar's
// security package: cedar signs a token with it that cedar's VerifyIDToken
// accepts, and a token this package mints with it verifies too.
func TestCreateKeyIfMissingCedarCompatible(t *testing.T) {
	m := keyMinter(t)
	created, err := m.CreateKeyIfMissing()
	if err != nil || !created {
		t.Fatalf("CreateKeyIfMissing = %v, %v", created, err)
	}
	path := filepath.Join(m.KeyDir, m.KeyID)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != KeySize {
		t.Errorf("key file is %d bytes, want %d", fi.Size(), KeySize)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
	}

	cfg := &security.SecurityConfig{TokenSigningKeyDir: m.KeyDir}
	now := time.Now().Unix()
	raw, err := security.GenerateJWT(m.KeyDir, m.KeyID, "ce.example.edu@users.htcondor.org", "users.htcondor.org", now, now+600, nil)
	if err != nil {
		t.Fatalf("cedar cannot sign with the created key: %v", err)
	}
	if _, err := security.VerifyIDToken(raw, cfg); err != nil {
		t.Fatalf("cedar rejects a token it signed with the created key: %v", err)
	}
	tok, err := m.Mint("ce.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.VerifyIDToken(tok.Raw, cfg); err != nil {
		t.Fatalf("cedar rejects a token minted with the created key: %v", err)
	}
}

// The on-disk bytes are the key XORed with 0xdeadbeef: unscrambling yields the
// key the minter signs with, and the scrambled file is not the key itself.
func TestCreateKeyIfMissingScrambles(t *testing.T) {
	m := keyMinter(t)
	if _, err := m.CreateKeyIfMissing(); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(m.KeyDir, m.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	key, err := m.signingKey()
	if err != nil {
		t.Fatal(err)
	}
	for i := range key {
		if key[i] != onDisk[i]^[]byte{0xde, 0xad, 0xbe, 0xef}[i%4] {
			t.Fatalf("byte %d: key %#x, file %#x", i, key[i], onDisk[i])
		}
	}
}

// An existing key, or a symlink at the key's path, is never replaced, and a
// second call is a no-op.
func TestCreateKeyIfMissingNeverOverwrites(t *testing.T) {
	m := keyMinter(t)
	path := filepath.Join(m.KeyDir, m.KeyID)
	if err := security.GeneratePoolSigningKey(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		created, err := m.CreateKeyIfMissing()
		if err != nil || created {
			t.Fatalf("CreateKeyIfMissing over an existing key = %v, %v", created, err)
		}
	}
	after, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an existing key was replaced")
	}

	// A dangling symlink is not followed to create its target.
	link := keyMinter(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(link.KeyDir, link.KeyID)); err != nil {
		t.Fatal(err)
	}
	if created, err := link.CreateKeyIfMissing(); err != nil || created {
		t.Fatalf("CreateKeyIfMissing over a symlink = %v, %v", created, err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("the symlink's target was created: %v", err)
	}
}

// Without SEC_PASSWORD_DIRECTORY nothing is created; a missing directory or a
// bad key name is an error.
func TestCreateKeyIfMissingErrors(t *testing.T) {
	m := keyMinter(t)
	m.KeyDir = ""
	if created, err := m.CreateKeyIfMissing(); err != nil || created {
		t.Fatalf("no key directory: %v, %v", created, err)
	}
	m = keyMinter(t)
	m.KeyDir = filepath.Join(m.KeyDir, "missing")
	if _, err := m.CreateKeyIfMissing(); err == nil {
		t.Fatal("no error for a missing key directory")
	}
	m = keyMinter(t)
	m.KeyID = "../escape"
	if _, err := m.CreateKeyIfMissing(); err == nil {
		t.Fatal("no error for a key name with ..")
	}
}

type failingFile struct {
	*os.File
}

func (failingFile) Write([]byte) (int, error) { return 10, errors.New("disk full") }

// A failed write leaves an empty file, never part of a key, and the minter
// refuses it.
func TestCreateKeyIfMissingWriteFailure(t *testing.T) {
	m := keyMinter(t)
	orig := openExclusive
	t.Cleanup(func() { openExclusive = orig })
	openExclusive = func(path string) (keyFile, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // test temp file
		if err != nil {
			return nil, err
		}
		_, _ = f.Write(make([]byte, 10))
		return failingFile{f}, nil
	}
	if created, err := m.CreateKeyIfMissing(); err == nil || created {
		t.Fatalf("CreateKeyIfMissing with a failing write = %v, %v", created, err)
	}
	fi, err := os.Stat(filepath.Join(m.KeyDir, m.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("a failed write left %d bytes", fi.Size())
	}
	if err := m.Check(); err == nil {
		t.Fatal("the minter accepts an empty key")
	}
}

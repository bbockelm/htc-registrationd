//go:build linux

package webui

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bbockelm/htc-registrationd/internal/authz"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/testpki"
	"github.com/bbockelm/htc-registrationd/internal/testpriv"
)

// TestRootOnlyCredentialsAfterDrop is the registrar under a root master: the
// HTTPS key and certificate and the OIDC client secret are root:root 0600 in
// a root-only directory, the daemon has dropped to an unprivileged uid, and
// the UI still reads them, at startup and on reconfig, through its default
// credential reader.
func TestRootOnlyCredentialsAfterDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ca := testpki.NewCA(t)
	certFile, keyFile := ca.ServerCert(t, "registrar.test") // under a root 0700 TempDir
	secretFile := filepath.Join(filepath.Dir(keyFile), "client-secret")
	if err := os.WriteFile(secretFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The database belongs to the dropped user, as $(SPOOL) does to condor.
	u, err := user.Lookup(testpriv.User)
	if err != nil {
		t.Skip(err)
	}
	dbDir, err := os.MkdirTemp("", "webui-root")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dbDir) })
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chown(dbDir, uid, gid); err != nil {
		t.Fatal(err)
	}

	_, _, restore := testpriv.Drop(t)
	for _, f := range []string{certFile, keyFile, secretFile} {
		if _, err := os.ReadFile(f); err == nil { //nolint:gosec // test files
			t.Fatalf("%s is readable after the drop; the test proves nothing", f)
		}
	}
	store, err := registrar.OpenStore(filepath.Join(dbDir, "registrar.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	srv, err := New(context.Background(), Config{
		PublicURL:        "https://registrar.test:9619",
		SharedPort:       true,
		CertFile:         certFile,
		KeyFile:          keyFile,
		ClientSecretFile: secretFile,
		OIDC:             OIDCConfig{Issuer: "https://idp.test", ClientID: "cid"},
		Store:            store,
		Authz:            authz.NewPolicy(nil, nil),
	})
	if err != nil {
		t.Fatalf("New after the drop: %v", err)
	}
	if srv.oidc.cfg.ClientSecret != "s3cret" {
		t.Fatalf("client secret %q", srv.oidc.cfg.ClientSecret)
	}
	if c, err := srv.certs.GetCertificate(nil); err != nil || c == nil {
		t.Fatalf("no serving certificate: %v", err)
	}
	if err := os.WriteFile(secretFile, []byte("rotated\n"), 0o600); err == nil {
		t.Fatal("the dropped uid wrote the root-only secret")
	}
	restore()
	if err := os.WriteFile(secretFile, []byte("rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _ = testpriv.Drop(t)
	srv.Reload()
	if srv.oidc.cfg.ClientSecret != "rotated" {
		t.Fatalf("after reconfig, client secret %q", srv.oidc.cfg.ClientSecret)
	}
}

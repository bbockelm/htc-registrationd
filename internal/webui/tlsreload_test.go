package webui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/testpki"
)

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from) //nolint:gosec // test files in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil { //nolint:gosec // test files in t.TempDir
		t.Fatal(err)
	}
}

func TestCertReloader(t *testing.T) {
	ca := testpki.NewCA(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	c1, k1 := ca.ServerCert(t, "one.registrar.test")
	copyFile(t, c1, certFile)
	copyFile(t, k1, keyFile)
	r, err := newCertReloader(certFile, keyFile, os.ReadFile, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	name := func() string {
		c, err := r.GetCertificate(nil)
		if err != nil || c.Leaf == nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		return c.Leaf.Subject.CommonName
	}
	if name() != "one.registrar.test" {
		t.Fatal("initial certificate")
	}

	// A renewal takes effect at the next check.
	c2, k2 := ca.ServerCert(t, "two.registrar.test")
	copyFile(t, c2, certFile)
	copyFile(t, k2, keyFile)
	if name() != "one.registrar.test" {
		t.Fatal("re-read before the interval")
	}
	now = now.Add(2 * certReloadInterval)
	if name() != "two.registrar.test" {
		t.Fatal("renewal not picked up")
	}

	// Half a renewal (new certificate, old key) keeps the pair in use.
	c3, k3 := ca.ServerCert(t, "three.registrar.test")
	copyFile(t, c3, certFile)
	now = now.Add(2 * certReloadInterval)
	if name() != "two.registrar.test" {
		t.Fatal("installed a mismatched pair")
	}
	// A forced reload (reconfig) does not wait for the interval.
	copyFile(t, k3, keyFile)
	r.refresh(true)
	if name() != "three.registrar.test" {
		t.Fatal("forced reload")
	}

	if _, err := newCertReloader(filepath.Join(dir, "missing"), keyFile, os.ReadFile, slog.Default()); err == nil {
		t.Fatal("started without a certificate")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestServeHTTPS(t *testing.T) {
	h := newHarness(t)
	ca := testpki.NewCA(t)
	certFile, keyFile := ca.ServerCert(t, "localhost")
	addr := freePort(t)
	srv, err := New(context.Background(), Config{
		PublicURL:      "https://localhost",
		HTTPSAddr:      addr,
		CertFile:       certFile,
		KeyFile:        keyFile,
		OIDC:           OIDCConfig{Issuer: h.idp.URL(), ClientID: h.idp.clientID},
		Store:          h.store,
		Authz:          h.policy,
		ReadCredential: os.ReadFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := srv.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(ca.CertFile)
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatalf("healthz over HTTPS: %d %v", resp.StatusCode, resp.Header)
	}
}

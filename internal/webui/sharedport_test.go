//go:build unix

package webui

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/portsplit"
	"github.com/bbockelm/htc-registrationd/internal/sharedporttest"
	"github.com/bbockelm/htc-registrationd/internal/testpki"
)

// TestServeSharedPort serves the UI on connections forwarded by a stand-in
// for condor_shared_port, at a public URL with the shared port's host:port,
// while CEDAR connections on the same endpoint go elsewhere.
func TestServeSharedPort(t *testing.T) {
	h := newHarness(t)
	ca := testpki.NewCA(t)
	certFile, keyFile := ca.ServerCert(t, "localhost")
	ep := sharedporttest.New(t)
	split := portsplit.Split(ep.Listener, nil)
	t.Cleanup(func() { _ = split.Close() })
	_, port, _ := net.SplitHostPort(ep.Addr)
	public := "https://localhost:" + port

	srv, err := New(context.Background(), Config{
		PublicURL:      public,
		SharedPort:     true,
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
	stop, err := srv.Start(ctx, split.Web())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(ca.CertFile)
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	get := func(path string) (int, http.Header) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, public+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	if code, hdr := get("/healthz"); code != http.StatusOK || hdr.Get("Strict-Transport-Security") == "" {
		t.Fatalf("healthz on the shared port: %d %v", code, hdr)
	}
	// Sign-in goes to the provider with a redirect URI on the shared port.
	code, hdr := get("/login?next=/registrations")
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil || code != http.StatusFound || !strings.HasPrefix(loc.String(), h.idp.URL()) ||
		loc.Query().Get("redirect_uri") != public+"/oidc/callback" {
		t.Fatalf("login on the shared port: %d %s", code, hdr.Get("Location"))
	}

	// Plain HTTP on the shared port is refused, as on any HTTPS port.
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// net/http answers 400 and closes. The close can reset the connection
	// before the answer is read (the rest of the request is unread), so a
	// reset or end of stream with nothing read is a refusal too.
	line, err := bufio.NewReader(c).ReadString('\n')
	var ne net.Error
	if line != "" && !strings.Contains(line, " 400 ") ||
		line == "" && (errors.As(err, &ne) && ne.Timeout() || err == nil) {
		t.Fatalf("plain HTTP on the shared port: %q, %v", line, err)
	}

	// CEDAR on the same endpoint is not the UI's.
	cc, err := (&net.Dialer{}).DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	_, _ = io.WriteString(cc, "\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x01\x2c\xd0")
	got := make(chan net.Conn, 1)
	go func() {
		if a, err := split.CEDAR().Accept(); err == nil {
			got <- a
		}
	}()
	select {
	case a := <-got:
		_ = a.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("CEDAR connection not delivered to the CEDAR listener")
	}
}

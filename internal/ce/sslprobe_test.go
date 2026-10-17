package ce

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/testpki"
)

// cedarSSLBug is the error cedar v0.7.10 (and the cedar#93 head) returns for
// every Go-to-Go SSL handshake: in confirmHandshakeCompletion the server sends
// its stale TLS-pump status (2, "receiving") where AUTH_SSL_HOLDING (4) is
// expected, so both ends fail the HOLDING check. Setting
// ssl.serverStatus = AuthSSLHolding before the server sends fixes it.
const cedarSSLBug = "expected both sides in HOLDING"

var (
	sslProbeOnce sync.Once
	sslProbeErr  error
)

// requireGoSSL skips the calling test, loudly, when the linked cedar cannot
// complete a Go-to-Go SSL handshake because of the known bug above, and fails
// it on any other probe error. Set HTC_REGISTRATIOND_REQUIRE_GO_SSL=1 to turn
// the skip into a failure.
func requireGoSSL(t *testing.T) {
	t.Helper()
	sslProbeOnce.Do(func() { sslProbeErr = probeGoSSL(t) })
	if sslProbeErr == nil {
		return
	}
	if strings.Contains(sslProbeErr.Error(), cedarSSLBug) && os.Getenv("HTC_REGISTRATIOND_REQUIRE_GO_SSL") == "" {
		t.Skipf("SKIPPED: the linked cedar cannot complete a Go-to-Go SSL handshake (%v); "+
			"this test needs a cedar whose SSL server sends AUTH_SSL_HOLDING in confirmHandshakeCompletion", sslProbeErr)
	}
	t.Fatalf("Go-to-Go SSL probe failed: %v", sslProbeErr)
}

func probeGoSSL(t *testing.T) error {
	ca := testpki.NewCA(t)
	certFile, keyFile := ca.ServerCert(t, "probe.test")
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods: []security.AuthMethod{security.AuthSSL}, Authentication: security.SecurityRequired,
		CryptoMethods: []security.CryptoMethod{security.CryptoAES}, Encryption: security.SecurityRequired,
		CertFile: certFile, KeyFile: keyFile, SessionCache: security.NewSessionCache(),
	})
	srv.Authorizer = func(string, string, string) bool { return true }
	srv.Handle(4242, func(context.Context, *cedarserver.Conn) error { return nil }, "ALLOW")
	addr := serve(t, srv)
	sc := cedarx.SSLOnly(&security.SecurityConfig{CAFile: ca.CertFile}, 4242, "probe.test", addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := cedarx.DialSSL(ctx, &client.ClientConfig{Address: addr, Security: sc, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	return cl.Close()
}

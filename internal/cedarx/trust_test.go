package cedarx

import (
	"testing"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/knobs"
)

func TestSSLTrust(t *testing.T) {
	cfg := knobs.Map{
		"AUTH_SSL_CLIENT_CAFILE":          "/etc/a.pem,/etc/b.pem",
		"AUTH_SSL_CLIENT_CADIR":           "/etc/grid-security/certificates",
		"AUTH_SSL_SERVER_USE_DEFAULT_CAS": "false",
	}
	var sc security.SecurityConfig
	if err := SSLTrust(cfg, "CLIENT", &sc); err != nil {
		t.Fatal(err)
	}
	if sc.CAFile != "/etc/a.pem,/etc/b.pem" || sc.CADir != "/etc/grid-security/certificates" {
		t.Fatalf("CAFile %q CADir %q", sc.CAFile, sc.CADir)
	}
	// System roots stay trusted unless the knob says otherwise.
	if sc.UseDefaultCAs == nil || !*sc.UseDefaultCAs {
		t.Fatalf("UseDefaultCAs %v, want true", sc.UseDefaultCAs)
	}

	sc = security.SecurityConfig{CAFile: "/stale.pem"}
	if err := SSLTrust(cfg, "SERVER", &sc); err != nil {
		t.Fatal(err)
	}
	if sc.CAFile != "" || sc.CADir != "" || sc.UseDefaultCAs == nil || *sc.UseDefaultCAs {
		t.Fatalf("server trust: CAFile %q CADir %q UseDefaultCAs %v", sc.CAFile, sc.CADir, sc.UseDefaultCAs)
	}

	if err := SSLTrust(knobs.Map{"AUTH_SSL_CLIENT_USE_DEFAULT_CAS": "maybe"}, "CLIENT", &sc); err == nil {
		t.Fatal("an unparseable USE_DEFAULT_CAS was accepted")
	}
}

func TestServerSSLTrust(t *testing.T) {
	srv := cedarserver.New(&security.SecurityConfig{CAFile: "/client-side.pem"})
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		if cmd == 1 {
			return &security.SecurityConfig{Command: 1}
		}
		return nil
	}
	HardenCommands(srv, 2)
	if err := ServerSSLTrust(knobs.Map{"AUTH_SSL_SERVER_CAFILE": "/server.pem"}, srv); err != nil {
		t.Fatal(err)
	}
	if srv.SecurityConfig.CAFile != "/server.pem" {
		t.Fatalf("base CAFile %q", srv.SecurityConfig.CAFile)
	}
	for _, cmd := range []int{1, 2} {
		sc := srv.SecurityConfigForCommand(cmd)
		if sc == nil || sc.CAFile != "/server.pem" || sc.UseDefaultCAs == nil || !*sc.UseDefaultCAs {
			t.Fatalf("command %d: %+v", cmd, sc)
		}
	}
	if sc := srv.SecurityConfigForCommand(3); sc != nil {
		t.Fatalf("command 3 gained a config: %+v", sc)
	}
}

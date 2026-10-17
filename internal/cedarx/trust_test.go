package cedarx

import (
	"sync/atomic"
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
	SSLTrust(cfg, "CLIENT", &sc)
	if sc.CAFile != "/etc/a.pem,/etc/b.pem" || sc.CADir != "/etc/grid-security/certificates" {
		t.Fatalf("CAFile %q CADir %q", sc.CAFile, sc.CADir)
	}
	// System roots stay trusted unless the knob says otherwise.
	if sc.UseDefaultCAs == nil || !*sc.UseDefaultCAs {
		t.Fatalf("UseDefaultCAs %v, want true", sc.UseDefaultCAs)
	}

	sc = security.SecurityConfig{CAFile: "/stale.pem"}
	SSLTrust(cfg, "SERVER", &sc)
	if sc.CAFile != "" || sc.CADir != "" || sc.UseDefaultCAs == nil || *sc.UseDefaultCAs {
		t.Fatalf("server trust: CAFile %q CADir %q UseDefaultCAs %v", sc.CAFile, sc.CADir, sc.UseDefaultCAs)
	}

	// An invalid value keeps the default, as in HTCondor.
	SSLTrust(knobs.Map{"AUTH_SSL_CLIENT_USE_DEFAULT_CAS": "maybe"}, "CLIENT", &sc)
	if sc.UseDefaultCAs == nil || !*sc.UseDefaultCAs {
		t.Fatalf("an invalid USE_DEFAULT_CAS: UseDefaultCAs %v, want the default true", sc.UseDefaultCAs)
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
	var cur atomic.Pointer[knobs.Map]
	// HTCondor-CE's defaults: a candidate list, and FS as the only method.
	cur.Store(&knobs.Map{"AUTH_SSL_SERVER_CAFILE": "/server.pem",
		"AUTH_SSL_SERVER_CERTFILE": "/etc/pki/tls/certs/localhost.crt,/etc/grid-security/hostcert.pem",
		"AUTH_SSL_SERVER_KEYFILE":  "/etc/pki/tls/private/localhost.key,/etc/grid-security/hostkey.pem"})
	ServerSSLTrust(func() knobs.Getter { return *cur.Load() }, srv)
	if srv.SecurityConfig.CAFile != "/server.pem" {
		t.Fatalf("base CAFile %q", srv.SecurityConfig.CAFile)
	}
	for _, cmd := range []int{1, 2, 3} {
		sc := srv.SecurityConfigForCommand(cmd)
		if sc == nil || sc.CAFile != "/server.pem" || sc.UseDefaultCAs == nil || !*sc.UseDefaultCAs ||
			sc.CertFile != "/etc/pki/tls/certs/localhost.crt,/etc/grid-security/hostcert.pem" ||
			sc.KeyFile != "/etc/pki/tls/private/localhost.key,/etc/grid-security/hostkey.pem" {
			t.Fatalf("command %d: %+v", cmd, sc)
		}
	}
	// A reconfig is seen by the next handshake.
	cur.Store(&knobs.Map{"AUTH_SSL_SERVER_CAFILE": "/new.pem", "AUTH_SSL_SERVER_USE_DEFAULT_CAS": "false"})
	for _, cmd := range []int{1, 2, 3} {
		sc := srv.SecurityConfigForCommand(cmd)
		if sc.CAFile != "/new.pem" || *sc.UseDefaultCAs {
			t.Fatalf("after reconfig, command %d: %+v", cmd, sc)
		}
	}
	if sc := srv.SecurityConfigForCommand(2); len(sc.AuthMethods) != 1 || sc.AuthMethods[0] != security.AuthSSL {
		t.Fatalf("hardening lost: %+v", sc.AuthMethods)
	}
}

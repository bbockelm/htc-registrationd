package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/knobs"
	"github.com/bbockelm/htc-registrationd/internal/testpki"
)

// SEC_TOKEN_DIRECTORY, when set, wins over SEC_TOKEN_SYSTEM_DIRECTORY, as in
// HTCondor's findTokens.
//
//nolint:gosec // G101: directory names, not credentials
func TestTokenFile(t *testing.T) {
	cases := []struct {
		cfg  knobs.Map
		want string
	}{
		{knobs.Map{"SEC_TOKEN_SYSTEM_DIRECTORY": "/etc/condor-ce/tokens.d"}, "/etc/condor-ce/tokens.d/50-htc-registration"},
		{knobs.Map{"SEC_TOKEN_SYSTEM_DIRECTORY": "/etc/condor-ce/tokens.d", "SEC_TOKEN_DIRECTORY": "/srv/tokens"},
			"/srv/tokens/50-htc-registration"},
		{knobs.Map{"SEC_TOKEN_DIRECTORY": "/srv/tokens", "HTC_REGISTRATIOND_TOKEN_FILE": "/x/tok"}, "/x/tok"},
	}
	for _, tc := range cases {
		if got, err := tokenFile(tc.cfg); err != nil || got != tc.want {
			t.Errorf("%v: %q %v, want %q", tc.cfg, got, err, tc.want)
		}
	}
	if _, err := tokenFile(knobs.Map{}); err == nil {
		t.Error("no token directory accepted")
	}
}

//nolint:gosec // G101: directory names, not credentials
func TestCESettings(t *testing.T) {
	s, err := ceSettings(knobs.Map{
		"SEC_TOKEN_SYSTEM_DIRECTORY":         "/etc/condor-ce/tokens.d",
		"CONDOR_VIEW_HOST":                   "collector.example.org:9619",
		"HTC_REGISTRATIOND_METHOD":           "Approval",
		"HTC_REGISTRATIOND_CONNECT_TIMEOUT":  "12",
		"HTC_REGISTRATIOND_CALLBACK_WAIT":    "2m",
		"HTC_REGISTRATIOND_REGISTRAR_NAME":   "registrar.example.org",
		"HTC_REGISTRATIOND_CALLBACK_ADDRESS": "ignored here",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != "approval" || s.Registrar != "<collector.example.org:9619?sock=htc_registrationd>" ||
		s.RegistrarServerName != "registrar.example.org" || s.ConnectTimeout != 12*time.Second ||
		s.CallbackWait != 2*time.Minute || s.TokenFile != "/etc/condor-ce/tokens.d/50-htc-registration" {
		t.Fatalf("settings %+v", s)
	}
}

// The registrar refuses to run without an issuer, and an issuer may not
// contain spaces or commas, as in HTCondor.
func TestTrustDomain(t *testing.T) {
	if td, err := trustDomain(knobs.Map{"TRUST_DOMAIN": "cm.example.org"}); err != nil || td != "cm.example.org" {
		t.Fatalf("%q %v", td, err)
	}
	// No fallback of this daemon's own: the configuration's default applies.
	if _, err := trustDomain(knobs.Map{"UID_DOMAIN": "example.org"}); err == nil {
		t.Fatal("an unset TRUST_DOMAIN fell back to UID_DOMAIN")
	}
	for _, bad := range []string{"a b", "a,b", "a\tb"} {
		if _, err := trustDomain(knobs.Map{"TRUST_DOMAIN": bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The address file is replaced via <path>.new, as DaemonCore writes it.
func TestWriteFileViaNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".htc_registrationd_address")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileViaNew(path, []byte("<1.2.3.4:9618>\n")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A rename puts a new file in place; rewriting in place keeps the old one,
	// which a reader could see half written.
	if os.SameFile(before, after) {
		t.Fatal("the address file was rewritten in place, not replaced")
	}
	b, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil || !strings.HasPrefix(string(b), "<1.2.3.4") {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Fatalf("the .new file was left behind: %v", err)
	}
}

// The tool reads HTCondor-CE's configuration unless CONDOR_CONFIG names
// another, and only when that file exists.
func TestUseCEConfig(t *testing.T) {
	old := ceConfig
	t.Cleanup(func() { ceConfig = old })
	ceConfig = filepath.Join(t.TempDir(), "condor_config")

	t.Setenv("CONDOR_CONFIG", "/elsewhere/condor_config")
	useCEConfig()
	if got := os.Getenv("CONDOR_CONFIG"); got != "/elsewhere/condor_config" {
		t.Errorf("a set CONDOR_CONFIG was replaced: %q", got)
	}

	if err := os.Unsetenv("CONDOR_CONFIG"); err != nil {
		t.Fatal(err)
	}
	useCEConfig()
	if v, set := os.LookupEnv("CONDOR_CONFIG"); set {
		t.Errorf("CONDOR_CONFIG set to %q although %s does not exist", v, ceConfig)
	}

	if err := os.WriteFile(ceConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	useCEConfig()
	if got := os.Getenv("CONDOR_CONFIG"); got != ceConfig {
		t.Errorf("CONDOR_CONFIG = %q, want %q", got, ceConfig)
	}
}

// HTCondor-CE's default method list is FS alone; REG_CALLBACK is served with
// SSL anyway, so a loadable server certificate is what makes callback mode
// available. The candidate list is walked as HTCondor walks it.
func TestSSLServerAvailable(t *testing.T) {
	ca := testpki.NewCA(t)
	cert, key := ca.ServerCert(t, "ce.example.org")
	sc := &security.SecurityConfig{AuthMethods: []security.AuthMethod{security.AuthFS}}
	cedarx.SSLServerCredential(knobs.Map{
		"AUTH_SSL_SERVER_CERTFILE": "/nonexistent/localhost.crt," + cert,
		"AUTH_SSL_SERVER_KEYFILE":  "/nonexistent/localhost.key," + key,
	}, sc)
	if ok, why := sslServerAvailable(sc); !ok {
		t.Fatalf("FS-only method list, loadable certificate: unavailable (%s)", why)
	}
	sc.CertFile, sc.KeyFile = "/nonexistent/localhost.crt", "/nonexistent/localhost.key"
	if ok, _ := sslServerAvailable(sc); ok {
		t.Fatal("no readable certificate: available")
	}
}

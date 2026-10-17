package demo

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Users are the identities the demo identity provider offers, and what the
// registrar's configuration lets each do.
var Users = []struct {
	Sub, Note string
}{
	{"alice", "may approve ce2.localhost"},
	{"bob", "may approve ce1.localhost"},
	{"admin", "registrar administrator: approves any name, sees and revokes every registration"},
	{"mallory", "not authorized for any name"},
}

// mapfile lets alice approve ce2 and bob ce1. Literal names also make them
// known for callback registration.
const mapfile = `# OIDC <subject> <CE names>
OIDC alice   ce2.localhost
OIDC bob     ce1.localhost
`

// commonConfig is the configuration every demo daemon and tool shares.
func (d *Demo) commonConfig(b *strings.Builder, dir, host string) {
	w := func(k, v string) { fmt.Fprintf(b, "%-40s = %s\n", k, v) }
	b.WriteString("# Written by htc-registrationd-demo at every start; edits are lost.\n\n")
	w("LOCAL_DIR", dir)
	w("LOG", "$(LOCAL_DIR)/log")
	w("SPOOL", "$(LOCAL_DIR)/spool")
	w("LOCK", "$(LOCAL_DIR)/lock")
	w("RUN", "$(LOCAL_DIR)/run")
	w("FULL_HOSTNAME", host)
	w("UID_DOMAIN", IdentityDomain)
	w("TRUST_DOMAIN", TrustDomain)
	w("ENABLE_IPV6", "false")
	w("NETWORK_INTERFACE", "127.0.0.1")
	w("USE_SHARED_PORT", "false")
	b.WriteString("\n# Local tools authenticate by file system; daemons prove their names by SSL.\n")
	w("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS, SSL, IDTOKENS")
	w("AUTH_SSL_CLIENT_CAFILE", d.pki.caFile)
	w("AUTH_SSL_SERVER_CAFILE", d.pki.caFile)
	w("AUTH_SSL_CLIENT_USE_DEFAULT_CAS", "false")
	w("AUTH_SSL_SERVER_USE_DEFAULT_CAS", "false")
	b.WriteString("# A daemon not started by a master as root reads SEC_TOKEN_DIRECTORY, not the system one.\n")
	w("SEC_TOKEN_SYSTEM_DIRECTORY", "$(LOCAL_DIR)/tokens.d")
	w("SEC_TOKEN_DIRECTORY", "$(LOCAL_DIR)/tokens.d")
	w("ALLOW_READ", "*")
	w("ALLOW_WRITE", d.user+"@*")
	w("ALLOW_DAEMON", d.user+"@*")
	w("ALLOW_ADMINISTRATOR", d.user+"@*")
	b.WriteString("\n")
	w("HTC_REGISTRATIOND_LOG", "$(LOG)/"+daemonLogName)
	w("HTC_REGISTRATIOND_DEBUG", "general:info")
	w("HTC_REGISTRATIOND_ADDRESS_FILE", "$(LOG)/.htc_registrationd_address")
	w("VALID_SPOOL_FILES", "htc-registrationd")
}

func mkdirs(dir string, subdirs ...string) error {
	for _, s := range subdirs {
		if err := os.MkdirAll(filepath.Join(dir, s), 0o700); err != nil {
			return err
		}
	}
	return nil
}

// RegistrarConfig is the registrar's CONDOR_CONFIG.
func (d *Demo) RegistrarConfig() string { return filepath.Join(d.root, "registrar", "condor_config") }

// RegistrarLog is the registrar's log file.
func (d *Demo) RegistrarLog() string { return filepath.Join(d.root, "registrar", "log", daemonLogName) }

// KeyDir is the registrar's SEC_PASSWORD_DIRECTORY.
func (d *Demo) KeyDir() string { return filepath.Join(d.root, "registrar", "passwords.d") }

// WebURL is the registrar web UI's public URL.
func (d *Demo) WebURL() string { return "http://localhost:" + strconv.Itoa(d.ports.Web) }

// IssuerURL is the identity provider's issuer.
func (d *Demo) IssuerURL() string { return "http://127.0.0.1:" + strconv.Itoa(d.ports.IDP) }

// RegistrarAddress is the registrar's sinful.
func (d *Demo) RegistrarAddress() string {
	return "<127.0.0.1:" + strconv.Itoa(d.ports.Registrar) + ">"
}

func (d *Demo) writeRegistrarConfig() error {
	dir := filepath.Join(d.root, "registrar")
	if err := mkdirs(dir, "log", "spool", "lock", "run", "passwords.d", "tokens.d"); err != nil {
		return err
	}
	cert, key, err := d.pki.serverCert(RegistrarName, []string{RegistrarName, "localhost"}, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "mapfile"), []byte(mapfile), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "oidc-client-secret"), []byte(d.clientSecret+"\n"), 0o600); err != nil {
		return err
	}
	var b strings.Builder
	d.commonConfig(&b, dir, RegistrarName)
	w := func(k, v string) { fmt.Fprintf(&b, "%-40s = %s\n", k, v) }
	w("AUTH_SSL_SERVER_CERTFILE", cert)
	w("AUTH_SSL_SERVER_KEYFILE", key)
	b.WriteString("\n# Token issuance\n")
	w("HTC_REGISTRATIOND_MODE", "registrar")
	w("SEC_PASSWORD_DIRECTORY", d.KeyDir())
	w("HTC_REGISTRATIOND_SIGNING_KEY", SigningKey)
	w("HTC_REGISTRATIOND_TOKEN_LIFETIME", d.opts.TokenLifetime.String())
	w("HTC_REGISTRATIOND_POLL_INTERVAL", "2")
	w("HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS", "127.0.0.0/8, ::1/128")
	b.WriteString("\n# Web UI and login\n")
	w("HTC_REGISTRATIOND_HTTP_ADDR", "127.0.0.1:"+strconv.Itoa(d.ports.Web))
	w("HTC_REGISTRATIOND_PUBLIC_URL", d.WebURL())
	w("HTC_REGISTRATIOND_OIDC_ISSUER", d.IssuerURL())
	w("HTC_REGISTRATIOND_OIDC_CLIENT_ID", ClientID)
	w("HTC_REGISTRATIOND_OIDC_CLIENT_SECRET_FILE", "$(LOCAL_DIR)/oidc-client-secret")
	w("HTC_REGISTRATIOND_ADMINS", "admin")
	w("HTC_REGISTRATIOND_AUTHZ", "mapfile")
	w("HTC_REGISTRATIOND_AUTHZ_MAPFILE", "$(LOCAL_DIR)/mapfile")
	return os.WriteFile(d.RegistrarConfig(), []byte(b.String()), 0o600)
}

func (d *Demo) writeCEConfig(ce *CE) error {
	if err := mkdirs(ce.dir, "log", "spool", "lock", "run", "tokens.d"); err != nil {
		return err
	}
	cert, key, err := d.pki.serverCert(ce.Name, []string{ce.Name}, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ce.dir, "log", ".master_address"),
		[]byte("<127.0.0.1:"+strconv.Itoa(ce.master)+">\n"), 0o600); err != nil {
		return err
	}
	var b strings.Builder
	d.commonConfig(&b, ce.dir, ce.Name)
	w := func(k, v string) { fmt.Fprintf(&b, "%-40s = %s\n", k, v) }
	w("AUTH_SSL_SERVER_CERTFILE", cert)
	w("AUTH_SSL_SERVER_KEYFILE", key)
	w("MASTER_ADDRESS_FILE", "$(LOG)/.master_address")
	b.WriteString("\n# Registration\n")
	w("HTC_REGISTRATIOND_MODE", "ce")
	w("HTC_REGISTRATIOND_NAME", ce.Name)
	w("HTC_REGISTRATIOND_METHOD", ce.Method)
	w("HTC_REGISTRATIOND_REGISTRAR", d.RegistrarAddress())
	w("HTC_REGISTRATIOND_REGISTRAR_NAME", RegistrarName)
	w("HTC_REGISTRATIOND_CALLBACK_ADDRESS", ce.Address())
	if d.collector != nil {
		w("CONDOR_VIEW_HOST", d.collector.address())
		if err := d.writeAdvertiseConfig(ce); err != nil {
			return err
		}
	}
	return os.WriteFile(ce.Config(), []byte(b.String()), 0o600)
}

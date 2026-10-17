package cedarx

import (
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/knobs"
)

// SSLTrust sets sc's SSL trust anchors from HTCondor's standard knobs for one
// side of a connection (side is "CLIENT" or "SERVER"), as Condor_Auth_SSL
// reads them:
//
//   - AUTH_SSL_<side>_CAFILE: CA bundles (cedar loads the last readable one);
//   - AUTH_SSL_<side>_CADIR: a directory of CA certificates;
//   - AUTH_SSL_<side>_USE_DEFAULT_CAS: whether the system trust store is
//     trusted as well (default true).
//
// It sets them whatever sc's method list says: every connection this daemon
// dials, and every command it hardens, is SSL-only even when the pool's
// method list leaves SSL out, which is exactly when golang-htcondor leaves
// CAFile empty. golang-htcondor's GetSecurityConfig / GetServerSecurityConfig
// do not read the CADIR and USE_DEFAULT_CAS knobs yet; once they do, and fill
// the CA file regardless of the method list, this helper can be deleted.
func SSLTrust(cfg knobs.Getter, side string, sc *security.SecurityConfig) {
	useDefault := knobs.Bool(cfg, "AUTH_SSL_"+side+"_USE_DEFAULT_CAS", true)
	sc.CAFile = knobs.String(cfg, "AUTH_SSL_"+side+"_CAFILE", "")
	sc.CADir = knobs.String(cfg, "AUTH_SSL_"+side+"_CADIR", "")
	sc.UseDefaultCAs = &useDefault
}

// ServerSSLTrust applies SSLTrust's SERVER knobs, read from the current
// configuration (cfg) at every handshake, to every per-command config srv
// derives, the base one included, so a reconfig takes effect for the next
// connection. Call it after the per-command policy is installed (and after
// HardenCommands).
func ServerSSLTrust(cfg func() knobs.Getter, srv *cedarserver.Server) {
	SSLTrust(cfg(), "SERVER", srv.SecurityConfig)
	prev := srv.SecurityConfigForCommand
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		var sc *security.SecurityConfig
		if prev != nil {
			sc = prev(cmd)
		}
		if sc == nil {
			sc = srv.SecurityConfig
		}
		c := *sc
		SSLTrust(cfg(), "SERVER", &c)
		return &c
	}
}

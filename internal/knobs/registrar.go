package knobs

import (
	"net"
	"strings"

	"github.com/bbockelm/cedar/addresses"
)

// RegistrarSock is the shared-port id the registrar is shipped with: its
// example configuration sets HTC_REGISTRATIOND_ARGS = -sock htc_registrationd,
// and condor_master names the shared-port endpoint it creates for a
// DaemonCore daemon after the -sock argument in <NAME>_ARGS.
const RegistrarSock = "htc_registrationd"

// DefaultRegistrar returns the registrar address a CE uses when
// HTC_REGISTRATIOND_REGISTRAR is unset: the host:port of the first
// CONDOR_VIEW_HOST entry, with sock=htc_registrationd. The registrar runs
// under the CE-Collector's master behind the same shared port as the
// collector, so the collector's host:port reaches it. An entry without a port
// takes COLLECTOR_PORT (default 9618), as HTCondor does for a collector named
// without one. It returns "" when CONDOR_VIEW_HOST is unset or its first entry
// has no host.
func DefaultRegistrar(cfg Getter) string {
	hosts := List(cfg, "CONDOR_VIEW_HOST", nil)
	if len(hosts) == 0 {
		return ""
	}
	info, err := addresses.ParseSinful(hosts[0])
	if err != nil {
		return ""
	}
	host, port := info.Host, info.Port
	if host == "" {
		host, port = info.PrimaryAddr, ""
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		return ""
	}
	if port == "" {
		port = String(cfg, "COLLECTOR_PORT", "9618")
	}
	return "<" + net.JoinHostPort(host, port) + "?sock=" + RegistrarSock + ">"
}

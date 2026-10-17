package knobs

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// CanonLookup returns a host's canonical name, as getaddrinfo's AI_CANONNAME
// does. nil means the system resolver.
type CanonLookup func(host string) (string, error)

func systemCanon(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

// CEName returns the name a CE registers, which must equal its Scheduler ad's
// Name (the collector requires Name == splitUserName(AuthenticatedIdentity)[0]):
// HTC_REGISTRATIOND_NAME when set; otherwise the name the schedd advertises,
// which is SCHEDD_NAME as BuildValidDaemonName turns it into a daemon name,
// or the local host's full name. The result is lower case: the registrar
// compares names without regard to case, as ClassAd == does.
//
// A name containing '@' cannot match splitUserName's first part, so it is an
// error.
func CEName(cfg Getter, lookup CanonLookup) (string, error) {
	name := String(cfg, "HTC_REGISTRATIOND_NAME", "")
	if name == "" {
		local := String(cfg, "FULL_HOSTNAME", "")
		if sn := String(cfg, "SCHEDD_NAME", ""); sn != "" {
			name = BuildValidDaemonName(cfg, sn, local, lookup)
		} else {
			name = local
		}
	}
	name = strings.ToLower(name)
	if name == "" {
		return "", fmt.Errorf("no name to register (set HTC_REGISTRATIOND_NAME)")
	}
	if strings.Contains(name, "@") {
		return "", fmt.Errorf("the schedd's name is %q, which contains '@', so no token subject can match it; "+
			"set SCHEDD_NAME to this host's name, or HTC_REGISTRATIOND_NAME to the name the schedd advertises", name)
	}
	return name, nil
}

// BuildValidDaemonName is HTCondor's build_valid_daemon_name
// (get_daemon_name.cpp), which the schedd applies to SCHEDD_NAME: a name with
// an '@' is used as is; a name that is (resolves to) the local host's full
// name becomes that full name; any other name becomes name@<local full name>.
func BuildValidDaemonName(cfg Getter, name, localFQDN string, lookup CanonLookup) string {
	if name == "" {
		return localFQDN
	}
	if strings.Contains(name, "@") {
		return name
	}
	if fqdn := FQDNFromHostname(cfg, name, lookup); fqdn != "" && strings.EqualFold(fqdn, localFQDN) {
		return localFQDN
	}
	return name + "@" + localFQDN
}

// FQDNFromHostname is HTCondor's get_fqdn_from_hostname: a name with a dot is
// already fully qualified; otherwise its canonical name from DNS when that
// has a dot (unless NO_DNS), else name.DEFAULT_DOMAIN_NAME, else "".
func FQDNFromHostname(cfg Getter, host string, lookup CanonLookup) string {
	if strings.Contains(host, ".") {
		return host
	}
	if !Bool(cfg, "NO_DNS", false) {
		if lookup == nil {
			lookup = systemCanon
		}
		if canon, err := lookup(host); err == nil {
			if canon = strings.TrimSuffix(canon, "."); strings.Contains(canon, ".") {
				return canon
			}
		}
	}
	if dom := String(cfg, "DEFAULT_DOMAIN_NAME", ""); dom != "" {
		if strings.HasSuffix(host, ".") {
			return host + dom
		}
		return host + "." + dom
	}
	return ""
}

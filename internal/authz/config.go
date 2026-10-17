package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/bbockelm/htc-registrationd/internal/knobs"
)

// Admins reads HTC_REGISTRATIOND_ADMINS, an HTCondor list (comma or white
// space separated) of users as configuration names them: the bare subject
// when HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM is sub, else the claim value.
func Admins(cfg knobs.Getter) []string {
	return knobs.List(cfg, "HTC_REGISTRATIOND_ADMINS", nil)
}

// subjectIssuer is the issuer of "<issuer>,<sub>" principals, or "" when
// the principal claim is not sub and principals are bare claim values.
func subjectIssuer(cfg knobs.Getter) string {
	if knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM", "sub") != "sub" {
		return ""
	}
	return knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_ISSUER", "")
}

// FromConfig builds the policy named by HTC_REGISTRATIOND_AUTHZ (a list of
// mapfile and topology, in order) and HTC_REGISTRATIOND_ADMINS. Start runs
// its background work.
func FromConfig(cfg knobs.Getter, log *slog.Logger) (*Policy, error) {
	if log == nil {
		log = slog.Default()
	}
	var backends []Backend
	var mf *Mapfile
	var topo *Topology
	for _, kind := range knobs.List(cfg, "HTC_REGISTRATIOND_AUTHZ", nil) {
		switch strings.ToLower(kind) {
		case "mapfile":
			if mf != nil {
				continue
			}
			path := knobs.String(cfg, "HTC_REGISTRATIOND_AUTHZ_MAPFILE", "")
			if path == "" {
				return nil, fmt.Errorf("HTC_REGISTRATIOND_AUTHZ includes mapfile but HTC_REGISTRATIOND_AUTHZ_MAPFILE is not set")
			}
			var err error
			if mf, err = NewMapfile(path, log); err != nil {
				return nil, err
			}
			backends = append(backends, mf)
		case "topology":
			if topo != nil {
				continue
			}
			tc, err := topologyConfig(cfg, log)
			if err != nil {
				return nil, err
			}
			topo = NewTopology(tc)
			backends = append(backends, topo)
		default:
			return nil, fmt.Errorf("HTC_REGISTRATIOND_AUTHZ: unknown backend %q (want mapfile or topology)", kind)
		}
	}
	p := NewPolicy(backends, Admins(cfg))
	p.SetSubjectIssuer(subjectIssuer(cfg))
	p.mapfile, p.topology = mf, topo
	return p, nil
}

func topologyConfig(cfg knobs.Getter, log *slog.Logger) (TopologyConfig, error) {
	tc := TopologyConfig{Logger: log}
	tc.URL = knobs.String(cfg, "HTC_REGISTRATIOND_TOPOLOGY_URL", DefaultTopologyURL)
	u, err := url.Parse(tc.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return tc, fmt.Errorf("HTC_REGISTRATIOND_TOPOLOGY_URL must be an https:// URL, not %q", tc.URL)
	}
	if tc.Refresh, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_TOPOLOGY_REFRESH", DefaultTopologyRefresh); err != nil {
		return tc, err
	}
	if tc.MaxStale, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_TOPOLOGY_MAX_STALE", DefaultTopologyMaxStale); err != nil {
		return tc, err
	}
	if tc.IncludeITB, err = knobs.Bool(cfg, "HTC_REGISTRATIOND_TOPOLOGY_INCLUDE_ITB", false); err != nil {
		return tc, err
	}
	return tc, nil
}

// Start runs the backends' background work (the Topology refresh) until ctx
// ends.
func (p *Policy) Start(ctx context.Context) {
	if p.topology != nil {
		go p.topology.Run(ctx)
	}
}

// Reconfig re-reads HTC_REGISTRATIOND_ADMINS and the mapfile (whose path
// may have changed). Changing HTC_REGISTRATIOND_AUTHZ or the Topology knobs
// takes a restart.
func (p *Policy) Reconfig(cfg knobs.Getter) {
	p.SetAdmins(Admins(cfg))
	if p.mapfile != nil {
		_ = p.mapfile.Reload(knobs.String(cfg, "HTC_REGISTRATIOND_AUTHZ_MAPFILE", ""))
	}
}

package authz

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Topology defaults.
const (
	DefaultTopologyURL      = "https://topology.opensciencegrid.org"
	DefaultTopologyRefresh  = 15 * time.Minute
	DefaultTopologyMaxStale = 24 * time.Hour
	// DefaultTopologyMaxBytes caps the rgsummary document. The full OSG
	// document is a few MB.
	DefaultTopologyMaxBytes = 64 << 20
)

// topologyQuery asks Topology for active resources that run a CE service
// (ID 1), in production (grid type 1) and, with includeITB, in the ITB
// (grid type 2). The response is filtered for active CEs locally too, in
// case a server ignores the parameters.
func topologyQuery(includeITB bool) string {
	q := "/rgsummary/xml?gridtype=on&gridtype_1=on"
	if includeITB {
		q += "&gridtype_2=on"
	}
	return q + "&service=on&service_1=on&active=on&active_value=1"
}

// Topology authorizes from OSG Topology. A principal (the OIDC osgid claim,
// a CILogon user id) may approve a name when the name is the FQDN of an
// active CE resource and the principal is the CILogonID of any contact in
// one of that resource's Administrative Contact lists, whatever the rank. A
// name is Known when it is the FQDN of an active CE resource.
//
// The document is fetched every Refresh. When a fetch fails, the last good
// copy is used until it is older than MaxStale; after that every decision
// fails until a fetch succeeds. A document with no active CE, or with
// fewer than half the active CEs of the copy in use, counts as a failed
// fetch: a truncated or emptied document must not revoke everyone's
// authorization at once.
type Topology struct {
	TopologyConfig

	mu      sync.RWMutex
	data    map[string]*topologyCE
	fetched time.Time
	lastErr error
}

// TopologyConfig configures a Topology backend.
type TopologyConfig struct {
	// URL is the Topology base URL (default DefaultTopologyURL).
	URL      string
	Refresh  time.Duration
	MaxStale time.Duration
	MaxBytes int64
	// IncludeITB adds ITB (test) resources to the production ones.
	IncludeITB bool
	// Client fetches the document; the default has a 60 s timeout and the
	// system's trusted roots.
	Client *http.Client
	Logger *slog.Logger
	Now    func() time.Time
}

// NewTopology returns a Topology backend with no data; Run or Fetch loads
// it.
func NewTopology(cfg TopologyConfig) *Topology {
	cfg.setDefaults()
	return &Topology{TopologyConfig: cfg}
}

type topologyCE struct {
	// resource is the first resource name seen with this FQDN.
	resource string
	// admins maps a CILogonID to how it is listed.
	admins map[string]topologyAdmin
}

type topologyAdmin struct {
	resource string
	rank     string
}

func (t *TopologyConfig) setDefaults() {
	if t.URL == "" {
		t.URL = DefaultTopologyURL
	}
	if t.Refresh <= 0 {
		t.Refresh = DefaultTopologyRefresh
	}
	if t.MaxStale <= 0 {
		t.MaxStale = DefaultTopologyMaxStale
	}
	if t.MaxBytes <= 0 {
		t.MaxBytes = DefaultTopologyMaxBytes
	}
	if t.Client == nil {
		t.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if t.Logger == nil {
		t.Logger = slog.Default()
	}
	if t.Now == nil {
		t.Now = time.Now
	}
}

// Name implements Backend.
func (*Topology) Name() string { return "topology" }

// Run fetches the document now and then every Refresh until ctx ends. A
// failed fetch is retried sooner, from one minute doubling up to Refresh.
func (t *Topology) Run(ctx context.Context) {
	retry := time.Minute
	for {
		wait := t.Refresh
		if err := t.Fetch(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			t.Logger.Error("authz: OSG Topology fetch failed", "url", t.URL, "err", err, "retry_in", retry.String())
			wait = min(retry, t.Refresh)
			retry *= 2
		} else {
			retry = time.Minute
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Fetch downloads and parses the document once, replacing the data in use
// only on success.
func (t *Topology) Fetch(ctx context.Context) error {
	err := t.fetch(ctx)
	t.mu.Lock()
	t.lastErr = err
	t.mu.Unlock()
	return err
}

func (t *Topology) fetch(ctx context.Context) error {
	u := strings.TrimSuffix(t.URL, "/") + topologyQuery(t.IncludeITB)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/xml, text/xml")
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, t.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("reading %s: %w", u, err)
	}
	if int64(len(body)) > t.MaxBytes {
		return fmt.Errorf("%s is larger than %d bytes", u, t.MaxBytes)
	}
	data, err := parseTopology(body)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(data) == 0 {
		return fmt.Errorf("%s lists no active CE; keeping the copy in use", u)
	}
	if prev := len(t.data); len(data)*2 < prev {
		return fmt.Errorf("%s lists %d active CEs, fewer than half of the %d in the copy in use; keeping that copy "+
			"(a restart accepts the new document)", u, len(data), prev)
	}
	t.data, t.fetched = data, t.Now()
	t.Logger.Info("authz: OSG Topology loaded", "ces", len(data))
	return nil
}

// rgSummary is the subset of /rgsummary/xml this backend reads.
type rgSummary struct {
	XMLName xml.Name `xml:"ResourceSummary"`
	Groups  []struct {
		Resources []topologyResource `xml:"Resources>Resource"`
	} `xml:"ResourceGroup"`
}

type topologyResource struct {
	Name     string `xml:"Name"`
	Active   string `xml:"Active"`
	FQDN     string `xml:"FQDN"`
	Services []struct {
		ID   string `xml:"ID"`
		Name string `xml:"Name"`
	} `xml:"Services>Service"`
	ContactLists []struct {
		Type     string `xml:"ContactType"`
		Contacts []struct {
			Name      string `xml:"Name"`
			CILogonID string `xml:"CILogonID"`
			Rank      string `xml:"ContactRank"`
		} `xml:"Contacts>Contact"`
	} `xml:"ContactLists>ContactList"`
}

func (r *topologyResource) isActiveCE() bool {
	if !strings.EqualFold(strings.TrimSpace(r.Active), "true") {
		return false
	}
	for _, s := range r.Services {
		if strings.TrimSpace(s.ID) == "1" || strings.TrimSpace(s.Name) == "CE" {
			return true
		}
	}
	return false
}

// parseTopology reads an rgsummary document into a map from lowercased CE
// FQDN to its administrative contacts. Inactive resources, resources
// without a CE service and resources without an FQDN are skipped.
func parseTopology(doc []byte) (map[string]*topologyCE, error) {
	var s rgSummary
	if err := xml.Unmarshal(doc, &s); err != nil {
		return nil, fmt.Errorf("parsing the OSG Topology rgsummary: %w", err)
	}
	out := map[string]*topologyCE{}
	for _, g := range s.Groups {
		for i := range g.Resources {
			r := &g.Resources[i]
			fqdn := strings.ToLower(strings.TrimSpace(r.FQDN))
			if fqdn == "" || !r.isActiveCE() {
				continue
			}
			name := strings.TrimSpace(r.Name)
			ce := out[fqdn]
			if ce == nil {
				ce = &topologyCE{resource: name, admins: map[string]topologyAdmin{}}
				out[fqdn] = ce
			}
			for _, cl := range r.ContactLists {
				if strings.TrimSpace(cl.Type) != "Administrative Contact" {
					continue
				}
				for _, c := range cl.Contacts {
					id := strings.TrimSpace(c.CILogonID)
					if id == "" {
						continue
					}
					if _, dup := ce.admins[id]; !dup {
						ce.admins[id] = topologyAdmin{resource: name, rank: strings.TrimSpace(c.Rank)}
					}
				}
			}
		}
	}
	return out, nil
}

// current returns the data in use, or an error when there is none or it is
// older than MaxStale.
func (t *Topology) current() (map[string]*topologyCE, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.data == nil {
		if t.lastErr != nil {
			return nil, fmt.Errorf("OSG Topology data is not available: %w", t.lastErr)
		}
		return nil, errors.New("OSG Topology data is not available yet")
	}
	if age := t.Now().Sub(t.fetched); age > t.MaxStale {
		stale := fmt.Errorf("OSG Topology data is %s old, past HTC_REGISTRATIOND_TOPOLOGY_MAX_STALE (%s)",
			age.Round(time.Minute), t.MaxStale)
		if t.lastErr != nil {
			return nil, fmt.Errorf("%w; last fetch error: %w", stale, t.lastErr)
		}
		return nil, stale
	}
	return t.data, nil
}

// Decide implements Backend.
func (t *Topology) Decide(_ context.Context, principal, name string) (Decision, error) {
	data, err := t.current()
	if err != nil {
		return Decision{}, err
	}
	ce := data[strings.ToLower(name)]
	if ce == nil {
		return Decision{Reason: fmt.Sprintf("%s is not the FQDN of an active CE in OSG Topology", name)}, nil
	}
	if a, ok := ce.admins[principal]; ok && principal != "" {
		rank := ""
		if a.rank != "" {
			rank = " (" + a.rank + ")"
		}
		return Decision{Allowed: true,
			Reason: fmt.Sprintf("Administrative Contact%s for resource %s in OSG Topology", rank, a.resource)}, nil
	}
	return Decision{Reason: fmt.Sprintf("Not an Administrative Contact for resource %s in OSG Topology", ce.resource)}, nil
}

// Known implements Backend.
func (t *Topology) Known(_ context.Context, name string) (bool, error) {
	data, err := t.current()
	if err != nil {
		return false, err
	}
	return data[strings.ToLower(name)] != nil, nil
}

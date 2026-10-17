package demo

import (
	"encoding/json"
	"net/url"

	"github.com/bbockelm/htc-registrationd/internal/atomicfile"
)

// ReadyFile is where in its state directory a running demo describes
// itself, unless told otherwise.
const ReadyFile = "ready.json"

// Ready describes a running demo, for programs that drive it.
type Ready struct {
	// Dir is the demo's state directory.
	Dir string `json:"dir"`
	// WebURL is the registrar web UI; IssuerURL the identity provider.
	WebURL    string `json:"web_url"`
	IssuerURL string `json:"issuer_url"`
	// RegistrarConfig is the registrar's CONDOR_CONFIG.
	RegistrarConfig string    `json:"registrar_config"`
	CEs             []ReadyCE `json:"ces"`
	// Collector reports whether the HTCondor collector runs; CollectorNote
	// says why not.
	Collector     bool   `json:"collector"`
	CollectorNote string `json:"collector_note,omitempty"`
}

// ReadyCE is one CE of a running demo.
type ReadyCE struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Method    string `json:"method"`
	Config    string `json:"config"`
	TokenFile string `json:"token_file"`
	// HasToken reports whether it held an unexpired token at startup.
	HasToken bool `json:"has_token"`
	// ApprovalURL and Code are its pending approval request, if any.
	ApprovalURL string `json:"approval_url,omitempty"`
	Code        string `json:"code,omitempty"`
}

// Ready describes the running demo.
func (d *Demo) Ready() Ready {
	r := Ready{Dir: d.root, WebURL: d.WebURL(), IssuerURL: d.IssuerURL(), RegistrarConfig: d.RegistrarConfig()}
	r.Collector, r.CollectorNote = d.HasCollector()
	if r.Collector {
		r.CollectorNote = ""
	}
	for _, c := range d.ces {
		rc := ReadyCE{Key: c.Key, Name: c.Name, Method: c.Method, Config: c.Config(), TokenFile: c.TokenFile(),
			HasToken: c.HasToken(), ApprovalURL: c.ApprovalURL()}
		if u, err := url.Parse(rc.ApprovalURL); err == nil && rc.ApprovalURL != "" {
			rc.Code = u.Query().Get("code")
		}
		r.CEs = append(r.CEs, rc)
	}
	return r
}

// WriteReady writes Ready to path as JSON, replacing it atomically.
func (d *Demo) WriteReady(path string) error {
	b, err := json.MarshalIndent(d.Ready(), "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, append(b, '\n'), 0o600)
}

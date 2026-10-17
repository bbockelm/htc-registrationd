package authz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/knobs"
)

const (
	admin111 = "OSG1000111"
	admin222 = "OSG1000222"
	sec333   = "OSG1000333"
	admin555 = "OSG1000555"
	admin777 = "OSG1000777"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// topologyServer serves the fixture over TLS, or fails while fail is set.
// Storing a []byte in doc replaces the document it serves.
func topologyServer(t *testing.T) (srv *httptest.Server, fail *atomic.Bool, query, doc *atomic.Value) {
	t.Helper()
	fixture, err := os.ReadFile("testdata/rgsummary.xml")
	if err != nil {
		t.Fatal(err)
	}
	fail, query, doc = &atomic.Bool{}, &atomic.Value{}, &atomic.Value{}
	doc.Store(fixture)
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query.Store(r.URL.RequestURI())
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(doc.Load().([]byte))
	}))
	t.Cleanup(srv.Close)
	return srv, fail, query, doc
}

func newTestTopology(t *testing.T) (*Topology, *clock, *atomic.Bool) {
	t.Helper()
	srv, fail, query, _ := topologyServer(t)
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	topo := NewTopology(TopologyConfig{URL: srv.URL + "/", Client: srv.Client(), Now: c.Now, MaxStale: 24 * time.Hour})
	if err := topo.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "/rgsummary/xml?gridtype=on&gridtype_1=on&service=on&service_1=on&active=on&active_value=1"
	if got, _ := query.Load().(string); got != want {
		t.Errorf("fetched %q, want %q", got, want)
	}
	return topo, c, fail
}

func TestTopologyDecide(t *testing.T) {
	topo, _, _ := newTestTopology(t)
	ctx := context.Background()
	cases := []struct {
		desc      string
		principal string
		name      string
		allowed   bool
		reason    string
	}{
		{"primary admin", admin111, "ce1.example.edu", true, "Administrative Contact (Primary) for resource EXAMPLE-CE1 in OSG Topology"},
		{"secondary admin", admin111, "ce2.example.edu", true, "Administrative Contact (Secondary) for resource EXAMPLE-CE2 in OSG Topology"},
		{"tertiary admin", admin111, "ce3.example.edu", true, "Administrative Contact (Tertiary) for resource EXAMPLE-CE3 in OSG Topology"},
		{"other primary on the same CE", admin222, "ce2.example.edu", true, "Administrative Contact (Primary) for resource EXAMPLE-CE2 in OSG Topology"},
		{"security contact is not an admin", sec333, "ce2.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE2 in OSG Topology"},
		{"security contact only", admin111, "ce4.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE4 in OSG Topology"},
		{"inactive resource", admin111, "retired-ce.example.edu", false, "retired-ce.example.edu is not the FQDN of an active CE in OSG Topology"},
		{"non-CE resource", admin111, "squid.example.edu", false, "squid.example.edu is not the FQDN of an active CE in OSG Topology"},
		{"requested name in upper case", admin111, "CE1.EXAMPLE.EDU", true, "Administrative Contact (Primary) for resource EXAMPLE-CE1 in OSG Topology"},
		{"FQDN in mixed case", admin555, "ce5.example.edu", true, "Administrative Contact (Tertiary) for resource EXAMPLE-CE5 in OSG Topology"},
		{"empty principal never matches an empty CILogonID", "", "ce5.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE5 in OSG Topology"},
		{"blank principal never matches a blank CILogonID", "   ", "ce5.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE5 in OSG Topology"},
		{"CE by service name", admin777, "ce.other.org", true, "Administrative Contact (Primary) for resource OTHER-CE in OSG Topology"},
		{"principal is compared exactly", strings.ToLower(admin111), "ce1.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE1 in OSG Topology"},
		{"unknown name", admin111, "nowhere.example.edu", false, "nowhere.example.edu is not the FQDN of an active CE in OSG Topology"},
	}
	for _, tc := range cases {
		d, err := topo.Decide(ctx, tc.principal, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.desc, err)
		}
		if d.Allowed != tc.allowed || d.Reason != tc.reason {
			t.Errorf("%s: got %+v, want allowed=%v reason %q", tc.desc, d, tc.allowed, tc.reason)
		}
	}
}

func TestTopologyKnown(t *testing.T) {
	topo, _, _ := newTestTopology(t)
	for name, want := range map[string]bool{
		"ce1.example.edu":        true,
		"CE4.example.edu":        true, // known even though no admin matches
		"ce5.example.edu":        true,
		"ce.other.org":           true,
		"retired-ce.example.edu": false,
		"squid.example.edu":      false,
		"":                       false,
	} {
		got, err := topo.Known(context.Background(), name)
		if err != nil || got != want {
			t.Errorf("Known(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
}

func TestTopologyStaleRefusal(t *testing.T) {
	topo, c, fail := newTestTopology(t)
	ctx := context.Background()
	fail.Store(true)

	// A failed fetch keeps the last good copy.
	c.Advance(time.Hour)
	if err := topo.Fetch(ctx); err == nil {
		t.Fatal("fetch from a failing server succeeded")
	}
	if d, err := topo.Decide(ctx, admin111, "ce1.example.edu"); err != nil || !d.Allowed {
		t.Fatalf("within MaxStale: %+v, %v", d, err)
	}

	// Past MaxStale every decision fails rather than answering from old data.
	c.Advance(24 * time.Hour)
	if d, err := topo.Decide(ctx, admin111, "ce1.example.edu"); err == nil {
		t.Fatalf("past MaxStale: got %+v, want an error", d)
	} else if !strings.Contains(err.Error(), "MAX_STALE") {
		t.Errorf("error does not name the knob: %v", err)
	}
	if _, err := topo.Known(ctx, "ce1.example.edu"); err == nil {
		t.Error("Known answered from stale data")
	}

	// A successful fetch restores service.
	fail.Store(false)
	if err := topo.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if d, err := topo.Decide(ctx, admin111, "ce1.example.edu"); err != nil || !d.Allowed {
		t.Fatalf("after a fresh fetch: %+v, %v", d, err)
	}
}

func TestTopologyNoDataYet(t *testing.T) {
	srv, fail, _, _ := topologyServer(t)
	fail.Store(true)
	topo := NewTopology(TopologyConfig{URL: srv.URL, Client: srv.Client()})
	if _, err := topo.Decide(context.Background(), admin111, "ce1.example.edu"); err == nil {
		t.Fatal("decided with no data")
	}
	_ = topo.Fetch(context.Background())
	if _, err := topo.Decide(context.Background(), admin111, "ce1.example.edu"); err == nil ||
		!strings.Contains(err.Error(), "503") {
		t.Fatalf("want the fetch error, got %v", err)
	}
}

func TestTopologySizeCap(t *testing.T) {
	srv, _, _, _ := topologyServer(t)
	topo := NewTopology(TopologyConfig{URL: srv.URL, Client: srv.Client(), MaxBytes: 100})
	if err := topo.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized document: %v", err)
	}
}

func TestTopologyRejectsBadXML(t *testing.T) {
	if _, err := parseTopology([]byte("<html>not topology</html>")); err == nil {
		t.Fatal("parsed a non-rgsummary document")
	}
}

// ceDoc is an rgsummary listing n active CEs, ce1.example.edu onward, each
// administered by admin111.
func ceDoc(n int) []byte {
	var b strings.Builder
	b.WriteString("<ResourceSummary><ResourceGroup><Resources>")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, `<Resource><Name>CE%d</Name><Active>True</Active><FQDN>ce%d.example.edu</FQDN>`+
			`<Services><Service><ID>1</ID><Name>CE</Name></Service></Services>`+
			`<ContactLists><ContactList><ContactType>Administrative Contact</ContactType><Contacts>`+
			`<Contact><Name>A</Name><CILogonID>%s</CILogonID><ContactRank>Primary</ContactRank></Contact>`+
			`</Contacts></ContactList></ContactLists></Resource>`, i, i, admin111)
	}
	b.WriteString("</Resources></ResourceGroup></ResourceSummary>")
	return []byte(b.String())
}

func TestTopologyRefusesEmptiedDocument(t *testing.T) {
	srv, _, _, doc := topologyServer(t)
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	topo := NewTopology(TopologyConfig{URL: srv.URL, Client: srv.Client(), Now: c.Now, MaxStale: 24 * time.Hour})
	ctx := context.Background()
	if err := topo.Fetch(ctx); err != nil { // the fixture: 6 active CEs
		t.Fatal(err)
	}
	stillServing := func(desc string) {
		t.Helper()
		if d, err := topo.Decide(ctx, admin111, "ce4.example.edu"); err != nil || d.Allowed ||
			!strings.Contains(d.Reason, "EXAMPLE-CE4") {
			t.Errorf("%s: the last good copy is not in use: %+v, %v", desc, d, err)
		}
	}
	for desc, bad := range map[string][]byte{
		"well-formed but empty":    []byte("<ResourceSummary></ResourceSummary>"),
		"no active CE":             []byte("<ResourceSummary><ResourceGroup><Resources></Resources></ResourceGroup></ResourceSummary>"),
		"fewer than half the CEs":  ceDoc(2),
		"a single CE of six known": ceDoc(1),
	} {
		doc.Store(bad)
		c.Advance(time.Hour)
		if err := topo.Fetch(ctx); err == nil {
			t.Errorf("%s: accepted", desc)
		}
		stillServing(desc)
	}

	// The kept copy is still subject to MaxStale.
	c.Advance(24 * time.Hour)
	if _, err := topo.Decide(ctx, admin111, "ce1.example.edu"); err == nil {
		t.Error("the kept copy outlived MaxStale")
	}

	// Half the CEs is accepted.
	doc.Store(ceDoc(3))
	if err := topo.Fetch(ctx); err != nil {
		t.Fatalf("half the CEs: %v", err)
	}
	if ok, err := topo.Known(ctx, "ce4.example.edu"); err != nil || ok {
		t.Errorf("the new document is not in use: %v, %v", ok, err)
	}

	// With no copy in use, an empty document is still refused.
	empty := NewTopology(TopologyConfig{URL: srv.URL, Client: srv.Client()})
	doc.Store([]byte("<ResourceSummary></ResourceSummary>"))
	if err := empty.Fetch(ctx); err == nil {
		t.Error("an empty first document was accepted")
	}
	if _, err := empty.Decide(ctx, admin111, "ce1.example.edu"); err == nil {
		t.Error("decided from an empty document")
	}
}

func TestTopologyIncludeITB(t *testing.T) {
	srv, _, query, _ := topologyServer(t)
	topo := NewTopology(TopologyConfig{URL: srv.URL, Client: srv.Client(), IncludeITB: true})
	if err := topo.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "/rgsummary/xml?gridtype=on&gridtype_1=on&gridtype_2=on&service=on&service_1=on&active=on&active_value=1"
	if got, _ := query.Load().(string); got != want {
		t.Errorf("fetched %q, want %q", got, want)
	}
	// An invalid value keeps the default, as HTCondor's param_boolean does.
	for knob, want := range map[string]bool{"": false, "false": false, "true": true, "maybe": false} {
		tc, err := topologyConfig(knobs.Map{"HTC_REGISTRATIOND_TOPOLOGY_INCLUDE_ITB": knob}, nil)
		if err != nil || tc.IncludeITB != want {
			t.Errorf("INCLUDE_ITB = %q: %v, %v", knob, tc.IncludeITB, err)
		}
	}
}

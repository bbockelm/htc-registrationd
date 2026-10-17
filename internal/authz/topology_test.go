package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	admin111 = "http://cilogon.org/serverA/users/111"
	admin222 = "http://cilogon.org/serverA/users/222"
	sec333   = "http://cilogon.org/serverA/users/333"
	admin555 = "http://cilogon.org/serverA/users/555"
	admin777 = "http://cilogon.org/serverE/users/777"
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
func topologyServer(t *testing.T) (*httptest.Server, *atomic.Bool, *atomic.Value) {
	t.Helper()
	doc, err := os.ReadFile("testdata/rgsummary.xml")
	if err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	var query atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query.Store(r.URL.RequestURI())
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, &fail, &query
}

func newTestTopology(t *testing.T) (*Topology, *clock, *atomic.Bool) {
	t.Helper()
	srv, fail, query := topologyServer(t)
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
		{"principal is compared exactly", strings.ToUpper(admin111), "ce1.example.edu", false, "Not an Administrative Contact for resource EXAMPLE-CE1 in OSG Topology"},
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
	srv, fail, _ := topologyServer(t)
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
	srv, _, _ := topologyServer(t)
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

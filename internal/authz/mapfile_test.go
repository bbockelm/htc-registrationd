package authz

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/knobs"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
)

const testMap = `# CE administrators
OIDC alice ce1.example.edu,*.grid.example.org
OIDC bob CE2.Example.EDU
SSL  bob ignored.example.edu
OIDC /^carol-[0-9]+$/ ce3.example.edu,ce4.example.edu
OIDC bob ce-never.example.edu
`

func writeMap(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestMapfile(t *testing.T) (*Mapfile, string, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authz.map")
	writeMap(t, path, testMap)
	m, err := NewMapfile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	m.Now = c.Now
	m.checkedAt = c.Now()
	return m, path, c
}

func TestMapfileDecide(t *testing.T) {
	m, _, _ := newTestMapfile(t)
	ctx := context.Background()
	alice := "alice"
	cases := []struct {
		principal, name string
		allowed         bool
		reason          string
	}{
		{alice, "ce1.example.edu", true, "mapfile line 2"},
		{alice, "CE1.EXAMPLE.EDU", true, "mapfile line 2"},
		{alice, "x.grid.example.org", true, "mapfile line 2"},
		{alice, "X.Grid.Example.ORG", true, "mapfile line 2"},
		{alice, "grid.example.org", false, "Mapfile line 2 does not list grid.example.org"},
		{alice, "ce2.example.edu", false, "Mapfile line 2 does not list ce2.example.edu"},
		{"bob", "ce2.example.edu", true, "mapfile line 3"},
		// The first matching line wins; line 6 never applies.
		{"bob", "ce-never.example.edu", false, "Mapfile line 3 does not list ce-never.example.edu"},
		// Only OIDC lines count.
		{"bob", "ignored.example.edu", false, "Mapfile line 3 does not list ignored.example.edu"},
		{"carol-42", "ce4.example.edu", true, "mapfile line 5"},
		{"carol-x", "ce4.example.edu", false, "No mapfile line matches your identity"},
		{"https://idp.example.org,alice", "ce1.example.edu", false, "No mapfile line matches your identity"},
		{"", "ce1.example.edu", false, "No mapfile line matches your identity"},
	}
	for _, tc := range cases {
		d, err := m.Decide(ctx, tc.principal, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed != tc.allowed || d.Reason != tc.reason {
			t.Errorf("Decide(%q, %q) = %+v, want allowed=%v reason %q", tc.principal, tc.name, d, tc.allowed, tc.reason)
		}
	}
}

func TestMapfileKnownIsLiteralOnly(t *testing.T) {
	m, _, _ := newTestMapfile(t)
	for name, want := range map[string]bool{
		"ce1.example.edu":      true,
		"ce2.example.edu":      true, // written CE2.Example.EDU
		"ce3.example.edu":      true,
		"ce-never.example.edu": true, // a literal on an OIDC line, even one that never wins
		"x.grid.example.org":   false,
		"*.grid.example.org":   false,
		"ignored.example.edu":  false, // not an OIDC line
	} {
		if got, err := m.Known(context.Background(), name); err != nil || got != want {
			t.Errorf("Known(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
}

func TestMapfileReloadOnChange(t *testing.T) {
	m, path, c := newTestMapfile(t)
	ctx := context.Background()
	writeMap(t, path, "OIDC dave ce9.example.edu\n")
	// Make sure the change is visible even on a coarse-mtime filesystem.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	// Within the check interval the old map is still in use.
	if d, _ := m.Decide(ctx, "dave", "ce9.example.edu"); d.Allowed {
		t.Fatal("re-read before the check interval")
	}
	c.Advance(2 * time.Second)
	if d, _ := m.Decide(ctx, "dave", "ce9.example.edu"); !d.Allowed {
		t.Fatalf("changed mapfile not re-read: %+v", d)
	}
	if d, _ := m.Decide(ctx, "bob", "ce2.example.edu"); d.Allowed {
		t.Fatal("old line still in effect")
	}

	// A broken file keeps the last good map.
	writeMap(t, path, "OIDC \"unterminated ce1.example.edu\n")
	later = later.Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * time.Second)
	if d, _ := m.Decide(ctx, "dave", "ce9.example.edu"); !d.Allowed {
		t.Fatalf("last good map dropped after a failed reload: %+v", d)
	}
	if err := m.Reload(""); err == nil {
		t.Fatal("Reload of a broken file succeeded")
	}
	if d, _ := m.Decide(ctx, "dave", "ce9.example.edu"); !d.Allowed {
		t.Fatalf("last good map dropped after a failed Reload: %+v", d)
	}

	// A missing file keeps the last good map too.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * time.Second)
	if d, _ := m.Decide(ctx, "dave", "ce9.example.edu"); !d.Allowed {
		t.Fatalf("last good map dropped when the file vanished: %+v", d)
	}
}

func TestNewMapfileFailsOnBadFile(t *testing.T) {
	if _, err := NewMapfile(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("loaded a missing mapfile")
	}
}

// fakeBackend answers from fixed values.
type fakeBackend struct {
	name  string
	d     Decision
	known bool
	err   error
}

func (f fakeBackend) Name() string { return f.name }
func (f fakeBackend) Decide(context.Context, string, string) (Decision, error) {
	return f.d, f.err
}
func (f fakeBackend) Known(context.Context, string) (bool, error) { return f.known, f.err }

func TestPolicyChain(t *testing.T) {
	ctx := context.Background()
	deny := fakeBackend{name: "a", d: Decision{Reason: "no from a"}}
	allow := fakeBackend{name: "b", d: Decision{Allowed: true, Reason: "yes from b"}, known: true}
	broken := fakeBackend{name: "c", err: errors.New("stale")}

	p := NewPolicy([]Backend{deny, allow}, nil)
	if d, err := p.Decide(ctx, "u", "n"); err != nil || !d.Allowed || d.Reason != "yes from b" {
		t.Errorf("first allow should win: %+v, %v", d, err)
	}
	p = NewPolicy([]Backend{broken, allow}, nil)
	if d, err := p.Decide(ctx, "u", "n"); err != nil || !d.Allowed {
		t.Errorf("an allow should win over another backend's error: %+v, %v", d, err)
	}
	if ok, err := p.Known(ctx, "n"); err != nil || !ok {
		t.Errorf("Known: %v, %v", ok, err)
	}
	p = NewPolicy([]Backend{deny, broken}, nil)
	if _, err := p.Decide(ctx, "u", "n"); err == nil {
		t.Error("an error with no allow must not read as a denial")
	}
	p = NewPolicy([]Backend{deny, deny}, []string{"root-admin"})
	if d, _ := p.Decide(ctx, "u", "n"); d.Allowed || d.Reason != "no from a; no from a" {
		t.Errorf("denial: %+v", d)
	}
	if d, _ := p.Decide(ctx, "root-admin", "n"); !d.Allowed || d.Reason != "Registrar administrator" {
		t.Errorf("admin: %+v", d)
	}
	if d, _ := NewPolicy(nil, nil).Decide(ctx, "u", "n"); d.Allowed {
		t.Error("no backends allowed something")
	}
}

func TestPolicyStillAuthorized(t *testing.T) {
	ctx := context.Background()
	p := NewPolicy([]Backend{fakeBackend{name: "b", d: Decision{Allowed: true}}}, nil)
	if ok, _ := p.StillAuthorized(ctx, registrar.Identity{Kind: "oidc", Principal: "u"}, "n"); !ok {
		t.Error("oidc approver refused")
	}
	if ok, _ := p.StillAuthorized(ctx, registrar.Identity{Kind: "other", Principal: "u"}, "n"); ok {
		t.Error("unknown approver kind allowed")
	}
	// Through the registrar's wrapper, CEDAR approvals stay valid.
	w := registrar.TrustCEDARApprovers{Backend: NewPolicy(nil, nil)}
	if ok, _ := w.StillAuthorized(ctx, registrar.Identity{Kind: "cedar", Principal: "admin@pool"}, "n"); !ok {
		t.Error("CEDAR approval refused")
	}
	if ok, _ := w.StillAuthorized(ctx, registrar.Identity{Kind: "oidc", Principal: "gone"}, "n"); ok {
		t.Error("unauthorized OIDC approval accepted")
	}
}

func TestFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authz.map")
	writeMap(t, path, testMap)
	p, err := FromConfig(knobs.Map{
		"HTC_REGISTRATIOND_AUTHZ":         "mapfile, topology",
		"HTC_REGISTRATIOND_AUTHZ_MAPFILE": path,
		"HTC_REGISTRATIOND_ADMINS":        "root,other  third",
		"HTC_REGISTRATIOND_OIDC_ISSUER":   "https://idp.example.org/",
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Backends(); len(got) != 2 || got[0] != "mapfile" || got[1] != "topology" {
		t.Errorf("backends %v", got)
	}
	// ADMINS is an HTCondor list of subjects; principals are
	// "<issuer>,<sub>" for the configured issuer only.
	for _, who := range []string{"https://idp.example.org,root", "https://idp.example.org/,other", "https://idp.example.org,third"} {
		if !p.IsAdmin(who) {
			t.Errorf("%q is not an administrator", who)
		}
	}
	for _, who := range []string{"root", "https://other.example.org,root", "https://idp.example.org,", "https://idp.example.org"} {
		if p.IsAdmin(who) {
			t.Errorf("%q is an administrator", who)
		}
	}
	// The mapfile answers, by subject, while Topology has no data.
	if d, err := p.Decide(context.Background(), "https://idp.example.org,bob", "ce2.example.edu"); err != nil || !d.Allowed {
		t.Errorf("%+v, %v", d, err)
	}
	if d, err := p.Decide(context.Background(), "https://other.example.org,bob", "ce2.example.edu"); err != nil || d.Allowed {
		t.Errorf("another issuer's subject was allowed: %+v, %v", d, err)
	}
	// With another principal claim, principals are the bare claim value.
	q, err := FromConfig(knobs.Map{
		"HTC_REGISTRATIOND_ADMINS":               "OSG1000001",
		"HTC_REGISTRATIOND_OIDC_ISSUER":          "https://idp.example.org",
		"HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM": "osgid",
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !q.IsAdmin("OSG1000001") || q.IsAdmin("https://idp.example.org,OSG1000001") {
		t.Error("osgid principals are not compared as bare claim values")
	}
	for _, bad := range []knobs.Map{
		{"HTC_REGISTRATIOND_AUTHZ": "ldap"},
		{"HTC_REGISTRATIOND_AUTHZ": "mapfile"},
		{"HTC_REGISTRATIOND_AUTHZ": "topology", "HTC_REGISTRATIOND_TOPOLOGY_URL": "http://topology.example.org"},
		{"HTC_REGISTRATIOND_AUTHZ": "topology", "HTC_REGISTRATIOND_TOPOLOGY_REFRESH": "soon"},
	} {
		if _, err := FromConfig(bad, nil); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

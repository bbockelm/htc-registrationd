package demo

import (
	"bytes"
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

// lockedBuffer collects the demo's output from several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func buildDaemon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "htc-registrationd")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "github.com/bbockelm/htc-registrationd/cmd/htc-registrationd") //nolint:gosec // builds this module's daemon
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building htc-registrationd: %v\n%s", err, out)
	}
	return bin
}

func startDemo(t *testing.T, opts Options) *Demo {
	t.Helper()
	d, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("starting the demo: %v", err)
	}
	return d
}

var (
	hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
	csrfInput   = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
)

// browser is an HTTP client that keeps cookies, as a browser does.
type browser struct {
	t *testing.T
	c *http.Client
}

func newBrowser(t *testing.T) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, c: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// do sends a request, following redirects, and returns the final status,
// URL and body.
func (b *browser) do(method, u string, form url.Values) (int, *url.URL, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	return resp.StatusCode, resp.Request.URL, string(raw)
}

// signIn opens approvalURL, which sends the browser through the registrar's
// login to the identity provider's page, picks who there, and returns the
// approval page the registrar sends the browser back to.
func (b *browser) signIn(approvalURL, who string) string {
	b.t.Helper()
	_, at, page := b.do(http.MethodGet, approvalURL, nil)
	if !strings.HasSuffix(at.Path, "/authorize") {
		b.t.Fatalf("opening %s ended at %s, not the identity provider's login page", approvalURL, at)
	}
	// The first form holds the identity buttons.
	form := url.Values{"user": {who}}
	for _, m := range hiddenInput.FindAllStringSubmatch(strings.SplitN(page, "</form>", 2)[0], -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	login := *at
	login.RawQuery = ""
	status, at, page := b.do(http.MethodPost, login.String(), form)
	if status != http.StatusOK || at.Path != "/approve" {
		b.t.Fatalf("signing in as %s ended at %s (HTTP %d):\n%s", who, at, status, page)
	}
	return page
}

// decide posts a decision on the approval page.
func (b *browser) decide(approvalURL, page, decision string) (int, string) {
	b.t.Helper()
	m := csrfInput.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("no CSRF token on the approval page:\n%s", page)
	}
	u, err := url.Parse(approvalURL)
	if err != nil {
		b.t.Fatal(err)
	}
	code := u.Query().Get("code")
	u.RawQuery = ""
	status, _, out := b.do(http.MethodPost, u.String(), url.Values{"csrf": {m[1]}, "code": {code}, "decision": {decision}})
	return status, out
}

func verifyToken(t *testing.T, d *Demo, c *CE) {
	t.Helper()
	raw, err := os.ReadFile(c.TokenFile())
	if err != nil {
		t.Fatalf("%s has no token: %v", c.Key, err)
	}
	claims, err := security.VerifyIDToken(strings.TrimSpace(string(raw)), &security.SecurityConfig{TokenSigningKeyDir: d.KeyDir()})
	if err != nil {
		t.Fatalf("%s's token does not verify with the registrar's key: %v", c.Key, err)
	}
	if claims.Subject != c.Name+"@"+IdentityDomain || claims.Issuer != TrustDomain || claims.Scope != "condor:/ADVERTISE_SCHEDD" {
		t.Errorf("%s's token claims: %+v", c.Key, claims)
	}
}

// TestDemo starts the demo headless, approves ce2 through the identity
// provider and the registrar's web UI as a browser would (after mallory is
// refused), and checks both CEs install tokens the registrar's key verifies.
// With an HTCondor installation (CONDOR_BIN, or condor_collector on PATH)
// it also checks what the collector accepts.
func TestDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("starts several processes")
	}
	logs := &lockedBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("demo output:\n%s", logs.String())
		}
	})
	opts := Options{Dir: t.TempDir(), Daemon: buildDaemon(t), Out: logs}
	d := startDemo(t, opts)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			d.Stop()
		}
	})
	ce1, ce2 := d.CE("ce1"), d.CE("ce2")
	verifyToken(t, d, ce1)
	approval := ce2.ApprovalURL()
	if approval == "" || !strings.HasPrefix(approval, d.WebURL()+"/approve?code=") {
		t.Fatalf("ce2's approval URL is %q", approval)
	}
	if !strings.Contains(d.Banner(), approval) {
		t.Errorf("the banner does not show ce2's approval URL:\n%s", d.Banner())
	}

	mallory := newBrowser(t)
	page := mallory.signIn(approval, "mallory")
	if !strings.Contains(page, "not authorized") {
		t.Errorf("mallory's approval page does not say she is not authorized:\n%s", page)
	}
	if code, out := mallory.decide(approval, page, "approve"); code != http.StatusForbidden {
		t.Fatalf("mallory's approval: HTTP %d, want 403:\n%s", code, out)
	}
	if ce2.HasToken() {
		t.Fatal("ce2 has a token after mallory's refused approval")
	}

	alice := newBrowser(t)
	page = alice.signIn(approval, "alice")
	if code, out := alice.decide(approval, page, "approve"); code != http.StatusOK || !strings.Contains(out, "approved") {
		t.Fatalf("alice's approval: HTTP %d:\n%s", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := waitFor(ctx, time.Minute, func() (bool, error) { return ce2.HasToken(), nil }); err != nil {
		t.Fatalf("ce2 did not install a token after alice approved: %v", err)
	}
	verifyToken(t, d, ce2)

	// The registrar's command-line list, authenticated by file system.
	env, err := d.CLIEnv("registrar")
	if err != nil {
		t.Fatal(err)
	}
	cli := exec.CommandContext(ctx, opts.Daemon, "cli", "list") //nolint:gosec // the daemon this test built
	cli.Env = env
	out, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("htc-registration list: %v\n%s", err, out)
	}
	for _, want := range []string{"ce1.localhost", "ce2.localhost", "alice"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("htc-registration list does not show %s:\n%s", want, out)
		}
	}

	if ok, why := d.HasCollector(); ok {
		checkCollector(t, d)
	} else {
		t.Logf("no HTCondor collector: %s", why)
	}

	// A restart keeps the registrations and the ports.
	web := d.WebURL()
	d.Stop()
	stopped = true
	d = startDemo(t, opts)
	t.Cleanup(d.Stop)
	if d.WebURL() != web {
		t.Errorf("the web UI moved from %s to %s", web, d.WebURL())
	}
	for _, c := range d.CEs() {
		if !c.HasToken() || c.ApprovalURL() != "" {
			t.Errorf("after a restart %s has no token or a pending approval", c.Key)
		}
	}
}

func checkCollector(t *testing.T, d *Demo) {
	t.Helper()
	ce1, ce2 := d.CE("ce1"), d.CE("ce2")
	want := map[[2]string]bool{
		{ce1.Name, ce1.Name}: true,  // ce1's token, Name ce1: accepted
		{ce1.Name, ce2.Name}: false, // ce1's token, Name ce2: rejected
		{ce2.Name, ce2.Name}: true,  // ce2's token after approval: accepted
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// ce2's check runs when its master is told to reconfigure.
	_ = waitFor(ctx, 30*time.Second, func() (bool, error) { return len(d.CollectorChecks()) >= len(want), nil })
	seen := map[[2]string]bool{}
	for _, c := range d.CollectorChecks() {
		k := [2]string{c.CE, c.Name}
		seen[k] = true
		if w, ok := want[k]; ok && c.Accepted != w {
			t.Errorf("collector check %s: accepted=%t, want %t", c, c.Accepted, w)
		}
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("no collector check with %s's token for Name %s", k[0], k[1])
		}
	}
}

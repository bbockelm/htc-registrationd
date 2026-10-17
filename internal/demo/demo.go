// Package demo runs htc-registrationd on one machine, with no root and no
// system changes: a registrar with its web UI, a mock OpenID provider, two
// CEs (one registering by callback, one by approval), and, when an HTCondor
// installation is found, a condor_collector configured as an HTCondor-CE
// CE-Collector that the CEs' tokens are tried against.
package demo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/htc-registrationd/internal/ce"
	"github.com/bbockelm/htc-registrationd/internal/demo/idp"
	"github.com/bbockelm/htc-registrationd/internal/mint"
)

// Options configure a demo.
type Options struct {
	// Dir holds all demo state (default .demo).
	Dir string
	// Daemon is the htc-registrationd binary.
	Daemon string
	// CondorBin is where to look for condor_collector; empty means
	// $CONDOR_BIN, then PATH.
	CondorBin string
	// NoCollector skips the HTCondor collector even when one is found.
	NoCollector bool
	// TokenLifetime is the registrar's token lifetime (default 10m; CEs
	// renew at half of it).
	TokenLifetime time.Duration
	// Out receives the prefixed logs and the banner (default os.Stdout).
	Out io.Writer
}

// Demo is a running demo.
type Demo struct {
	opts Options
	root string
	user string
	// daemonUser is who the daemons authenticate as by FS: the user, or,
	// when the demo runs as root, the condor account HTCondor's FS
	// authentication uses for a root daemon.
	daemonUser   string
	pki          *pki
	ports        *ports
	clientSecret string
	ces          []*CE
	collector    *collector
	// collectorNote says why there is no collector.
	collectorNote string
	out           *output

	procs   []*process
	idpSrv  *http.Server
	run     context.Context
	cancel  context.CancelFunc
	tails   sync.WaitGroup
	reconfs chan *CE

	mu     sync.Mutex
	checks []CollectorCheck
	forged bool
}

// New resolves the demo's layout in opts.Dir. It changes nothing on disk.
func New(opts Options) (*Demo, error) {
	if opts.Dir == "" {
		opts.Dir = ".demo"
	}
	if opts.TokenLifetime <= 0 {
		opts.TokenLifetime = 10 * time.Minute
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	root, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	d := &Demo{opts: opts, root: root, user: u.Username, daemonUser: u.Username, out: &output{w: opts.Out, width: 9}}
	if os.Geteuid() == 0 {
		if _, err := user.Lookup("condor"); err == nil {
			d.daemonUser = "condor"
		}
	}
	d.ces = []*CE{
		{Key: "ce1", Name: "ce1.localhost", Method: ce.MethodCallback, dir: filepath.Join(root, "ce1")},
		{Key: "ce2", Name: "ce2.localhost", Method: ce.MethodApproval, dir: filepath.Join(root, "ce2")},
	}
	return d, nil
}

// allowUsers is the ALLOW_* value naming the user and the daemons.
func (d *Demo) allowUsers() string {
	if d.daemonUser == d.user {
		return d.user + "@*"
	}
	return d.user + "@*, " + d.daemonUser + "@*"
}

// Root is the demo's state directory.
func (d *Demo) Root() string { return d.root }

// CEs are the demo's CEs.
func (d *Demo) CEs() []*CE { return d.ces }

// CE returns the CE with key (ce1, ce2), or nil.
func (d *Demo) CE(key string) *CE {
	for _, c := range d.ces {
		if c.Key == key {
			return c
		}
	}
	return nil
}

// ConfigFor is the CONDOR_CONFIG of a demo daemon: registrar, ce1 or ce2.
func (d *Demo) ConfigFor(target string) (string, error) {
	path := ""
	if target == "registrar" {
		path = d.RegistrarConfig()
	} else if c := d.CE(target); c != nil {
		path = c.Config()
	} else {
		return "", fmt.Errorf("unknown daemon %q (want registrar, ce1 or ce2)", target)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no demo in %s; run make demo first", d.root)
	}
	return path, nil
}

// CLIEnv is the environment for running htc-registration against a demo
// daemon: registrar, ce1 or ce2.
func (d *Demo) CLIEnv(target string) ([]string, error) {
	config, err := d.ConfigFor(target)
	if err != nil {
		return nil, err
	}
	return childEnv("CONDOR_CONFIG=" + config), nil
}

// Advertise sends a Scheduler ad claiming name to the demo collector,
// authenticating with the installed token of the CE with key ceKey, and
// reports whether the collector accepted it. The demo must be running.
func (d *Demo) Advertise(ctx context.Context, ceKey, name string) (CollectorCheck, error) {
	c := d.CE(ceKey)
	if c == nil {
		return CollectorCheck{}, fmt.Errorf("unknown CE %q (want ce1 or ce2)", ceKey)
	}
	p, err := readPorts(d.root)
	if err != nil {
		return CollectorCheck{}, err
	}
	d.ports = p
	c.port = []int{p.CE1, p.CE2}[slices.Index(d.ces, c)]
	col, why := findCondor(d.condorHint())
	if col == nil {
		return CollectorCheck{}, errors.New(why)
	}
	col.port, col.dir = p.Collector, filepath.Join(d.root, "collector")
	if _, err := os.Stat(filepath.Join(col.dir, "log", ".collector_address")); err != nil {
		return CollectorCheck{}, errors.New("the demo collector is not running")
	}
	d.collector = col
	return d.checkAd(ctx, c, name)
}

func (d *Demo) condorHint() string {
	if d.opts.CondorBin != "" {
		return d.opts.CondorBin
	}
	return os.Getenv("CONDOR_BIN")
}

func (d *Demo) runDir() string { return filepath.Join(d.root, "run") }

func (d *Demo) say(format string, args ...any) { d.out.line("demo", fmt.Sprintf(format, args...)) }

// Start sets the demo up and starts every process. It returns once ce1 is
// registered and ce2 has registered or published its approval URL, with the
// demo still running; Stop ends it.
func (d *Demo) Start(ctx context.Context) (err error) {
	if d.opts.Daemon == "" {
		return errors.New("demo: Options.Daemon (the htc-registrationd binary) is required")
	}
	if err := os.MkdirAll(d.runDir(), 0o700); err != nil {
		return err
	}
	killStale(d.runDir(), filepath.Base(d.opts.Daemon), "condor_collector")
	if d.ports, err = loadPorts(d.root); err != nil {
		return err
	}
	if !d.opts.NoCollector {
		d.collector, d.collectorNote = findCondor(d.condorHint())
	} else {
		d.collectorNote = "disabled"
	}
	if err := d.ports.checkFree(d.collector != nil); err != nil {
		return err
	}
	d.ces[0].port, d.ces[0].master = d.ports.CE1, d.ports.Master1
	d.ces[1].port, d.ces[1].master = d.ports.CE2, d.ports.Master2
	if d.pki, err = loadOrCreatePKI(filepath.Join(d.root, "pki")); err != nil {
		return fmt.Errorf("demo PKI: %w", err)
	}
	if d.clientSecret, err = d.loadClientSecret(); err != nil {
		return err
	}

	// ctx bounds startup; the demo runs until Stop.
	d.run, d.cancel = context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		if err != nil {
			d.Stop()
		}
	}()
	d.reconfs = make(chan *CE, 16)

	if d.collector != nil {
		d.collector.port, d.collector.dir = d.ports.Collector, filepath.Join(d.root, "collector")
		if err := d.writeCollectorConfig(); err != nil {
			return err
		}
		if err := d.startCollector(ctx); err != nil {
			d.say("the HTCondor collector did not start: %v", err)
			d.collectorNote = "condor_collector did not start: " + err.Error()
			d.collector = nil
		}
	}
	if err := d.writeRegistrarConfig(); err != nil {
		return err
	}
	for _, c := range d.ces {
		if err := d.writeCEConfig(c); err != nil {
			return err
		}
	}
	if err := d.startIDP(ctx); err != nil {
		return err
	}
	if err := d.startRegistrar(ctx); err != nil {
		return err
	}
	for _, c := range d.ces {
		onReconfig := func() {
			select {
			case d.reconfs <- c:
			case <-d.run.Done():
			}
		}
		if err := d.startMaster(ctx, c, onReconfig); err != nil {
			return err
		}
		if err := d.startCE(c); err != nil {
			return err
		}
	}
	go d.watch(d.run)

	// ce1 registers by itself; ce2 waits for a person.
	ce1, ce2 := d.ces[0], d.ces[1]
	if err := d.waitCE(ctx, ce1, 90*time.Second, func() bool { return hasToken(ce1) }); err != nil {
		return fmt.Errorf("ce1 did not register: %w", err)
	}
	if err := d.waitCE(ctx, ce2, 90*time.Second, func() bool { return hasToken(ce2) || approvalURL(ce2) != "" }); err != nil {
		return fmt.Errorf("ce2 neither registered nor published an approval URL: %w", err)
	}
	if d.collector != nil {
		// The banner shows what the collector made of ce1's token.
		if err := waitFor(ctx, 60*time.Second, func() (bool, error) { return d.forgedDone(), nil }); err != nil {
			d.say("collector check did not finish: %v", err)
		}
	}
	return nil
}

func (d *Demo) loadClientSecret() (string, error) {
	path := filepath.Join(d.root, "registrar", "oidc-client-secret")
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // the demo's own state
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (d *Demo) startIDP(ctx context.Context) error {
	var users []idp.User
	for _, u := range Users {
		users = append(users, idp.User{Sub: u.Sub, Note: u.Note})
	}
	p := idp.New(idp.Config{
		Issuer: d.IssuerURL(), ClientID: ClientID, ClientSecret: d.clientSecret,
		RedirectURI: d.WebURL() + "/oidc/callback", Users: users, EmailDomain: "example.org",
		Logger: newLineLogger(d.out, "idp"),
	})
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(d.ports.IDP))
	if err != nil {
		return fmt.Errorf("identity provider: %w", err)
	}
	d.idpSrv = &http.Server{Handler: p.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = d.idpSrv.Serve(ln) }()
	return nil
}

func (d *Demo) daemonEnv(config string) []string {
	return childEnv("CONDOR_CONFIG=" + config)
}

func (d *Demo) startRegistrar(ctx context.Context) error {
	addrFile := filepath.Join(d.root, "registrar", "log", ".htc_registrationd_address")
	_ = os.Remove(addrFile)
	d.startTail(d.RegistrarLog(), "registrar")
	p, err := start("registrar", d.runDir(), d.out, d.daemonEnv(d.RegistrarConfig()), d.opts.Daemon,
		"-mode", "registrar", "-listen", "127.0.0.1:"+strconv.Itoa(d.ports.Registrar))
	if err != nil {
		return err
	}
	d.procs = append(d.procs, p)
	client := &http.Client{Timeout: 2 * time.Second}
	return waitFor(ctx, 30*time.Second, func() (bool, error) {
		if p.exited() {
			return false, fmt.Errorf("the registrar exited: %w", p.err)
		}
		if _, err := os.Stat(addrFile); err != nil {
			return false, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.WebURL()+"/healthz", nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, nil
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, nil
	})
}

func (d *Demo) startCE(c *CE) error {
	d.startTail(c.Log(), c.Key)
	p, err := start(c.Key, d.runDir(), d.out, d.daemonEnv(c.Config()), d.opts.Daemon,
		"-mode", "ce", "-listen", "127.0.0.1:"+strconv.Itoa(c.port))
	if err != nil {
		return err
	}
	d.procs = append(d.procs, p)
	return nil
}

// startTail follows a daemon log from its current end.
func (d *Demo) startTail(path, prefix string) {
	d.startTailFrom(path, prefix, false, shortenLogLine)
}

func (d *Demo) startTailFrom(path, prefix string, fromStart bool, filter func(string) string) {
	d.tails.Add(1)
	go func() {
		defer d.tails.Done()
		tail(d.run, path, fromStart, d.out, prefix, filter)
	}()
}

// shortenLogLine rewrites a daemon's log record,
//
//	time=2026-10-17T11:12:45.311-05:00 level=INFO msg="..." pid=1 destination=general k=v
//
// as "11:12:45 INFO ... k=v". Other lines are returned as they are.
func shortenLogLine(line string) string {
	fields := splitLogfmt(line)
	if len(fields) < 3 || fields[0][0] != "time" || fields[1][0] != "level" || fields[2][0] != "msg" {
		return line
	}
	ts := fields[0][1]
	if i := strings.IndexByte(ts, 'T'); i >= 0 && len(ts) >= i+9 {
		ts = ts[i+1 : i+9]
	}
	msg := fields[2][1]
	if strings.HasPrefix(msg, "** ") || strings.HasPrefix(msg, "daemon-core env:") {
		// The startup preamble; it stays in the log file.
		return ""
	}
	var b strings.Builder
	b.WriteString(ts + " " + fields[1][1] + " " + msg)
	for _, f := range fields[3:] {
		if f[0] == "pid" || f[0] == "destination" {
			continue
		}
		v := f[1]
		if strings.ContainsAny(v, " \t\"=") || v == "" {
			v = strconv.Quote(v)
		}
		b.WriteString(" " + f[0] + "=" + v)
	}
	return b.String()
}

// splitLogfmt splits key=value pairs, unquoting quoted values. It returns
// nil when line is not in that form.
func splitLogfmt(line string) [][2]string {
	var out [][2]string
	for line != "" {
		line = strings.TrimLeft(line, " ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 || strings.ContainsAny(line[:eq], " \"") {
			return nil
		}
		key, rest := line[:eq], line[eq+1:]
		var val string
		if strings.HasPrefix(rest, "\"") {
			q, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return nil
			}
			val, _ = strconv.Unquote(q)
			rest = rest[len(q):]
		} else {
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				end = len(rest)
			}
			val, rest = rest[:end], rest[end:]
		}
		out = append(out, [2]string{key, val})
		line = rest
	}
	return out
}

func (d *Demo) waitCE(ctx context.Context, c *CE, limit time.Duration, done func() bool) error {
	var proc *process
	for _, p := range d.procs {
		if p.name == c.Key {
			proc = p
		}
	}
	return waitFor(ctx, limit, func() (bool, error) {
		if proc != nil && proc.exited() {
			return false, fmt.Errorf("%s exited: %w", c.Key, proc.err)
		}
		return done(), nil
	})
}

var errTimeout = errors.New("timed out")

// waitFor polls cond until it is true, fails, or limit passes.
func waitFor(ctx context.Context, limit time.Duration, cond func() (bool, error)) error {
	deadline := time.Now().Add(limit)
	for {
		ok, err := cond()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return errTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Stop stops every process. The state directory is kept.
func (d *Demo) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	// CEs first, then the registrar, then the collector: the reverse of
	// start.
	var wg sync.WaitGroup
	for i := len(d.procs) - 1; i >= 0; i-- {
		p := d.procs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.stop(10 * time.Second)
		}()
	}
	wg.Wait()
	if d.idpSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = d.idpSrv.Shutdown(sctx)
		cancel()
	}
	d.tails.Wait()
}

// Wait blocks until ctx ends or a demo process exits on its own.
func (d *Demo) Wait(ctx context.Context) error {
	exited := make(chan *process, len(d.procs))
	for _, p := range d.procs {
		go func() {
			<-p.done
			exited <- p
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case p := <-exited:
		return fmt.Errorf("%s exited: %w", p.name, p.err)
	}
}

// hasToken reports whether the CE has an unexpired token installed.
func hasToken(c *CE) bool {
	_, err := tokenClaims(c)
	return err == nil
}

func tokenClaims(c *CE) (*mint.Claims, error) {
	raw, err := os.ReadFile(c.TokenFile())
	if err != nil {
		return nil, err
	}
	claims, err := mint.ParseUnverified(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if time.Unix(claims.Expiry, 0).Before(time.Now()) {
		return nil, errors.New("expired")
	}
	return claims, nil
}

// approvalURL is the CE's published approval URL, or "".
func approvalURL(c *CE) string {
	b, err := os.ReadFile(c.ApprovalURLFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ApprovalURL is the CE's pending approval URL, or "".
func (c *CE) ApprovalURL() string { return approvalURL(c) }

// HasToken reports whether the CE has an unexpired token installed.
func (c *CE) HasToken() bool { return hasToken(c) }

// watch handles the CEs' reconfig requests: each follows a token install,
// and is when a CE's master would have its schedd advertise with the new
// token. With a collector, the demo advertises a Scheduler ad for the CE
// using it; the first time ce1 does, it also tries an ad that claims ce2's
// name with ce1's token.
func (d *Demo) watch(ctx context.Context) {
	// A CE whose token survives from an earlier run sends no reconfig.
	for _, c := range d.ces {
		if hasToken(c) {
			d.tokenInstalled(ctx, c, false)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-d.reconfs:
			d.tokenInstalled(ctx, c, true)
		}
	}
}

func (d *Demo) tokenInstalled(ctx context.Context, c *CE, fresh bool) {
	claims, err := tokenClaims(c)
	if err != nil {
		d.say("%s: master reconfig requested, but no usable token: %v", c.Key, err)
		return
	}
	what := "has a token from an earlier run"
	if fresh {
		what = "asked its master to reconfigure; token"
	}
	d.say("%s %s: sub=%s scope=%s expires %s", c.Key, what, claims.Subject, claims.Scope,
		time.Unix(claims.Expiry, 0).Local().Format("15:04:05"))
	if d.collector == nil {
		return
	}
	d.record(ctx, c, c.Name)
	d.mu.Lock()
	first := !d.forged && c == d.ces[0]
	d.forged = d.forged || first
	d.mu.Unlock()
	if first {
		d.record(ctx, c, d.ces[1].Name)
	}
}

func (d *Demo) record(ctx context.Context, c *CE, name string) {
	res, err := d.checkAd(ctx, c, name)
	if err != nil {
		d.say("collector check (%s's token, Name = %s) failed: %v", c.Name, name, err)
		res.Detail = "error: " + err.Error()
	} else {
		d.say("collector: %s", res)
	}
	d.mu.Lock()
	d.checks = append(d.checks, res)
	d.mu.Unlock()
}

func (d *Demo) forgedDone() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.checks {
		if r.CE == d.ces[0].Name && r.Name == d.ces[1].Name {
			return true
		}
	}
	return false
}

// CollectorChecks are the collector checks run so far.
func (d *Demo) CollectorChecks() []CollectorCheck {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]CollectorCheck(nil), d.checks...)
}

// HasCollector reports whether the HTCondor collector is running, and if
// not, why.
func (d *Demo) HasCollector() (bool, string) { return d.collector != nil, d.collectorNote }

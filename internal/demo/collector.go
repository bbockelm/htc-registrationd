package demo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// collectorRequirements is HTCondor-CE's CE-Collector COLLECTOR_REQUIREMENTS
// (01-ce-collector-requirements.conf): a Scheduler ad is accepted only when
// its Name, and the CE named in its grid_resource, are the user part of the
// identity it authenticated as.
const collectorRequirements = `\
  (  (TARGET.MyType == "Scheduler") \
  && (TARGET.Name == splitUserName(TARGET.AuthenticatedIdentity)[0])  \
  && (isString(TARGET.grid_resource))  \
  && (stringListSize(TARGET.grid_resource, ": ") >= 3)  \
  && (split(TARGET.grid_resource, ": ")[1] == splitUserName(TARGET.AuthenticatedIdentity)[0]) \
  && (split(TARGET.grid_resource, ": ")[2] == splitUserName(TARGET.AuthenticatedIdentity)[0]) \
  ) || \
  ((TARGET.MyType != "Scheduler") && (TARGET.MyType != "Machine") && (TARGET.MyType != "DaemonMaster"))`

// violation is what the collector logs (at D_MACHINE) when an ad fails
// COLLECTOR_REQUIREMENTS.
const violation = "COLLECTOR_REQUIREMENTS VIOLATION"

// collector is a C++ condor_collector configured as a CE-Collector.
type collector struct {
	exe       string
	advertise string
	status    string
	version   string
	libEnv    []string
	port      int
	dir       string
	proc      *process
}

func (c *collector) address() string { return "127.0.0.1:" + strconv.Itoa(c.port) }

func (c *collector) config() string { return filepath.Join(c.dir, "condor_config") }

func (c *collector) log() string { return filepath.Join(c.dir, "log", "CollectorLog") }

// findCondor locates condor_collector, condor_advertise and condor_status:
// in hint (a directory holding condor_collector, or a release directory),
// else on PATH. It returns why it found none.
func findCondor(hint string) (*collector, string) {
	var exe string
	if hint != "" {
		for _, p := range []string{filepath.Join(hint, "condor_collector"), filepath.Join(hint, "sbin", "condor_collector"),
			filepath.Join(hint, "..", "sbin", "condor_collector")} {
			if isExecutable(p) {
				exe = filepath.Clean(p)
				break
			}
		}
		if exe == "" {
			return nil, "no condor_collector in " + hint
		}
	} else {
		p, err := exec.LookPath("condor_collector")
		if err != nil {
			return nil, "condor_collector is not on PATH; set CONDOR_BIN to an HTCondor sbin directory"
		}
		exe = p
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}
	release := filepath.Dir(filepath.Dir(exe))
	find := func(name string) string {
		for _, d := range []string{filepath.Dir(exe), filepath.Join(release, "bin"), filepath.Join(release, "sbin")} {
			if p := filepath.Join(d, name); isExecutable(p) {
				return p
			}
		}
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		return ""
	}
	c := &collector{exe: exe, advertise: find("condor_advertise"), status: find("condor_status")}
	if c.advertise == "" || c.status == "" {
		return nil, "found " + exe + " but not condor_advertise and condor_status"
	}
	// A build tree's release_dir is not on the loader path.
	if release != "/usr" && release != "/" {
		if st, err := os.Stat(filepath.Join(release, "lib", "condor")); err == nil && st.IsDir() {
			v := "LD_LIBRARY_PATH"
			if runtime.GOOS == "darwin" {
				v = "DYLD_LIBRARY_PATH"
			}
			c.libEnv = []string{v + "=" + filepath.Join(release, "lib") + ":" + filepath.Join(release, "lib", "condor")}
		}
	}
	if v := find("condor_version"); v != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, v) //nolint:gosec // HTCondor's own tool
		cmd.Env = childEnv(append(c.libEnv, "CONDOR_CONFIG=/dev/null")...)
		if out, err := cmd.Output(); err == nil {
			if f := strings.Fields(string(out)); len(f) > 1 {
				c.version = f[1]
			}
		}
	}
	return c, ""
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

func (c *collector) env() []string {
	return childEnv(append(c.libEnv, "CONDOR_CONFIG="+c.config())...)
}

func (d *Demo) writeCollectorConfig() error {
	c := d.collector
	if err := mkdirs(c.dir, "log", "spool", "lock", "run", "execute", "tokens.d"); err != nil {
		return err
	}
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%-50s = %s\n", k, v) }
	b.WriteString("# Written by htc-registrationd-demo at every start; edits are lost.\n\n")
	w("LOCAL_DIR", c.dir)
	w("LOG", "$(LOCAL_DIR)/log")
	w("SPOOL", "$(LOCAL_DIR)/spool")
	w("LOCK", "$(LOCAL_DIR)/lock")
	w("RUN", "$(LOCAL_DIR)/run")
	w("EXECUTE", "$(LOCAL_DIR)/execute")
	w("CONDOR_HOST", "127.0.0.1")
	w("COLLECTOR_HOST", c.address())
	w("COLLECTOR_NAME", "Demo CE-Collector")
	w("COLLECTOR_ADDRESS_FILE", "$(LOG)/.collector_address")
	w("NETWORK_INTERFACE", "127.0.0.1")
	w("ENABLE_IPV6", "false")
	w("USE_SHARED_PORT", "false")
	w("UID_DOMAIN", IdentityDomain)
	w("TRUST_DOMAIN", TrustDomain)
	b.WriteString("\n# The registrar's signing key verifies the CEs' tokens.\n")
	w("SEC_PASSWORD_DIRECTORY", d.KeyDir())
	w("SEC_TOKEN_POOL_SIGNING_KEY_FILE", "$(LOCAL_DIR)/pool-signing-key")
	w("SEC_TOKEN_SYSTEM_DIRECTORY", "$(LOCAL_DIR)/tokens.d")
	w("SEC_TOKEN_DIRECTORY", "$(LOCAL_DIR)/tokens.d")
	w("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS, IDTOKENS")
	w("COLLECTOR.SEC_ADVERTISE_SCHEDD_AUTHENTICATION_METHODS", "IDTOKENS")
	w("SEC_ADVERTISE_SCHEDD_AUTHENTICATION", "REQUIRED")
	w("ALLOW_READ", "*")
	w("ALLOW_WRITE", d.user+"@*")
	w("ALLOW_DAEMON", d.user+"@*")
	w("ALLOW_ADMINISTRATOR", d.user+"@*")
	w("ALLOW_ADVERTISE_SCHEDD", "*@"+IdentityDomain)
	b.WriteString("\n# HTCondor-CE's CE-Collector requirements: an ad's Name must be the name it authenticated as.\n")
	w("COLLECTOR_REQUIREMENTS", collectorRequirements)
	w("COLLECTOR_DEBUG", "D_MACHINE")
	return os.WriteFile(c.config(), []byte(b.String()), 0o600)
}

// writeAdvertiseConfig is the configuration condor_advertise uses to
// authenticate as ce, with ce's installed token.
func (d *Demo) writeAdvertiseConfig(ce *CE) error {
	var t strings.Builder
	w := func(k, v string) { fmt.Fprintf(&t, "%-36s = %s\n", k, v) }
	t.WriteString("# condor_advertise as " + ce.Name + ", with its installed token.\n\n")
	w("LOCAL_DIR", ce.dir)
	w("LOG", "$(LOCAL_DIR)/log")
	w("COLLECTOR_HOST", d.collector.address())
	w("NETWORK_INTERFACE", "127.0.0.1")
	w("ENABLE_IPV6", "false")
	w("USE_SHARED_PORT", "false")
	w("UID_DOMAIN", IdentityDomain)
	w("TRUST_DOMAIN", TrustDomain)
	w("SEC_TOKEN_DIRECTORY", "$(LOCAL_DIR)/tokens.d")
	w("SEC_CLIENT_AUTHENTICATION_METHODS", "IDTOKENS")
	w("SEC_PASSWORD_DIRECTORY", "$(LOCAL_DIR)/no-passwords.d")
	w("SEC_TOKEN_POOL_SIGNING_KEY_FILE", "$(LOCAL_DIR)/no-pool-signing-key")
	return os.WriteFile(advertiseConfig(ce), []byte(t.String()), 0o600)
}

func advertiseConfig(ce *CE) string { return filepath.Join(ce.dir, "advertise_config") }

func (d *Demo) startCollector(ctx context.Context) error {
	c := d.collector
	addrFile := filepath.Join(c.dir, "log", ".collector_address")
	_ = os.Remove(addrFile)
	p, err := start("collector", d.runDir(), d.out, c.env(), c.exe, "-f", "-p", strconv.Itoa(c.port))
	if err != nil {
		return err
	}
	c.proc = p
	d.startTailFrom(c.log(), "collector", true, collectorLogFilter)
	if err := waitFor(ctx, 30*time.Second, func() (bool, error) {
		if p.exited() {
			return false, fmt.Errorf("condor_collector exited: %w", p.err)
		}
		_, err := os.Stat(addrFile)
		return err == nil, nil
	}); err != nil {
		p.stop(5 * time.Second)
		return err
	}
	d.procs = append(d.procs, p)
	return nil
}

// collectorLogFilter keeps the collector's lines about ads it rejects,
// authorization failures and errors, without the date.
func collectorLogFilter(line string) string {
	keep := false
	for _, s := range []string{"VIOLATION", "DENIED", "ERROR", "FAILED", "STARTING UP", "EXITING"} {
		if strings.Contains(line, s) {
			keep = true
			break
		}
	}
	if !keep {
		return ""
	}
	if f := strings.SplitN(line, " ", 2); len(f) == 2 && strings.Count(f[0], "/") == 2 {
		return f[1]
	}
	return line
}

// schedulerAd is a minimal CE Scheduler ad: name is the Name it claims.
func schedulerAd(name string, ce *CE) string {
	return fmt.Sprintf("MyType = \"Scheduler\"\nName = %q\nMachine = %q\nMyAddress = %q\n"+
		"grid_resource = \"condor %s %s:9619\"\nDemoAdvertisedBy = %q\n",
		name, name, ce.Address(), name, name, ce.Name)
}

// advertise sends a Scheduler ad claiming name, authenticating with ce's
// installed token, and returns condor_advertise's output.
func (d *Demo) advertise(ctx context.Context, ce *CE, name string) (string, error) {
	c := d.collector
	adFile := filepath.Join(ce.dir, "scheduler-"+name+".ad")
	if err := os.WriteFile(adFile, []byte(schedulerAd(name, ce)), 0o600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.advertise, "-tcp", "UPDATE_SCHEDD_AD", adFile) //nolint:gosec // HTCondor's own tool
	cmd.Env = childEnv(append(c.libEnv, "CONDOR_CONFIG="+advertiseConfig(ce))...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// query runs condor_status -schedd with a constraint and returns its lines.
func (d *Demo) query(ctx context.Context, constraint string, attrs ...string) ([]string, error) {
	c := d.collector
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := append([]string{"-schedd", "-constraint", constraint, "-af"}, attrs...)
	cmd := exec.CommandContext(ctx, c.status, args...) //nolint:gosec // HTCondor's own tool
	cmd.Env = c.env()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("condor_status: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

func (d *Demo) violations() int {
	b, err := os.ReadFile(d.collector.log())
	if err != nil {
		return 0
	}
	return bytes.Count(b, []byte(violation))
}

// CollectorCheck is the outcome of advertising one Scheduler ad.
type CollectorCheck struct {
	// CE is the CE whose token authenticated the update.
	CE string
	// Name is the Name the ad claimed.
	Name string
	// Accepted reports whether the collector holds the ad.
	Accepted bool
	// Detail is condor_status's view of the ad, or why it is absent.
	Detail string
}

func (c CollectorCheck) String() string {
	verdict := "rejected"
	if c.Accepted {
		verdict = "accepted"
	}
	return fmt.Sprintf("%s's token, ad Name = %s: %s (%s)", c.CE, c.Name, verdict, c.Detail)
}

// checkAd advertises a Scheduler ad claiming name with ce's token, then
// asks the collector whether it holds it.
func (d *Demo) checkAd(ctx context.Context, ce *CE, name string) (CollectorCheck, error) {
	res := CollectorCheck{CE: ce.Name, Name: name}
	before := d.violations()
	out, err := d.advertise(ctx, ce, name)
	if err != nil {
		return res, fmt.Errorf("condor_advertise: %w: %s", err, out)
	}
	constraint := fmt.Sprintf("Name == %q && DemoAdvertisedBy == %q", name, ce.Name)
	var lines []string
	// The collector processes the update after acknowledging it.
	err = waitFor(ctx, 5*time.Second, func() (bool, error) {
		var qerr error
		lines, qerr = d.query(ctx, constraint, "Name", "AuthenticatedIdentity")
		return qerr == nil && len(lines) > 0, qerr
	})
	if len(lines) > 0 {
		res.Accepted, res.Detail = true, "condor_status: "+lines[0]
		return res, nil
	}
	if err != nil && !errors.Is(err, errTimeout) {
		return res, err
	}
	res.Detail = "not in condor_status"
	if d.violations() > before {
		res.Detail += "; CollectorLog: " + violation
	}
	return res, nil
}

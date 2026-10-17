package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

// Names and domains the demo uses. Every *.localhost name resolves to
// loopback without configuration (RFC 6761 section 6.3).
const (
	RegistrarName  = "registrar.localhost"
	TrustDomain    = "demo.localhost"
	IdentityDomain = "users.htcondor.org"
	SigningKey     = "ce-registration"
	ClientID       = "htc-registrationd-demo"
	tokenFileName  = "50-htc-registration" //nolint:gosec // a file name
	daemonLogName  = "HtcRegistrationdLog"
)

// CE is one demo CE.
type CE struct {
	// Key names the CE's directory under the demo root (ce1, ce2).
	Key string
	// Name is the CE name it registers.
	Name string
	// Method is its HTC_REGISTRATIOND_METHOD.
	Method string
	dir    string
	port   int
	master int
}

// Dir is the CE's directory.
func (c *CE) Dir() string { return c.dir }

// Config is the CE's CONDOR_CONFIG.
func (c *CE) Config() string { return filepath.Join(c.dir, "condor_config") }

// StateDir is the CE's HTC_REGISTRATIOND_STATE_DIR.
func (c *CE) StateDir() string { return filepath.Join(c.dir, "spool", "htc-registrationd") }

// TokenFile is where the CE installs its token.
func (c *CE) TokenFile() string { return filepath.Join(c.dir, "tokens.d", tokenFileName) }

// ApprovalURLFile is where the CE publishes a pending approval URL.
func (c *CE) ApprovalURLFile() string { return filepath.Join(c.StateDir(), "approval-url") }

// Log is the CE daemon's log file.
func (c *CE) Log() string { return filepath.Join(c.dir, "log", daemonLogName) }

// Address is the CE daemon's sinful.
func (c *CE) Address() string { return "<127.0.0.1:" + strconv.Itoa(c.port) + ">" }

// ports are the loopback TCP ports the demo listens on. They are chosen once
// and kept in ports.json, so URLs (and the identity provider's issuer, which
// recorded approvals name) stay the same from one run to the next.
type ports struct {
	Registrar int `json:"registrar"`
	Web       int `json:"web"`
	IDP       int `json:"idp"`
	CE1       int `json:"ce1"`
	CE2       int `json:"ce2"`
	Master1   int `json:"ce1_master"`
	Master2   int `json:"ce2_master"`
	Collector int `json:"collector"`
}

func (p *ports) all() []*int {
	return []*int{&p.Registrar, &p.Web, &p.IDP, &p.CE1, &p.CE2, &p.Master1, &p.Master2, &p.Collector}
}

// loadPorts reads ports.json in dir, choosing ports when it is missing or
// incomplete, and saves it.
func loadPorts(dir string) (*ports, error) {
	path := filepath.Join(dir, "ports.json")
	p := &ports{}
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // the demo's own state file
		if err := json.Unmarshal(b, p); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !slices.ContainsFunc(p.all(), func(v *int) bool { return *v == 0 }) {
		return p, nil
	}
	base, err := freeRange(len(p.all()))
	if err != nil {
		return nil, err
	}
	for i, v := range p.all() {
		*v = base + i
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	return p, nil
}

// Demo ports are taken from below the ephemeral ranges (Linux 32768-60999,
// macOS and IANA 49152-65535), so no outgoing connection holds one when a
// daemon binds it.
const portLow, portHigh = 20000, 30000

// freeRange finds n consecutive free loopback ports.
func freeRange(n int) (int, error) {
	for range 100 {
		base := portLow + rand.IntN(portHigh-portLow-n) //nolint:gosec // a port number, not a secret
		ok := true
		for port := base; port < base+n && ok; port++ {
			ok = portFree(port)
		}
		if ok {
			return base, nil
		}
	}
	return 0, fmt.Errorf("no %d consecutive free ports between %d and %d", n, portLow, portHigh)
}

func portFree(port int) bool {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// readPorts reads ports.json in dir.
func readPorts(dir string) (*ports, error) {
	b, err := os.ReadFile(filepath.Join(dir, "ports.json")) //nolint:gosec // the demo's own state file
	if err != nil {
		return nil, fmt.Errorf("no demo in %s; run make demo first", dir)
	}
	p := &ports{}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, err
	}
	return p, nil
}

// checkFree fails when a port is already taken, naming what it was for.
func (p *ports) checkFree(withCollector bool) error {
	names := map[string]int{
		"registrar": p.Registrar, "web UI": p.Web, "identity provider": p.IDP,
		"ce1": p.CE1, "ce2": p.CE2, "ce1 master": p.Master1, "ce2 master": p.Master2,
	}
	if withCollector {
		names["collector"] = p.Collector
	}
	for what, port := range names {
		if !portFree(port) {
			return fmt.Errorf("port %d (%s) is in use; is another demo running? (make demo-clean picks new ports)", port, what)
		}
	}
	return nil
}

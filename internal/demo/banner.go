package demo

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// rel shortens a path to one relative to the working directory when it is
// beneath it.
func rel(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	if r, err := filepath.Rel(wd, path); err == nil && !strings.HasPrefix(r, "..") {
		if !strings.Contains(r, string(filepath.Separator)) {
			return "." + string(filepath.Separator) + r
		}
		return r
	}
	return path
}

// CLI is the command that runs the htc-registration tool.
func (d *Demo) CLI() string {
	if p := filepath.Join(filepath.Dir(d.opts.Daemon), "htc-registration"); isExecutable(p) {
		return rel(p)
	}
	return rel(d.opts.Daemon) + " cli"
}

// Banner is the summary printed once the demo is up.
func (d *Demo) Banner() string {
	var b strings.Builder
	line := strings.Repeat("=", 78)
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	p("")
	p(line)
	p(" htc-registrationd demo is running. State: %s", rel(d.root))
	p(line)
	p("")
	p(" Registrar web UI    %s/registrations", d.WebURL())
	p(" Identity provider   %s", d.IssuerURL())
	p("")
	p(" CEs")
	for _, c := range d.ces {
		state := "not registered"
		if claims, err := tokenClaims(c); err == nil {
			state = "registered; token expires " + time.Unix(claims.Expiry, 0).Local().Format("15:04:05") +
				", " + rel(c.TokenFile())
		} else if u := approvalURL(c); u != "" {
			state = "awaiting approval at\n" + strings.Repeat(" ", 35) + u
		}
		p("   %-14s %-9s %s", c.Name, c.Method, state)
	}
	p("")
	p(" Sign-in identities (pick one on the identity provider's page)")
	for _, u := range Users {
		p("   %-8s %s", u.Sub, u.Note)
	}
	p("")
	if d.collector != nil {
		v := d.collector.version
		if v == "" {
			v = "version unknown"
		}
		p(" HTCondor collector  %s (HTCondor %s, %s)", d.collector.address(), v, d.collector.exe)
		p("   Requirements: a Scheduler ad's Name must be the CE name its token authenticates.")
		for _, c := range d.CollectorChecks() {
			p("   %s", c)
		}
		p("")
	} else {
		p(" HTCondor collector  not started: %s", d.collectorNote)
		p("")
	}
	p(" Try")
	p("   make demo-status                     both CEs' registration state and the registrar's list")
	p("   make demo-revoke NAME=ce1.localhost  revoke ce1's registration")
	p("   make demo-renew CE=ce1               renew ce1's token now")
	p("   make demo-request CE=ce1             start an approval request on ce1 (prints its URL and code)")
	p("   make demo-approve CODE=XXXX-XXXX     approve a request on the command line")
	if d.collector != nil {
		p("   make demo-advertise CE=ce1 NAME=ce2.localhost   advertise a Scheduler ad with ce1's token")
	}
	p("")
	p(" Or run the tool directly:")
	p("   CONDOR_CONFIG=%s %s list", rel(d.RegistrarConfig()), d.CLI())
	p("   CONDOR_CONFIG=%s %s status", rel(d.ces[1].Config()), d.CLI())
	if d.collector != nil {
		lib := ""
		if len(d.collector.libEnv) > 0 {
			lib = d.collector.libEnv[0] + " "
		}
		p("   %sCONDOR_CONFIG=%s %s -schedd -af Name AuthenticatedIdentity",
			lib, rel(d.collector.config()), d.collector.status)
	}
	p("")
	p(" Logs: %s/*/log. Ctrl-C stops the demo and keeps its state; make demo-clean removes it.", rel(d.root))
	p(line)
	p("")
	return b.String()
}

// PrintBanner writes the banner between the log lines.
func (d *Demo) PrintBanner() { d.out.block(d.Banner()) }

// Say writes a line prefixed "demo".
func (d *Demo) Say(format string, args ...any) { d.say(format, args...) }

// lineHandler is a slog handler that writes one prefixed line per record.
type lineHandler struct {
	out    *output
	prefix string
	attrs  []slog.Attr
}

func newLineLogger(out *output, prefix string) *slog.Logger {
	return slog.New(&lineHandler{out: out, prefix: prefix})
}

func (h *lineHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("15:04:05.000 "))
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	h.out.line(h.prefix, b.String())
	return nil
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &n
}

func (h *lineHandler) WithGroup(string) slog.Handler { return h }

package knobs

import (
	"strings"
	"testing"
	"time"
)

func TestTypedKnobs(t *testing.T) {
	cfg := Map{
		"HTC_REGISTRATIOND_TOKEN_LIFETIME": "259200",
		"HTC_REGISTRATIOND_APPROVAL_TTL":   "30m",
		"HTC_REGISTRATIOND_RECHECK":        "False",
		"HTC_REGISTRATIOND_MAX":            "12",
		"HTC_REGISTRATIOND_LIMITS":         "ADVERTISE_SCHEDD, READ",
		"BAD_BOOL":                         "maybe",
	}
	if d, err := Duration(cfg, "HTC_REGISTRATIOND_TOKEN_LIFETIME", 0); err != nil || d != 72*time.Hour {
		t.Errorf("seconds: %v %v", d, err)
	}
	if d, err := Duration(cfg, "htc_registrationd_approval_ttl", 0); err != nil || d != 30*time.Minute {
		t.Errorf("duration, case-insensitive: %v %v", d, err)
	}
	if d, _ := Duration(cfg, "UNSET", time.Second); d != time.Second {
		t.Errorf("default: %v", d)
	}
	if b, err := Bool(cfg, "HTC_REGISTRATIOND_RECHECK", true); err != nil || b {
		t.Errorf("bool: %v %v", b, err)
	}
	if _, err := Bool(cfg, "BAD_BOOL", true); err == nil {
		t.Error("bad bool accepted")
	}
	if n, err := Int(cfg, "HTC_REGISTRATIOND_MAX", 0); err != nil || n != 12 {
		t.Errorf("int: %v %v", n, err)
	}
	if l := List(cfg, "HTC_REGISTRATIOND_LIMITS", nil); len(l) != 2 || l[1] != "READ" {
		t.Errorf("list: %v", l)
	}
}

func TestSpoolWarning(t *testing.T) {
	base := Map{"SPOOL": "/var/lib/condor-ce/spool"}
	if w := SpoolWarning(base, "/var/lib/condor-ce/spool/htc-registrationd"); !strings.Contains(w, "VALID_SPOOL_FILES") {
		t.Errorf("no warning: %q", w)
	}
	covered := Map{"SPOOL": "/var/lib/condor-ce/spool", "VALID_SPOOL_FILES": "job_queue.log, htc-registrationd"}
	if w := SpoolWarning(covered, "/var/lib/condor-ce/spool/htc-registrationd"); w != "" {
		t.Errorf("covered but warned: %q", w)
	}
	prefix := Map{"SPOOL": "/s", "SYSTEM_VALID_SPOOL_FILES": "htc-"}
	if w := SpoolWarning(prefix, "/s/htc-registrationd/sub"); w != "" {
		t.Errorf("prefix-covered but warned: %q", w)
	}
	if w := SpoolWarning(base, "/var/lib/htc-registrationd"); w != "" {
		t.Errorf("outside SPOOL but warned: %q", w)
	}
}

func TestDefaultRegistrar(t *testing.T) {
	cases := []struct {
		name string
		cfg  Map
		want string
	}{
		{"unset", Map{}, ""},
		{"host and port", Map{"CONDOR_VIEW_HOST": "collector.example.org:9619"},
			"<collector.example.org:9619?sock=htc_registrationd>"},
		{"first of several", Map{"CONDOR_VIEW_HOST": "c1.example.org:9619, c2.example.org:9619"},
			"<c1.example.org:9619?sock=htc_registrationd>"},
		{"space separated", Map{"CONDOR_VIEW_HOST": "c1.example.org:9619 c2.example.org:9619"},
			"<c1.example.org:9619?sock=htc_registrationd>"},
		{"no port takes COLLECTOR_PORT", Map{"CONDOR_VIEW_HOST": "collector.example.org", "COLLECTOR_PORT": "9619"},
			"<collector.example.org:9619?sock=htc_registrationd>"},
		{"no port and no COLLECTOR_PORT", Map{"CONDOR_VIEW_HOST": "collector.example.org"},
			"<collector.example.org:9618?sock=htc_registrationd>"},
		{"sinful with another sock", Map{"CONDOR_VIEW_HOST": "<192.0.2.5:9619?sock=collector&addrs=192.0.2.5-9619>"},
			"<192.0.2.5:9619?sock=htc_registrationd>"},
		{"ipv6", Map{"CONDOR_VIEW_HOST": "[2001:db8::5]:9619"},
			"<[2001:db8::5]:9619?sock=htc_registrationd>"},
	}
	for _, tc := range cases {
		if got := DefaultRegistrar(tc.cfg); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

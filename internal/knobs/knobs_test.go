package knobs

import (
	"errors"
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
	if b := Bool(cfg, "HTC_REGISTRATIOND_RECHECK", true); b {
		t.Errorf("bool: %v", b)
	}
	if b := Bool(cfg, "BAD_BOOL", true); !b {
		t.Error("an invalid bool did not keep the default")
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

// StringIsBooleanParam follows HTCondor's string_is_boolean_param.
func TestStringIsBooleanParam(t *testing.T) {
	cases := []struct {
		in          string
		def         bool
		want, valid bool
	}{
		{"true", false, true, true},
		{"TRUE", false, true, true},
		{"True  ", false, true, true},
		{"1", false, true, true},
		{"false", true, false, true},
		{"FaLsE\t", true, false, true},
		{"0", true, false, true},
		// Not literals, so ClassAd expressions.
		{"2 > 1", false, true, true},
		{"1 == 2", true, false, true},
		{"10", false, true, true},
		{"0.0", true, false, true},
		{"(3 - 3)", true, false, true},
		{"true && false", true, false, true},
		// HTCondor rejects these, keeping the default.
		{"yes", false, false, false},
		{"on", false, false, false},
		{"t", true, true, false},
		{"off", true, true, false},
		{`"true"`, false, false, false},
		// An invalid value with a literal prefix yields the literal.
		{"truex", false, true, false},
		{"falsey", true, false, false},
	}
	for _, tc := range cases {
		got, valid := StringIsBooleanParam(tc.in, tc.def)
		if got != tc.want || valid != tc.valid {
			t.Errorf("StringIsBooleanParam(%q, %v) = %v, %v; want %v, %v", tc.in, tc.def, got, valid, tc.want, tc.valid)
		}
	}
}

func TestCEName(t *testing.T) {
	lookup := func(host string) (string, error) {
		if host == "ce1" {
			return "ce1.example.edu.", nil
		}
		return "", errNoSuchHost
	}
	cases := []struct {
		name string
		cfg  Map
		want string
		err  string
	}{
		{"explicit, lower-cased", Map{"HTC_REGISTRATIOND_NAME": "CE.Example.EDU"}, "ce.example.edu", ""},
		{"no SCHEDD_NAME: the host", Map{"FULL_HOSTNAME": "ce1.example.edu"}, "ce1.example.edu", ""},
		{"SCHEDD_NAME is the host", Map{"SCHEDD_NAME": "CE1.example.edu", "FULL_HOSTNAME": "ce1.example.edu"},
			"ce1.example.edu", ""},
		{"short SCHEDD_NAME resolving to the host", Map{"SCHEDD_NAME": "ce1", "FULL_HOSTNAME": "ce1.example.edu"},
			"ce1.example.edu", ""},
		{"short SCHEDD_NAME with DEFAULT_DOMAIN_NAME", Map{"SCHEDD_NAME": "ce2", "NO_DNS": "true",
			"DEFAULT_DOMAIN_NAME": "example.edu", "FULL_HOSTNAME": "ce2.example.edu"}, "ce2.example.edu", ""},
		{"another name becomes name@host", Map{"SCHEDD_NAME": "alias.example.edu", "FULL_HOSTNAME": "ce1.example.edu"},
			"", "alias.example.edu@ce1.example.edu"},
		{"a name with @ is kept, and refused", Map{"SCHEDD_NAME": "a@b.example.edu", "FULL_HOSTNAME": "ce1.example.edu"},
			"", "a@b.example.edu"},
		{"nothing", Map{}, "", "no name"},
	}
	for _, tc := range cases {
		got, err := CEName(tc.cfg, lookup)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: %q, %v; want an error mentioning %q", tc.name, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if got := BuildValidDaemonName(Map{}, "alias.example.edu", "ce1.example.edu", lookup); got != "alias.example.edu@ce1.example.edu" {
		t.Errorf("BuildValidDaemonName: %q", got)
	}
}

var errNoSuchHost = errors.New("no such host")

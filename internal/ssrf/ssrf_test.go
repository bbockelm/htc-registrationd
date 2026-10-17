package ssrf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func newTestPolicy(t *testing.T, allow string, local ...string) *Policy {
	t.Helper()
	prefixes, err := ParseAllowList(allow)
	if err != nil {
		t.Fatal(err)
	}
	p := New(prefixes)
	p.LocalAddrs = func() ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(local))
		for _, l := range local {
			out = append(out, netip.MustParseAddr(l))
		}
		return out, nil
	}
	return p
}

func TestCheckAddrDefaults(t *testing.T) {
	p := newTestPolicy(t, "", "198.51.100.7", "2001:db8:aaaa::7")
	cases := []struct {
		addr  string
		allow bool
	}{
		// Public addresses.
		{"8.8.8.8", true},
		{"192.0.2.10", true}, // TEST-NET-1 is not in the denied list
		{"2606:4700::1111", true},
		{"2001:db8::1", true},

		// IPv4 denials.
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"10.1.2.3", false},
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"127.0.0.1", false},
		{"127.255.255.255", false},
		{"169.254.169.254", false}, // cloud metadata
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"172.32.0.1", true},
		{"192.168.1.1", false},
		{"224.0.0.1", false},
		{"239.255.255.255", false},
		{"255.255.255.255", false}, // broadcast
		{"240.0.0.1", false},
		{"100.128.0.1", true}, // just past CGNAT

		// IPv6 denials.
		{"::", false},
		{"::1", false},
		{"fe80::1", false},
		{"fe80::1%en0", false},
		{"fec0::1", false},
		{"ff02::1", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"::127.0.0.1", false}, // IPv4-compatible
		{"64:ff9b:1::1", false},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false}, // Teredo
		{"100::1", false},

		// Embedded IPv4.
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:8.8.8.8", true},
		{"64:ff9b::7f00:1", false},    // NAT64 of 127.0.0.1
		{"64:ff9b::a9fe:a9fe", false}, // NAT64 of 169.254.169.254
		{"64:ff9b::808:808", true},    // NAT64 of 8.8.8.8
		{"2002:7f00:1::1", false},     // 6to4 of 127.0.0.1
		{"2002:c0a8:101::1", false},   // 6to4 of 192.168.1.1
		{"2002:808:808::1", true},     // 6to4 of 8.8.8.8

		// The registrar's own interfaces.
		{"198.51.100.7", false},
		{"::ffff:198.51.100.7", false},
		{"2001:db8:aaaa::7", false},
		{"198.51.100.8", true},
	}
	for _, tc := range cases {
		err := p.CheckAddr(netip.MustParseAddr(tc.addr))
		if tc.allow && err != nil {
			t.Errorf("%s: denied (%v), want allowed", tc.addr, err)
		}
		if !tc.allow {
			if err == nil {
				t.Errorf("%s: allowed, want denied", tc.addr)
			} else if !errors.Is(err, ErrDenied) {
				t.Errorf("%s: error %v does not match ErrDenied", tc.addr, err)
			}
		}
	}
}

func TestAllowListOverrides(t *testing.T) {
	p := newTestPolicy(t, "127.0.0.0/8, 10.20.0.0/16 fd00::/8", "127.0.0.1")
	for _, a := range []string{"127.0.0.1", "::ffff:127.0.0.1", "10.20.3.4", "64:ff9b::a14:304", "fd00::5"} {
		if err := p.CheckAddr(netip.MustParseAddr(a)); err != nil {
			t.Errorf("%s: %v, want allowed by the allow list", a, err)
		}
	}
	for _, a := range []string{"10.21.0.1", "169.254.169.254", "::1", "fc00::1"} {
		if err := p.CheckAddr(netip.MustParseAddr(a)); err == nil {
			t.Errorf("%s: allowed, want denied", a)
		}
	}
}

func TestParseAllowList(t *testing.T) {
	got, err := ParseAllowList("10.0.0.0/8,192.0.2.1 ::1\n10.1.2.3/8")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.1/32", "::1/128", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := ParseAllowList("not-a-cidr"); err == nil {
		t.Error("garbage parsed")
	}
}

// Control is the dial-time hook: it must refuse a denied concrete address,
// including one a name was resolved to.
func TestControl(t *testing.T) {
	p := newTestPolicy(t, "")
	if err := p.Control("tcp", "127.0.0.1:9618", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("loopback: %v, want denied", err)
	}
	if err := p.Control("tcp6", "[fe80::1%lo0]:9618", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("link-local with zone: %v, want denied", err)
	}
	if err := p.Control("tcp", "8.8.8.8:9618", nil); err != nil {
		t.Errorf("public: %v", err)
	}
	if err := p.Control("tcp", "not-an-ip:1", nil); err == nil {
		t.Error("a non-literal dial address was accepted")
	}
}

// The hook works in a real net.Dialer: a loopback listener is unreachable
// through it unless allow-listed.
func TestControlInDialer(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	d := net.Dialer{Control: newTestPolicy(t, "").Control}
	if c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		_ = c.Close()
		t.Fatal("dial to loopback succeeded through the hook")
	} else if !errors.Is(err, ErrDenied) {
		t.Fatalf("dial error %v does not match ErrDenied", err)
	}

	d = net.Dialer{Control: newTestPolicy(t, "127.0.0.0/8").Control}
	c, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("allow-listed dial: %v", err)
	}
	_ = c.Close()
}

func TestCheckSinful(t *testing.T) {
	p := newTestPolicy(t, "")
	cases := []struct {
		name, sinful, dial, errHas string
	}{
		{name: "public IP with shared port",
			sinful: "<192.0.2.10:9619?addrs=192.0.2.10-9619&sock=htc_registrationd>",
			dial:   "<192.0.2.10:9619?addrs=192.0.2.10-9619&sock=htc_registrationd>"},
		// Host names are left for cedar to resolve; the dial hook checks the
		// addresses they resolve to.
		{name: "host name is not resolved",
			sinful: "<ce.example.edu:9619?sock=htc_registrationd>",
			dial:   "<ce.example.edu:9619?sock=htc_registrationd>"},
		{name: "name resolving to loopback is left to the dial hook",
			sinful: "<localhost:9619>",
			dial:   "<localhost:9619>"},
		{name: "ipv6 literal",
			sinful: "<[2001:db8::11]:9619>",
			dial:   "<[2001:db8::11]:9619>"},
		{name: "bare host:port",
			sinful: "192.0.2.10:9618",
			dial:   "<192.0.2.10:9618>"},
		{name: "loopback literal", sinful: "<127.0.0.1:9619>", errHas: "loopback"},
		{name: "metadata service literal", sinful: "<169.254.169.254:80>", errHas: "link-local"},
		{name: "private addrs entry", sinful: "<192.0.2.10:9619?addrs=192.0.2.10-9619+10.0.0.1-9619>", errHas: "RFC 1918"},
		{name: "ipv6 loopback addrs entry", sinful: "<192.0.2.10:9619?addrs=[::1]-9619>", errHas: "loopback"},
		{name: "CCB contact", sinful: "<10.0.0.5:9619?CCBID=192.0.2.1:9618#42&sock=x>", errHas: "CCB"},
		{name: "lower-case ccbid", sinful: "<192.0.2.10:9619?ccbid=192.0.2.1:9618#42>", errHas: "CCB"},
		{name: "private network part", sinful: "<192.0.2.10:9619?PrivNet=site&PrivAddr=%3c10.0.0.5:9619%3e>", errHas: "private-network"},
		{name: "no port", sinful: "<192.0.2.10>", errHas: "host:port"},
		{name: "zero port", sinful: "<192.0.2.10:0>", errHas: "bad port"},
		{name: "bad sock", sinful: "<192.0.2.10:9619?sock=../../x>", errHas: "shared-port"},
		{name: "mapped loopback literal", sinful: "<[::ffff:127.0.0.1]:9619>", errHas: "loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := p.CheckSinful(tc.sinful)
			if tc.errHas != "" {
				if err == nil {
					t.Fatalf("accepted (dial %s), want error containing %q", tgt.Dial, tc.errHas)
				}
				if !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("error %q does not contain %q", err, tc.errHas)
				}
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("error %v does not match ErrDenied", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tgt.Dial != tc.dial {
				t.Fatalf("dial %q, want %q", tgt.Dial, tc.dial)
			}
		})
	}
}

func TestCheckSinfulAllowListedLoopback(t *testing.T) {
	p := newTestPolicy(t, "127.0.0.0/8", "127.0.0.1")
	tgt, err := p.CheckSinful("<127.0.0.1:4242>")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Dial != "<127.0.0.1:4242>" {
		t.Fatalf("dial %q", tgt.Dial)
	}
}

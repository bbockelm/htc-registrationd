// Package ssrf decides which addresses the registrar may dial for a
// callback-mode registration.
//
// The registrar dials an address an unauthenticated client chose, so the
// decision is made on the concrete IP being connected, never on a name: a DNS
// entry for a public-looking host can point at 127.0.0.1. Policy.Control has
// the net.Dialer.Control signature so it can run at dial time, after
// resolution, on the very address the socket connects to; that also defeats
// DNS rebinding between a pre-check and the connect.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/addresses"
)

// DeniedError reports an address the policy refuses.
type DeniedError struct {
	Addr   netip.Addr
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("callback address %s is not allowed: %s", e.Addr, e.Reason)
}

// ErrDenied matches every *DeniedError with errors.Is.
var ErrDenied = errors.New("callback address denied")

// Is lets errors.Is(err, ErrDenied) match.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

type deniedRange struct {
	prefix netip.Prefix
	reason string
}

func mustRanges(spec ...string) []deniedRange {
	out := make([]deniedRange, 0, len(spec)/2)
	for i := 0; i < len(spec); i += 2 {
		out = append(out, deniedRange{netip.MustParsePrefix(spec[i]), spec[i+1]})
	}
	return out
}

// deniedV4 are the IPv4 ranges denied by default. 240.0.0.0/4 (reserved)
// includes the limited broadcast address 255.255.255.255.
var deniedV4 = mustRanges(
	"0.0.0.0/8", "this-network (0.0.0.0/8)",
	"10.0.0.0/8", "private (RFC 1918)",
	"100.64.0.0/10", "carrier-grade NAT (RFC 6598)",
	"127.0.0.0/8", "loopback",
	"169.254.0.0/16", "link-local",
	"172.16.0.0/12", "private (RFC 1918)",
	"192.168.0.0/16", "private (RFC 1918)",
	"224.0.0.0/4", "multicast",
	"240.0.0.0/4", "reserved / broadcast",
)

// deniedV6 are the IPv6 ranges denied by default. ::/96 (deprecated
// IPv4-compatible addresses, which also covers :: and ::1), the local-use
// NAT64 prefix and Teredo are refused outright; ::ffff:0:0/96, 64:ff9b::/96
// and 2002::/16 embed an IPv4 address that is checked on its own instead.
var deniedV6 = mustRanges(
	"::/128", "unspecified",
	"::1/128", "loopback",
	"::/96", "IPv4-compatible (deprecated)",
	"100::/64", "discard-only (RFC 6666)",
	"64:ff9b:1::/48", "local-use NAT64 (RFC 8215)",
	"2001::/32", "Teredo",
	"fc00::/7", "unique local (ULA)",
	"fe80::/10", "link-local",
	"fec0::/10", "site-local (deprecated)",
	"ff00::/8", "multicast",
)

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// Resolver resolves host names; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy is the callback-address policy. The zero value is not usable; build
// one with New.
type Policy struct {
	allow []netip.Prefix

	// LocalAddrs returns this host's own interface addresses, every one of
	// which is denied. Replaceable for tests.
	LocalAddrs func() ([]netip.Addr, error)
	// Resolver resolves sinful host names in CheckSinful. Defaults to
	// net.DefaultResolver.
	Resolver Resolver

	mu        sync.Mutex
	local     []netip.Addr
	localTime time.Time
}

// localTTL bounds how stale the cached interface address list may be.
const localTTL = 30 * time.Second

// New returns a policy that re-allows the given prefixes
// (HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS).
func New(allow []netip.Prefix) *Policy {
	return &Policy{
		allow:      allow,
		LocalAddrs: InterfaceAddrs,
		Resolver:   net.DefaultResolver,
	}
}

// ParseAllowList parses a comma- or space-separated list of CIDR prefixes or
// bare addresses (taken as single-host prefixes).
func ParseAllowList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("allow-list entry %q: %w", f, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("allow-list entry %q: %w", f, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// InterfaceAddrs returns the addresses of every local network interface.
func InterfaceAddrs() ([]netip.Addr, error) {
	ifas, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ifas))
	for _, ifa := range ifas {
		var ip net.IP
		switch v := ifa.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// embeddedV4 returns the IPv4 address an IPv6 address carries in its
// IPv4-mapped, NAT64 (64:ff9b::/96) or 6to4 (2002::/16) form.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	if a.Is4In6() {
		return a.Unmap(), true
	}
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	if nat64WellKnown.Contains(a) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	if sixToFour.Contains(a) {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

func (p *Policy) allowed(a netip.Addr) bool {
	for _, pr := range p.allow {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

func (p *Policy) localAddrs() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local != nil && time.Since(p.localTime) < localTTL {
		return p.local
	}
	if p.LocalAddrs == nil {
		return nil
	}
	addrs, err := p.LocalAddrs()
	if err != nil {
		// Keep the previous list rather than silently dropping the check.
		return p.local
	}
	p.local, p.localTime = addrs, time.Now()
	return p.local
}

func denyReason(a netip.Addr, local []netip.Addr) string {
	ranges := deniedV6
	if a.Is4() {
		ranges = deniedV4
	}
	for _, r := range ranges {
		if r.prefix.Contains(a) {
			return r.reason
		}
	}
	for _, l := range local {
		if l == a {
			return "an address of the registrar's own interfaces"
		}
	}
	return ""
}

// CheckAddr reports whether the registrar may connect to a. The allow list
// wins over every default denial, including the registrar's own addresses.
func (p *Policy) CheckAddr(a netip.Addr) error {
	if !a.IsValid() {
		return &DeniedError{Addr: a, Reason: "invalid address"}
	}
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	v4, embedded := embeddedV4(a)
	if p.allowed(a) || (embedded && p.allowed(v4)) {
		return nil
	}
	local := p.localAddrs()
	if r := denyReason(a, local); r != "" {
		return &DeniedError{Addr: a, Reason: r}
	}
	if embedded {
		if r := denyReason(v4, local); r != "" {
			return &DeniedError{Addr: a, Reason: fmt.Sprintf("embeds %s, %s", v4, r)}
		}
	}
	return nil
}

// Control has the net.Dialer.Control signature: it refuses the connect when
// the concrete remote address fails CheckAddr. It runs after resolution, so a
// name that resolves (or is rebound) to a denied address is caught here.
func (p *Policy) Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf: dial address %q: %w", address, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("ssrf: dial address %q is not an IP literal: %w", address, err)
	}
	return p.CheckAddr(a)
}

// Target is a sinful that passed CheckSinful.
type Target struct {
	// Dial is the sinful to hand to cedar. Its host is the checked IP literal
	// (with the original sock id, if any), so cedar connects to exactly the
	// address that was checked and does not resolve the name again.
	Dial string
	// Host is the host portion of the original sinful.
	Host string
	// Checked lists every address that was checked: the primary host's
	// resolved addresses and every addrs= entry.
	Checked []netip.Addr
}

// SinfulError reports a sinful refused for its form rather than its address.
type SinfulError struct{ Reason string }

func (e *SinfulError) Error() string { return "callback address refused: " + e.Reason }

// Is lets errors.Is(err, ErrDenied) match.
func (e *SinfulError) Is(target error) bool { return target == ErrDenied }

// CheckSinful validates a callback sinful before dialing: it rejects CCB contacts and private-network parts, checks every addrs=
// entry, resolves a host name and checks every address it resolves to, and
// returns a Target pinned to a checked IP.
func (p *Policy) CheckSinful(ctx context.Context, raw string) (*Target, error) {
	info, err := addresses.ParseSinful(raw)
	if err != nil {
		return nil, &SinfulError{Reason: fmt.Sprintf("unparseable sinful: %v", err)}
	}
	if info.IsCCB() || info.Params["CCBID"] != "" {
		return nil, &SinfulError{Reason: "the address is a CCB contact; a CE reachable only through CCB must use approval mode"}
	}
	if info.PrivateAddr != "" || info.PrivateNet != "" {
		return nil, &SinfulError{Reason: "the address has a private-network part; use approval mode"}
	}
	if info.Host == "" || info.Port == "" {
		return nil, &SinfulError{Reason: "the address has no host:port"}
	}
	port, err := strconv.ParseUint(info.Port, 10, 16)
	if err != nil || port == 0 {
		return nil, &SinfulError{Reason: fmt.Sprintf("bad port %q", info.Port)}
	}
	if info.SharedPortID != "" && !addresses.IsValidSharedPortID(info.SharedPortID) {
		return nil, &SinfulError{Reason: fmt.Sprintf("bad shared-port id %q", info.SharedPortID)}
	}

	t := &Target{Host: info.Host}
	for _, entry := range info.Addrs {
		a, err := parseAddrsEntry(entry)
		if err != nil {
			return nil, &SinfulError{Reason: err.Error()}
		}
		if err := p.CheckAddr(a); err != nil {
			return nil, err
		}
		t.Checked = append(t.Checked, a)
	}

	host := strings.TrimSuffix(strings.TrimPrefix(info.Host, "["), "]")
	var primary []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		primary = []netip.Addr{a}
	} else {
		res := p.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		primary, err = res.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, &SinfulError{Reason: fmt.Sprintf("resolving %s: %v", host, err)}
		}
		if len(primary) == 0 {
			return nil, &SinfulError{Reason: fmt.Sprintf("%s resolves to no address", host)}
		}
	}
	// Every resolved address must pass: a name that resolves to a public and a
	// loopback address is not one to dial.
	for _, a := range primary {
		if err := p.CheckAddr(a); err != nil {
			return nil, err
		}
		t.Checked = append(t.Checked, a)
	}
	pin := primary[0].WithZone("")
	if pin.Is4In6() {
		pin = pin.Unmap()
	}
	dial := netip.AddrPortFrom(pin, uint16(port)).String()
	if info.SharedPortID != "" {
		dial += "?sock=" + info.SharedPortID
	}
	t.Dial = "<" + dial + ">"
	return t, nil
}

// parseAddrsEntry parses one entry of a sinful's addrs= list: "a.b.c.d-port"
// or "[v6]-port".
func parseAddrsEntry(entry string) (netip.Addr, error) {
	i := strings.LastIndexByte(entry, '-')
	if i <= 0 {
		return netip.Addr{}, fmt.Errorf("bad addrs entry %q", entry)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(entry[:i], "["), "]")
	if _, err := strconv.ParseUint(entry[i+1:], 10, 16); err != nil {
		return netip.Addr{}, fmt.Errorf("bad port in addrs entry %q", entry)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bad address in addrs entry %q: %w", entry, err)
	}
	return a, nil
}

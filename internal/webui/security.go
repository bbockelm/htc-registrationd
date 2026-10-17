package webui

import (
	"container/list"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// contentSecurityPolicy allows the page's own stylesheet and nothing else:
// no script, no frames, forms submitting only to this origin (and, since
// form-action also governs redirects, never redirected elsewhere: see
// requireLogin).
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// withHeaders sets the security headers on every response.
func withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		// The user code travels in the URL, so no other origin is sent a
		// Referer. Not no-referrer: under it a browser sends "Origin: null"
		// with every form POST, which sameOrigin refuses.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// DefaultTrustedProxies are the reverse proxies whose X-Forwarded-For is
// read when HTC_REGISTRATIOND_TRUSTED_PROXIES is not set.
var DefaultTrustedProxies = []string{"127.0.0.1", "::1"}

// parseProxies reads addresses and CIDR prefixes.
func parseProxies(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, v := range list {
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("HTC_REGISTRATIOND_TRUSTED_PROXIES: %q is not an address or prefix", v)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trustedProxy(a netip.Addr, proxies []netip.Prefix) bool {
	for _, p := range proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address requests are rate-limited by. On the plain-HTTP
// listener, when the connection comes from a trusted proxy, it is the
// nearest X-Forwarded-For hop that is not itself a trusted proxy; the
// header is never used for anything else, and never on the HTTPS
// listener.
func clientIP(r *http.Request, proxies []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	client := peer.WithZone("").Unmap()
	if r.TLS != nil || !trustedProxy(client, proxies) {
		return client.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = a.WithZone("").Unmap()
		if !trustedProxy(client, proxies) {
			break
		}
	}
	return client.String()
}

func (s *Server) clientIP(r *http.Request) string { return clientIP(r, s.cfg.TrustedProxies) }

// ipLimiter is a token bucket per client network: the address for IPv4,
// its /64 for IPv6, since one host commonly holds a whole /64.
type ipLimiter struct {
	limit rate.Limit
	burst int
	now   func() time.Time
	max   int

	mu      sync.Mutex
	clients map[string]*list.Element
	// lru holds *limiterEntry, least recently seen first.
	lru *list.List
}

type limiterEntry struct {
	key string
	l   *rate.Limiter
}

// maxLimiterClients bounds the limiter's memory; when it is full the
// least recently seen network is forgotten.
const maxLimiterClients = 10000

func newIPLimiter(perMinute, burst int, now func() time.Time) *ipLimiter {
	return &ipLimiter{
		limit:   rate.Limit(float64(perMinute) / 60),
		burst:   burst,
		now:     now,
		max:     maxLimiterClients,
		clients: map[string]*list.Element{},
		lru:     list.New(),
	}
}

// limiterKey is the network ip is limited as: the address for IPv4
// (including IPv4-mapped IPv6), the /64 for IPv6. Anything else is used
// as it is.
func limiterKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

func (l *ipLimiter) allow(ip string) bool {
	key := limiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	el := l.clients[key]
	if el == nil {
		for l.lru.Len() >= l.max {
			oldest := l.lru.Front()
			l.lru.Remove(oldest)
			delete(l.clients, oldest.Value.(*limiterEntry).key)
		}
		el = l.lru.PushBack(&limiterEntry{key: key, l: rate.NewLimiter(l.limit, l.burst)})
		l.clients[key] = el
	} else {
		l.lru.MoveToBack(el)
	}
	return el.Value.(*limiterEntry).l.AllowN(l.now(), 1)
}

// safeNext reports whether next is a same-origin path to return to after
// login: an absolute path, not a scheme-relative or backslash form a
// browser might read as another host, with no control characters.
func safeNext(next string) bool {
	if next == "" || len(next) > 2048 || next[0] != '/' || strings.HasPrefix(next, "//") {
		return false
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	u, err := url.Parse(next)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}

// sameOrigin checks a state-changing request's Origin (when the browser
// sends one) against the public URL's canonical origin.
func sameOrigin(r *http.Request, origin string) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == origin
}

// csrfOK checks the form's CSRF token against the session's.
func csrfOK(r *http.Request, sess *session) bool {
	tok := r.PostFormValue("csrf")
	return tok != "" && sess != nil && secret.Equal(tok, sess.CSRF)
}

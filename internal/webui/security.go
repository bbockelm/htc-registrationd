package webui

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// contentSecurityPolicy allows the page's own stylesheet and nothing else:
// no script, no frames, forms posting only to this origin.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// withHeaders sets the security headers on every response.
func withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		// The user code travels in the URL.
		h.Set("Referrer-Policy", "no-referrer")
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

// clientIP is the address requests are rate-limited by. On the plain-HTTP
// listener, which accepts only loopback connections from a reverse proxy,
// it is the last X-Forwarded-For entry (the one the proxy added); the
// header is never used for anything else, and never on the HTTPS listener.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if r.TLS == nil && ip != nil && ip.IsLoopback() {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); fwd != nil {
				return fwd.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

// ipLimiter is a token bucket per client address.
type ipLimiter struct {
	limit rate.Limit
	burst int
	now   func() time.Time

	mu      sync.Mutex
	clients map[string]*limiterEntry
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// maxLimiterClients bounds the limiter's memory; idle entries are dropped
// first.
const maxLimiterClients = 10000

func newIPLimiter(perMinute, burst int, now func() time.Time) *ipLimiter {
	return &ipLimiter{
		limit:   rate.Limit(float64(perMinute) / 60),
		burst:   burst,
		now:     now,
		clients: map[string]*limiterEntry{},
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.clients[ip]
	if e == nil {
		if len(l.clients) >= maxLimiterClients {
			for k, v := range l.clients {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(l.clients, k)
				}
			}
			if len(l.clients) >= maxLimiterClients {
				l.clients = map[string]*limiterEntry{}
			}
		}
		e = &limiterEntry{l: rate.NewLimiter(l.limit, l.burst)}
		l.clients[ip] = e
	}
	e.seen = now
	return e.l.AllowN(now, 1)
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
// sends one) against the public URL.
func sameOrigin(r *http.Request, origin string) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == origin
}

// csrfOK checks the form's CSRF token against the session's.
func csrfOK(r *http.Request, sess *session) bool {
	tok := r.PostFormValue("csrf")
	return tok != "" && sess != nil && secret.Equal(tok, sess.CSRF)
}

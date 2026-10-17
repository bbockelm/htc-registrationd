package webui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/htc-registrationd/internal/authz"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// maxFormBytes caps a POSTed form.
const maxFormBytes = 16 << 10

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /static/style.css", serveStyle)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/approve", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /login", s.limit(s.loginLimit, s.handleLogin))
	mux.HandleFunc("GET /oidc/callback", s.limit(s.loginLimit, s.handleCallback))
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /approve", s.limit(s.approveLimit, s.handleApprovePage))
	mux.HandleFunc("POST /approve", s.limit(s.approveLimit, s.handleApproveDecision))
	mux.HandleFunc("GET /registrations", s.handleRegistrations)
	mux.HandleFunc("POST /registrations/revoke", s.handleRevoke)
	return s.withSession(mux)
}

func (s *Server) limit(l *ipLimiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			s.message(w, r, http.StatusTooManyRequests, "Too many requests", "Wait a minute and try again.")
			return
		}
		h(w, r)
	}
}

// Cookies. With an https public URL they are Secure and carry the __Host-
// prefix, which also pins them to this host and path /.
const (
	sessionCookie = "hrd_session"
	loginCookie   = "hrd_login"
)

func (s *Server) cookieName(base string) string {
	if s.secure {
		return "__Host-" + base
	}
	return base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	//nolint:gosec // Secure follows the public URL's scheme: always set for https, impossible for a loopback http URL.
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return c.Value
}

type sessionKey struct{}

type sessionRef struct {
	id   string
	sess *session
}

// withSession loads the request's session, if any, into its context.
func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := s.cookie(r, sessionCookie); id != "" {
			sess, err := s.sessions.get(r.Context(), id)
			switch {
			case err == nil:
				r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, &sessionRef{id: id, sess: sess}))
			case errors.Is(err, errNoSession):
				s.setCookie(w, sessionCookie, "", -1)
			default:
				s.log.Error("webui: reading session", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func currentSession(r *http.Request) *sessionRef {
	ref, _ := r.Context().Value(sessionKey{}).(*sessionRef)
	return ref
}

func (s *Server) base(r *http.Request, title string) base {
	b := base{Title: title}
	if ref := currentSession(r); ref != nil {
		b.User, b.CSRF, b.IsAdmin = ref.sess, ref.sess.CSRF, s.cfg.Authz.IsAdmin(ref.sess.Principal)
		b.UserName = ref.sess.Principal
		if name, ok := s.cfg.Authz.ConfigName(ref.sess.Principal); ok {
			b.UserName = name
		}
	}
	return b
}

func approver(sess *session) registrar.Identity {
	return registrar.Identity{Kind: authz.IdentityKind, Principal: sess.Principal}
}

// requireLogin returns the session, or redirects to login (GET) or refuses
// (POST) and returns nil.
func (s *Server) requireLogin(w http.ResponseWriter, r *http.Request) *session {
	if ref := currentSession(r); ref != nil {
		return ref.sess
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil
	}
	s.message(w, r, http.StatusForbidden, "Signed out", "Your session has ended. Sign in and try again.")
	return nil
}

// checkPost parses a POSTed form and verifies its origin and CSRF token.
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request, sess *session) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.message(w, r, http.StatusBadRequest, "Bad request", "The form could not be read.")
		return false
	}
	if !sameOrigin(r, s.origin) || !csrfOK(r, sess) {
		s.message(w, r, http.StatusForbidden, "Request refused", "The form did not come from this page. Reload the page and try again.")
		return false
	}
	return true
}

func (s *Server) redirectURL() string { return s.cfg.PublicURL + "/oidc/callback" }

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !safeNext(next) {
		next = "/approve"
	}
	ep, err := s.oidc.endpoints(r.Context())
	if err != nil {
		s.log.Error("webui: OIDC provider unavailable", "err", err)
		s.message(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "The identity provider cannot be reached. Try again later.")
		return
	}
	state, err := secret.NewSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	s.logins.save(state, verifier, next)
	// The state is bound to this browser: the callback must present it
	// both in the URL and in this cookie.
	s.setCookie(w, loginCookie, state, int(loginTTL/time.Second))
	authURL := s.oidc.oauth2Config(ep, s.redirectURL()).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	bound := s.cookie(r, loginCookie)
	s.setCookie(w, loginCookie, "", -1)
	if e := q.Get("error"); e != "" {
		s.log.Warn("webui: identity provider refused the login", "error", e, "description", q.Get("error_description"))
		s.message(w, r, http.StatusUnauthorized, "Sign-in failed", "The identity provider did not sign you in.")
		return
	}
	if state == "" || code == "" || bound == "" || !secret.Equal(state, bound) {
		s.log.Warn("webui: login callback with a missing or mismatched state", "client", clientIP(r))
		s.message(w, r, http.StatusBadRequest, "Sign-in failed", "This sign-in did not start in this browser, or took too long. Start again.")
		return
	}
	verifier, next, ok := s.logins.take(state)
	if !ok {
		s.message(w, r, http.StatusBadRequest, "Sign-in failed", "This sign-in expired or was already used. Start again.")
		return
	}
	ep, err := s.oidc.endpoints(r.Context())
	if err != nil {
		s.message(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "The identity provider cannot be reached. Try again later.")
		return
	}
	tok, err := s.oidc.exchange(r.Context(), ep, s.redirectURL(), code, verifier)
	if err != nil {
		s.log.Warn("webui: authorization code exchange failed", "err", err)
		s.message(w, r, http.StatusBadGateway, "Sign-in failed", "The identity provider did not confirm the sign-in. Start again.")
		return
	}
	id, err := s.oidc.userInfo(r.Context(), ep, tok)
	if err != nil {
		s.log.Warn("webui: reading the user's identity failed", "err", err)
		s.message(w, r, http.StatusForbidden, "Sign-in failed", "The identity provider did not supply the identity this registrar requires.")
		return
	}
	if old := currentSession(r); old != nil {
		_ = s.sessions.remove(r.Context(), old.id)
	}
	sid, _, err := s.sessions.create(r.Context(), id.Principal, truncate(id.Display, 200))
	if err != nil {
		s.log.Error("webui: creating session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, sessionCookie, sid, 0)
	s.log.Info("webui: signed in", "principal", id.Principal, "client", clientIP(r))
	if !safeNext(next) {
		next = "/approve"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ref := currentSession(r)
	if ref == nil {
		s.message(w, r, http.StatusOK, "Signed out", "You are signed out.")
		return
	}
	if !s.checkPost(w, r, ref.sess) {
		return
	}
	_ = s.sessions.remove(r.Context(), ref.id)
	s.setCookie(w, sessionCookie, "", -1)
	r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, (*sessionRef)(nil)))
	s.message(w, r, http.StatusOK, "Signed out", "You are signed out.")
}

// enterCodePage asks for a user code.
type enterCodePage struct {
	base
	Code  string
	Error string
}

// approvePage confirms one request.
type approvePage struct {
	base
	Req      *registrar.RequestRecord
	RDNS     string
	Decision authz.Decision
	// Unavailable is set when authorization could not be checked.
	Unavailable bool
}

// validCode reports whether code has the XXXX-XXXX shape of a user code.
func validCode(code string) bool {
	if len(code) != 9 || code[4] != '-' {
		return false
	}
	for i, c := range code {
		if i != 4 && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// lookupRequest finds the approval request with code, or renders the page
// that explains why there is none to act on and returns nil.
func (s *Server) lookupRequest(w http.ResponseWriter, r *http.Request, sess *session, code string) *registrar.RequestRecord {
	rec, err := s.cfg.Store.RequestByUserCode(r.Context(), code)
	if errors.Is(err, registrar.ErrNotFound) || (err == nil && rec.Method != protocol.MethodApproval) {
		s.message(w, r, http.StatusNotFound, "Unknown code", "No request has the code "+code+". Check the code shown on your CE.")
		return nil
	}
	if err != nil {
		s.log.Error("webui: looking up a request", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}
	now := s.cfg.Now()
	by := ""
	if rec.DecidedBy == approver(sess).String() {
		by = " by you"
	}
	switch {
	case rec.Status == registrar.ReqPending && now.Before(rec.ExpiresAt):
		return rec
	case rec.Status == registrar.ReqPending, rec.Status == registrar.ReqExpired:
		s.message(w, r, http.StatusGone, "Request expired",
			"The request from "+rec.Name+" with code "+code+" expired at "+utc(rec.ExpiresAt)+".")
	case rec.Status == registrar.ReqApproved:
		s.message(w, r, http.StatusOK, "Request approved",
			"The request from "+rec.Name+" was approved"+by+" at "+utc(rec.DecidedAt)+". The CE has not collected its token yet.")
	case rec.Status == registrar.ReqClaimed:
		s.message(w, r, http.StatusOK, "Request approved",
			"The request from "+rec.Name+" was approved"+by+" at "+utc(rec.DecidedAt)+". The CE has collected its token.")
	case rec.Status == registrar.ReqDenied:
		s.message(w, r, http.StatusOK, "Request denied",
			"The request from "+rec.Name+" was denied"+by+" at "+utc(rec.DecidedAt)+".")
	default:
		s.message(w, r, http.StatusConflict, "Request closed", "The request from "+rec.Name+" is "+rec.Status+".")
	}
	return nil
}

func utc(t time.Time) string {
	if t.IsZero() {
		return "an unknown time"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) handleApprovePage(w http.ResponseWriter, r *http.Request) {
	sess := s.requireLogin(w, r)
	if sess == nil {
		return
	}
	raw := r.URL.Query().Get("code")
	if strings.TrimSpace(raw) == "" {
		s.render(w, http.StatusOK, "enter_code", enterCodePage{base: s.base(r, "Enter a code")})
		return
	}
	code := registrar.NormalizeUserCode(raw)
	if !validCode(code) {
		s.render(w, http.StatusBadRequest, "enter_code", enterCodePage{base: s.base(r, "Enter a code"),
			Code: raw, Error: "A code has eight letters, like BCDF-GHJK."})
		return
	}
	rec := s.lookupRequest(w, r, sess, code)
	if rec == nil {
		return
	}
	page := approvePage{base: s.base(r, "Approve "+rec.Name), Req: rec, RDNS: s.reverseDNS(r.Context(), rec.SourceIP)}
	d, err := s.cfg.Authz.Decide(r.Context(), sess.Principal, rec.Name)
	if err != nil {
		s.log.Error("webui: authorization check failed", "principal", sess.Principal, "name", rec.Name, "err", err)
		page.Unavailable = true
	} else {
		page.Decision = d
	}
	s.render(w, http.StatusOK, "approve", page)
}

func (s *Server) handleApproveDecision(w http.ResponseWriter, r *http.Request) {
	sess := s.requireLogin(w, r)
	if sess == nil || !s.checkPost(w, r, sess) {
		return
	}
	code := registrar.NormalizeUserCode(r.PostFormValue("code"))
	approve := r.PostFormValue("decision") == "approve"
	if !validCode(code) || (!approve && r.PostFormValue("decision") != "deny") {
		s.message(w, r, http.StatusBadRequest, "Bad request", "The form could not be read.")
		return
	}
	rec := s.lookupRequest(w, r, sess, code)
	if rec == nil {
		return
	}
	d, err := s.cfg.Authz.Decide(r.Context(), sess.Principal, rec.Name)
	if err != nil {
		s.log.Error("webui: authorization check failed", "principal", sess.Principal, "name", rec.Name, "err", err)
		s.message(w, r, http.StatusServiceUnavailable, "Authorization unavailable",
			"Your authorization for "+rec.Name+" could not be checked. Nothing was changed. Try again later.")
		return
	}
	if !d.Allowed {
		s.log.Warn("webui: unauthorized decision refused", "principal", sess.Principal, "name", rec.Name,
			"code", code, "authorization", d.Audit(), "client", clientIP(r))
		s.message(w, r, http.StatusForbidden, "Not authorized", "You are not authorized to approve "+rec.Name+". "+d.Reason)
		return
	}
	who := approver(sess)
	if err := s.cfg.Store.Decide(r.Context(), rec.Number, approve, who, d.Audit()); err != nil {
		if errors.Is(err, registrar.ErrNotPending) {
			http.Redirect(w, r, "/approve?code="+url.QueryEscape(code), http.StatusSeeOther)
			return
		}
		s.log.Error("webui: recording a decision", "request", rec.Number, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verb := "denied"
	if approve {
		verb = "approved"
	}
	s.log.Info("registrar: request "+verb+" in the web UI", "request", rec.Number, "name", rec.Name, "code", code,
		"by", who.String(), "authorization", d.Audit(), "client", clientIP(r))
	http.Redirect(w, r, "/approve?code="+url.QueryEscape(code), http.StatusSeeOther)
}

// reverseDNS names addr's PTR records and whether they resolve back to it.
func (s *Server) reverseDNS(ctx context.Context, addr string) string {
	if addr == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := s.cfg.Resolver.LookupAddr(ctx, addr)
	if err != nil || len(names) == 0 {
		return "no reverse DNS"
	}
	name := strings.TrimSuffix(names[0], ".")
	addrs, err := s.cfg.Resolver.LookupHost(ctx, name)
	if err == nil && slices.Contains(addrs, addr) {
		return name + ", which resolves back to this address"
	}
	return name + ", which does not resolve back to this address"
}

// registrationsPage lists registrations.
type registrationsPage struct {
	base
	Rows    []regRow
	Revoked *registrar.RegistrationRecord
}

type regRow struct {
	Reg       *registrar.RegistrationRecord
	Approver  string
	CanRevoke bool
}

// visible reports whether sess may see (and so revoke) reg: administrators
// see every registration, others the ones they approved or are authorized
// for.
func (s *Server) visible(ctx context.Context, sess *session, admin bool, reg *registrar.RegistrationRecord) bool {
	if admin || reg.Approver == approver(sess).String() {
		return true
	}
	d, err := s.cfg.Authz.Decide(ctx, sess.Principal, reg.Name)
	return err == nil && d.Allowed
}

func approverText(a string) string {
	if a == "" {
		return "—"
	}
	id := registrar.ParseIdentity(a)
	switch id.Kind {
	case authz.IdentityKind:
		return id.Principal
	case "cedar":
		return id.Principal + " (command line)"
	}
	return a
}

func (s *Server) handleRegistrations(w http.ResponseWriter, r *http.Request) {
	sess := s.requireLogin(w, r)
	if sess == nil {
		return
	}
	regs, err := s.cfg.Store.ListRegistrations(r.Context())
	if err != nil {
		s.log.Error("webui: listing registrations", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	admin := s.cfg.Authz.IsAdmin(sess.Principal)
	page := registrationsPage{base: s.base(r, "Registrations")}
	for _, reg := range regs {
		if !s.visible(r.Context(), sess, admin, reg) {
			continue
		}
		page.Rows = append(page.Rows, regRow{Reg: reg, Approver: approverText(reg.Approver),
			CanRevoke: reg.Status != registrar.RegRevoked})
	}
	if id := r.URL.Query().Get("revoked"); id != "" {
		if reg, err := s.cfg.Store.Registration(r.Context(), id); err == nil && reg.Status == registrar.RegRevoked &&
			s.visible(r.Context(), sess, admin, reg) {
			page.Revoked = reg
		}
	}
	s.render(w, http.StatusOK, "registrations", page)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sess := s.requireLogin(w, r)
	if sess == nil || !s.checkPost(w, r, sess) {
		return
	}
	id := r.PostFormValue("id")
	reg, err := s.cfg.Store.Registration(r.Context(), id)
	admin := s.cfg.Authz.IsAdmin(sess.Principal)
	if err != nil || !s.visible(r.Context(), sess, admin, reg) {
		s.message(w, r, http.StatusNotFound, "Unknown registration", "No registration you can manage has that id.")
		return
	}
	who := approver(sess)
	if _, err := s.cfg.Store.Revoke(r.Context(), reg.ID, "", who, "revoked in the web UI"); err != nil &&
		!errors.Is(err, registrar.ErrNotFound) {
		s.log.Error("webui: revoking", "registration", reg.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Warn("registrar: registration revoked in the web UI", "registration", reg.ID, "name", reg.Name,
		"by", who.String(), "client", clientIP(r))
	http.Redirect(w, r, "/registrations?revoked="+url.QueryEscape(reg.ID), http.StatusSeeOther)
}

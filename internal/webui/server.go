// Package webui is the registrar's HTTPS interface: administrators log in
// with OpenID Connect, confirm and approve (or deny) approval-mode requests
// by user code, and list and revoke registrations.
package webui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"

	"github.com/bbockelm/htc-registrationd/internal/authz"
	"github.com/bbockelm/htc-registrationd/internal/knobs"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
)

// Authorizer answers whether a principal may approve a CE name.
type Authorizer interface {
	Decide(ctx context.Context, principal, name string) (authz.Decision, error)
	IsAdmin(principal string) bool
	// ConfigName is how configuration names principal, shown so an
	// administrator can copy it into ADMINS or the mapfile.
	ConfigName(principal string) (string, bool)
}

// Resolver is the DNS the approval page uses to name a request's source.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Config configures the web UI.
type Config struct {
	// PublicURL is the origin browsers and CEs use, e.g.
	// https://registrar.example.org. Redirect URIs and the verification
	// URI are built from it.
	PublicURL string
	// HTTPSAddr, with CertFile and KeyFile, is the HTTPS listener.
	HTTPSAddr string
	CertFile  string
	KeyFile   string
	// HTTPAddr is a plain-HTTP listener on a loopback address, for a
	// reverse proxy that terminates TLS.
	HTTPAddr string

	OIDC OIDCConfig
	// ClientSecretFile holds the OIDC client secret; it is read with
	// ReadCredential at startup and on Reload.
	ClientSecretFile string

	// SessionIdle and SessionLifetime end a session after inactivity and
	// after its absolute age (defaults 1 h and 12 h).
	SessionIdle     time.Duration
	SessionLifetime time.Duration

	Store *registrar.Store
	Authz Authorizer

	// ReadCredential reads the TLS key, certificate and client secret
	// (default droppriv.ReadFileMaybeAsRoot: root-owned files are read by
	// re-raising privilege).
	ReadCredential func(string) ([]byte, error)
	Resolver       Resolver
	Logger         *slog.Logger
	Now            func() time.Time
}

// Enabled reports whether any listener is configured.
func (c *Config) Enabled() bool { return c.HTTPSAddr != "" || c.HTTPAddr != "" }

// FromConfig reads the web UI's knobs. A configuration with no listener is
// returned with Enabled() false.
func FromConfig(cfg knobs.Getter) (*Config, error) {
	c := &Config{
		PublicURL:        strings.TrimRight(knobs.String(cfg, "HTC_REGISTRATIOND_PUBLIC_URL", ""), "/"),
		HTTPSAddr:        knobs.String(cfg, "HTC_REGISTRATIOND_HTTPS_ADDR", ""),
		CertFile:         knobs.String(cfg, "HTC_REGISTRATIOND_HTTPS_CERTFILE", ""),
		KeyFile:          knobs.String(cfg, "HTC_REGISTRATIOND_HTTPS_KEYFILE", ""),
		HTTPAddr:         knobs.String(cfg, "HTC_REGISTRATIOND_HTTP_ADDR", ""),
		ClientSecretFile: knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_CLIENT_SECRET_FILE", ""),
		OIDC: OIDCConfig{
			Issuer:         knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_ISSUER", ""),
			ClientID:       knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_CLIENT_ID", ""),
			Scopes:         knobs.List(cfg, "HTC_REGISTRATIOND_OIDC_SCOPES", DefaultScopes),
			PrincipalClaim: knobs.String(cfg, "HTC_REGISTRATIOND_OIDC_PRINCIPAL_CLAIM", "sub"),
		},
	}
	var err error
	if c.SessionIdle, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_SESSION_IDLE", time.Hour); err != nil {
		return nil, err
	}
	if c.SessionLifetime, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_SESSION_LIFETIME", 12*time.Hour); err != nil {
		return nil, err
	}
	if !c.Enabled() {
		return c, nil
	}
	return c, c.validate()
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secureURL reports whether u is https, or http to a loopback host.
func secureURL(u *url.URL) bool {
	if u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(u.Hostname()))
}

func (c *Config) validate() error {
	u, err := url.Parse(c.PublicURL)
	switch {
	case c.PublicURL == "":
		return errors.New("HTC_REGISTRATIOND_PUBLIC_URL is required with a web listener")
	case err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("HTC_REGISTRATIOND_PUBLIC_URL must be a scheme and host only, like https://registrar.example.org, not %q", c.PublicURL)
	case !secureURL(u):
		return fmt.Errorf("HTC_REGISTRATIOND_PUBLIC_URL must be https:// (got %q)", c.PublicURL)
	}
	if c.HTTPSAddr != "" && (c.CertFile == "" || c.KeyFile == "") {
		return errors.New("HTC_REGISTRATIOND_HTTPS_ADDR needs HTC_REGISTRATIOND_HTTPS_CERTFILE and HTC_REGISTRATIOND_HTTPS_KEYFILE")
	}
	if c.HTTPAddr != "" {
		host, _, err := net.SplitHostPort(c.HTTPAddr)
		if err != nil || !isLoopbackHost(host) {
			return fmt.Errorf("HTC_REGISTRATIOND_HTTP_ADDR must be a loopback address such as 127.0.0.1:8080, not %q", c.HTTPAddr)
		}
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		return errors.New("the web UI needs HTC_REGISTRATIOND_OIDC_ISSUER and HTC_REGISTRATIOND_OIDC_CLIENT_ID")
	}
	if iu, err := url.Parse(c.OIDC.Issuer); err != nil || !secureURL(iu) {
		return fmt.Errorf("HTC_REGISTRATIOND_OIDC_ISSUER must be an https:// URL, not %q", c.OIDC.Issuer)
	}
	return nil
}

// VerificationURI is where a CE's administrator approves a request.
func (c *Config) VerificationURI() string { return c.PublicURL + "/approve" }

// Server is the web UI.
type Server struct {
	cfg      Config
	log      *slog.Logger
	sessions *sessionStore
	oidc     *oidcProvider
	certs    *certReloader
	pages    *pages

	loginLimit   *ipLimiter
	approveLimit *ipLimiter
	secure       bool
	origin       string
	handler      http.Handler
}

// Rate limits per client address.
const (
	loginPerMinute   = 10
	approvePerMinute = 30
)

// New builds the web UI. It reads the client secret and, with an HTTPS
// listener, the TLS keypair, and fails if either cannot be read.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Authz == nil {
		return nil, errors.New("webui: a Store and an Authorizer are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ReadCredential == nil {
		cfg.ReadCredential = droppriv.ReadFileMaybeAsRoot
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = time.Hour
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = 12 * time.Hour
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	pu, err := url.Parse(cfg.PublicURL)
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("webui: bad public URL %q", cfg.PublicURL)
	}
	if cfg.ClientSecretFile != "" {
		if cfg.OIDC.ClientSecret, err = readSecret(cfg.ReadCredential, cfg.ClientSecretFile); err != nil {
			return nil, err
		}
	}
	sessions, err := newSessionStore(ctx, cfg.Store.DB(), cfg.Now, cfg.SessionIdle, cfg.SessionLifetime)
	if err != nil {
		return nil, err
	}
	pg, err := loadPages()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:          cfg,
		log:          cfg.Logger,
		sessions:     sessions,
		oidc:         newOIDCProvider(cfg.OIDC),
		pages:        pg,
		loginLimit:   newIPLimiter(loginPerMinute, loginPerMinute, cfg.Now),
		approveLimit: newIPLimiter(approvePerMinute, approvePerMinute, cfg.Now),
		secure:       pu.Scheme == "https",
		origin:       pu.Scheme + "://" + pu.Host,
	}
	if cfg.HTTPSAddr != "" {
		if s.certs, err = newCertReloader(cfg.CertFile, cfg.KeyFile, cfg.ReadCredential, s.log); err != nil {
			return nil, err
		}
	}
	s.handler = withHeaders(s.routes())
	return s, nil
}

func readSecret(read func(string) ([]byte, error), path string) (string, error) {
	b, err := read(path)
	if err != nil {
		return "", fmt.Errorf("reading the OIDC client secret %s: %w", path, err)
	}
	sec := strings.TrimSpace(string(b))
	if sec == "" {
		return "", fmt.Errorf("the OIDC client secret file %s is empty", path)
	}
	return sec, nil
}

// Handler returns the UI's HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Reload re-reads the client secret and the TLS keypair. A file that does
// not read keeps the value in use.
func (s *Server) Reload() {
	if s.cfg.ClientSecretFile != "" {
		if sec, err := readSecret(s.cfg.ReadCredential, s.cfg.ClientSecretFile); err != nil {
			s.log.Error("webui: keeping the OIDC client secret in use", "err", err)
		} else {
			s.oidc.setSecret(sec)
		}
	}
	if s.certs != nil {
		s.certs.refresh(true)
	}
}

// Start binds the configured listeners and serves until ctx ends or stop is
// called; stop waits for in-flight requests (up to 10 s).
func (s *Server) Start(ctx context.Context) (stop func(), err error) {
	var servers []*http.Server
	var lns []net.Listener
	closeAll := func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}
	lc := net.ListenConfig{}
	if s.cfg.HTTPSAddr != "" {
		ln, err := lc.Listen(ctx, "tcp", s.cfg.HTTPSAddr)
		if err != nil {
			return nil, fmt.Errorf("webui: HTTPS listener: %w", err)
		}
		lns = append(lns, tls.NewListener(ln, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.certs.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		}))
	}
	if s.cfg.HTTPAddr != "" {
		ln, err := lc.Listen(ctx, "tcp", s.cfg.HTTPAddr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("webui: HTTP listener: %w", err)
		}
		lns = append(lns, ln)
	}
	for _, ln := range lns {
		srv := &http.Server{
			Handler:           s.handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		}
		servers = append(servers, srv)
		go func(ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("webui: server stopped", "addr", ln.Addr().String(), "err", err)
			}
		}(ln)
		s.log.Info("webui: listening", "addr", ln.Addr().String(), "public_url", s.cfg.PublicURL)
	}
	pruneCtx, cancelPrune := context.WithCancel(ctx)
	go s.prune(pruneCtx)
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancelPrune()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			for _, srv := range servers {
				_ = srv.Shutdown(sctx)
			}
		})
	}
	go func() {
		<-ctx.Done()
		stop()
	}()
	return stop, nil
}

func (s *Server) prune(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.sessions.prune(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("webui: pruning sessions", "err", err)
			}
		}
	}
}

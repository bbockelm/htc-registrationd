// Package ce is the HTCondor-CE side of htc-registrationd: it requests a
// token from the registrar (by callback or by approval), installs it in the
// system token directory, reconfigures the local master, and renews it.
package ce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/htc-registrationd/internal/atomicfile"
	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// Methods for HTC_REGISTRATIOND_METHOD.
const (
	MethodAuto     = "auto"
	MethodCallback = protocol.MethodCallback
	MethodApproval = protocol.MethodApproval
)

// Config configures the CE manager.
type Config struct {
	// Name is the name to register (HTC_REGISTRATIOND_NAME, default
	// $(SCHEDD_NAME), then $(FULL_HOSTNAME)).
	Name string
	// Method is auto, callback or approval (HTC_REGISTRATIOND_METHOD).
	Method string
	// Registrar is the registrar's address (HTC_REGISTRATIOND_REGISTRAR).
	Registrar string
	// RegistrarServerName, when set, is the name the registrar's certificate
	// must carry; otherwise cedar derives it from Registrar.
	RegistrarServerName string
	// StateDir holds registration.json, status.json and approval-url.
	StateDir string
	// TokenFile is where the token is installed:
	// $(SEC_TOKEN_SYSTEM_DIRECTORY)/50-htc-registration.
	TokenFile string
	// Limits is sent as the requested Limits (informational).
	Limits string
	// Version is reported to the registrar as CEVersion.
	Version string

	// CallbackAddress returns this daemon's own sinful, for callback mode.
	CallbackAddress func() (string, error)
	// SSLServerAvailable reports whether an SSL server credential is
	// available (for auto mode) and, if not, why.
	SSLServerAvailable func() (bool, string)
	// ClientSecurity returns the base client security config for registrar
	// connections (SSL-only and encryption are forced on a copy).
	ClientSecurity func() *security.SecurityConfig
	// Reconfig sends DC_RECONFIG_FULL to the local master.
	Reconfig func(ctx context.Context) error
	// Ping, optional, checks the installed token against CONDOR_VIEW_HOST at
	// ADVERTISE_SCHEDD and returns a description of the result.
	Ping func(ctx context.Context) (string, error)

	// RenewFraction of a token's lifetime elapses before renewal (0.5).
	RenewFraction float64
	// RetryMin and RetryMax bound the jittered exponential back-off after a
	// failure (30 s / 30 min).
	RetryMin, RetryMax time.Duration
	// DeniedRetry is the wait before a new approval request after a denial (1 h).
	DeniedRetry time.Duration
	// ConnectTimeout bounds connecting to the registrar (30 s).
	ConnectTimeout time.Duration
	// CallbackWait bounds the wait for the registrar's callback outcome (90 s).
	CallbackWait time.Duration
	// ApprovalLogInterval is how often the pending approval URL is logged (5 min).
	ApprovalLogInterval time.Duration

	Logger *slog.Logger
	Now    func() time.Time
}

func (c *Config) setDefaults() {
	if c.Method == "" {
		c.Method = MethodAuto
	}
	if c.RenewFraction <= 0 || c.RenewFraction >= 1 {
		c.RenewFraction = 0.5
	}
	if c.RetryMin <= 0 {
		c.RetryMin = 30 * time.Second
	}
	if c.RetryMax <= 0 {
		c.RetryMax = 30 * time.Minute
	}
	if c.DeniedRetry <= 0 {
		c.DeniedRetry = time.Hour
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 30 * time.Second
	}
	if c.CallbackWait <= 0 {
		c.CallbackWait = 90 * time.Second
	}
	if c.ApprovalLogInterval <= 0 {
		c.ApprovalLogInterval = 5 * time.Minute
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Manager runs the CE side.
type Manager struct {
	cfg Config
	log *slog.Logger

	mu         sync.Mutex
	state      *State
	status     Status
	live       map[*liveRequest]struct{}
	force      bool
	failures   int
	lastURLLog time.Time

	wake chan struct{}
}

// NewManager loads the state directory and returns a manager.
func NewManager(cfg Config) (*Manager, error) {
	cfg.setDefaults()
	switch cfg.Method {
	case MethodAuto, MethodCallback, MethodApproval:
	default:
		return nil, fmt.Errorf("HTC_REGISTRATIOND_METHOD must be auto, callback or approval, not %q", cfg.Method)
	}
	if cfg.Name == "" {
		return nil, errors.New("no name to register (set HTC_REGISTRATIOND_NAME)")
	}
	if cfg.Registrar == "" {
		return nil, errors.New("no registrar address (set HTC_REGISTRATIOND_REGISTRAR or CONDOR_VIEW_HOST)")
	}
	if cfg.StateDir == "" || cfg.TokenFile == "" {
		return nil, errors.New("StateDir and TokenFile are required")
	}
	if cfg.ClientSecurity == nil {
		return nil, errors.New("ClientSecurity is required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:   cfg,
		log:   cfg.Logger,
		state: st,
		live:  map[*liveRequest]struct{}{},
		wake:  make(chan struct{}, 1),
	}
	m.status = Status{State: StateIdle, Name: cfg.Name, Registrar: cfg.Registrar, TokenFile: cfg.TokenFile}
	return m, nil
}

// State returns a copy of the current registration state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.state
}

// Status returns a copy of the current status.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// RenewNow asks the run loop to renew immediately (REG_RENEW_NOW).
func (m *Manager) RenewNow() {
	m.mu.Lock()
	m.force = true
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run drives requests and renewals until ctx ends.
func (m *Manager) Run(ctx context.Context) error {
	m.startupReconfig(ctx)
	for {
		wait := m.Step(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if wait < 0 {
			wait = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		case <-m.wake:
			t.Stop()
		}
	}
}

// startupReconfig covers a crash between installing a token and reconfiguring:
// a token installed after the last reconfig means the master never re-read
// tokens.d, so startup reconfigures.
func (m *Manager) startupReconfig(ctx context.Context) {
	m.mu.Lock()
	need := m.state.TokenInstalledAt != 0 && m.state.TokenInstalledAt >= m.state.LastReconfig
	m.mu.Unlock()
	if need {
		m.log.Info("ce: the installed token is newer than the last reconfig; reconfiguring")
		m.reconfig(ctx)
	}
}

// Step does one unit of work and returns how long to wait before the next.
func (m *Manager) Step(ctx context.Context) time.Duration {
	now := m.cfg.Now()
	m.mu.Lock()
	st := *m.state
	force := m.force
	m.force = false
	m.mu.Unlock()

	var wait time.Duration
	var err error
	switch {
	case st.RequestID != "":
		wait, err = m.pollApproval(ctx, &st)
	case st.HasToken(now) && !force && now.Before(st.RenewAt(m.cfg.RenewFraction)):
		m.setStatus(func(s *Status) {
			s.State = StateRegistered
			s.NextRenewal = st.RenewAt(m.cfg.RenewFraction).Unix()
		})
		return st.RenewAt(m.cfg.RenewFraction).Sub(now)
	case st.HasToken(now) && st.Method == MethodApproval && st.RegistrationID != "":
		err = m.renewApproval(ctx, &st)
	case st.HasToken(now) && st.Method == MethodCallback && m.cfg.Method != MethodApproval:
		// Callback renewal is a fresh full exchange: each renewal re-proves
		// ownership of the name, and no long-lived secret exists.
		err = m.requestCallback(ctx)
	default:
		if st.RegistrationID != "" && !st.HasToken(now) {
			// An expired token, in either mode, starts a fresh request.
			m.log.Warn("ce: the token expired; starting a fresh request", "registration", st.RegistrationID)
			if err := m.update(func(s *State) { s.clearRegistration() }); err != nil {
				return m.fail(err)
			}
		}
		wait, err = m.freshRequest(ctx)
	}
	if err != nil {
		return m.fail(err)
	}
	m.mu.Lock()
	m.failures = 0
	m.mu.Unlock()
	return wait
}

// fail records err and returns the jittered back-off delay.
func (m *Manager) fail(err error) time.Duration {
	m.mu.Lock()
	m.failures++
	n := m.failures
	m.mu.Unlock()
	d := m.cfg.RetryMin
	for i := 1; i < n && d < m.cfg.RetryMax; i++ {
		d *= 2
	}
	if d > m.cfg.RetryMax {
		d = m.cfg.RetryMax
	}
	// ±25% jitter so a fleet of CEs does not retry in lock step.
	d = time.Duration(float64(d) * (0.75 + rand.Float64()/2)) //nolint:gosec // jitter, not a secret
	m.log.Error("ce: registration step failed", "err", err.Error(), "retry_in", d.Round(time.Second).String())
	st := m.State()
	hasToken := st.HasToken(m.cfg.Now())
	m.setStatus(func(s *Status) {
		s.LastError = err.Error()
		s.LastErrorTime = m.cfg.Now().Unix()
		if !hasToken && s.State != StateApprovalPending {
			s.State = StateError
		}
	})
	return d
}

// update mutates the state and saves it atomically.
func (m *Manager) update(fn func(*State)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := *m.state
	fn(&next)
	if err := SaveState(m.cfg.StateDir, &next); err != nil {
		return err
	}
	*m.state = next
	return nil
}

func (m *Manager) setStatus(fn func(*Status)) {
	m.mu.Lock()
	fn(&m.status)
	st := *m.state
	m.status.Method = st.Method
	m.status.RegistrationID = st.RegistrationID
	m.status.TokenExpiry = st.TokenExpiry
	m.status.UpdatedAt = m.cfg.Now().Unix()
	snap := m.status
	m.mu.Unlock()
	if err := SaveStatus(m.cfg.StateDir, &snap); err != nil {
		m.log.Warn("ce: writing status.json", "err", err)
	}
}

// freshRequest starts a new registration. In auto mode it tries callback when
// an SSL server credential is available, and falls back to approval when there
// is none or the callback fails.
func (m *Manager) freshRequest(ctx context.Context) (time.Duration, error) {
	if m.cfg.Method != MethodApproval {
		ok, why := m.callbackAvailable()
		switch {
		case ok:
			err := m.requestCallback(ctx)
			if err == nil {
				return 0, nil
			}
			if m.cfg.Method == MethodCallback {
				return 0, err
			}
			m.log.Warn("ce: callback registration failed; falling back to approval mode", "err", err.Error())
		case m.cfg.Method == MethodCallback:
			return 0, fmt.Errorf("callback mode is configured but unavailable: %s", why)
		default:
			m.log.Info("ce: callback mode unavailable; using approval mode", "reason", why)
		}
	}
	return m.startApproval(ctx)
}

func (m *Manager) callbackAvailable() (bool, string) {
	if m.cfg.SSLServerAvailable != nil {
		if ok, why := m.cfg.SSLServerAvailable(); !ok {
			return false, why
		}
	}
	if m.cfg.CallbackAddress == nil {
		return false, "no callback address"
	}
	if _, err := m.cfg.CallbackAddress(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// dialRegistrar connects to the registrar for cmd, verifying its server
// certificate, with encryption.
func (m *Manager) dialRegistrar(ctx context.Context, cmd int) (*client.HTCondorClient, error) {
	sc := cedarx.SSLOnly(m.cfg.ClientSecurity(), cmd, m.cfg.RegistrarServerName, m.cfg.Registrar)
	cl, err := cedarx.DialSSL(ctx, &client.ClientConfig{
		Address:    m.cfg.Registrar,
		Security:   sc,
		Timeout:    m.cfg.ConnectTimeout,
		ClientName: "htc-registrationd",
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to registrar %s: %w", m.cfg.Registrar, err)
	}
	return cl, nil
}

// installToken writes the token to TokenFile atomically (mode 0600) and
// records it in the state. It does not touch any other file in tokens.d.
func (m *Manager) installToken(raw string) error {
	claims, err := mint.ParseUnverified(raw)
	if err != nil {
		return fmt.Errorf("received token: %w", err)
	}
	now := m.cfg.Now()
	if claims.Expiry <= now.Unix() {
		return fmt.Errorf("received token is already expired")
	}
	if claims.Subject != m.cfg.Name && !strings.HasPrefix(claims.Subject, m.cfg.Name+"@") {
		return fmt.Errorf("received token is for %q, not %q", claims.Subject, m.cfg.Name)
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.TokenFile), 0o700); err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	if err := atomicfile.WriteFile(m.cfg.TokenFile, []byte(strings.TrimSpace(raw)+"\n"), 0o600); err != nil {
		return fmt.Errorf("installing token: %w", err)
	}
	if err := m.update(func(s *State) {
		s.TokenIssuedAt = claims.IssuedAt
		s.TokenExpiry = claims.Expiry
		s.TokenInstalledAt = now.Unix()
	}); err != nil {
		return fmt.Errorf("recording installed token: %w", err)
	}
	m.log.Info("ce: installed token", "file", m.cfg.TokenFile, "subject", claims.Subject, "jti", claims.JTI,
		"expiry", time.Unix(claims.Expiry, 0).UTC().Format(time.RFC3339))
	return nil
}

// reconfig tells the local master to re-read tokens.d, then pings the view
// host with the new token.
func (m *Manager) reconfig(ctx context.Context) {
	if m.cfg.Reconfig != nil {
		if err := m.cfg.Reconfig(ctx); err != nil {
			m.log.Error("ce: DC_RECONFIG_FULL to the local master failed", "err", err.Error())
			m.setStatus(func(s *Status) { s.LastError, s.LastErrorTime = "reconfig: "+err.Error(), m.cfg.Now().Unix() })
			return
		}
	}
	if err := m.update(func(s *State) { s.LastReconfig = m.cfg.Now().Unix() }); err != nil {
		m.log.Warn("ce: recording reconfig", "err", err)
	}
	if m.cfg.Ping == nil {
		return
	}
	res, err := m.cfg.Ping(ctx)
	if err != nil {
		res = "failed: " + err.Error()
		m.log.Warn("ce: ADVERTISE_SCHEDD ping of the view host failed", "err", err.Error())
	}
	m.setStatus(func(s *Status) { s.LastPingTime, s.LastPingResult = m.cfg.Now().Unix(), res })
}

// succeeded records a successful issuance in the status.
func (m *Manager) succeeded() {
	st := m.State()
	m.setStatus(func(s *Status) {
		s.State = StateRegistered
		s.LastSuccess = m.cfg.Now().Unix()
		s.LastError, s.LastErrorTime = "", 0
		s.ApprovalURL, s.UserCode, s.RequestExpires = "", "", 0
		s.NextRenewal = st.RenewAt(m.cfg.RenewFraction).Unix()
	})
}

// --- approval mode ---

func (m *Manager) startApproval(ctx context.Context) (time.Duration, error) {
	nonce, err := secret.NewSecret()
	if err != nil {
		return 0, err
	}
	m.setStatus(func(s *Status) { s.State = StateRequesting })
	cl, err := m.dialRegistrar(ctx, protocol.RegRequest)
	if err != nil {
		return 0, err
	}
	defer func() { _ = cl.Close() }()
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.Request{
		Name: m.cfg.Name, Method: protocol.MethodApproval, Nonce: nonce, Limits: m.cfg.Limits, CEVersion: m.cfg.Version,
	}); err != nil {
		return 0, err
	}
	var reply protocol.RequestReply
	if err := protocol.Recv(ctx, cl.GetStream(), &reply); err != nil {
		return 0, err
	}
	if reply.Status != protocol.StatusPending || reply.RequestID == "" {
		return 0, fmt.Errorf("approval request refused: %w", replyErr(reply.Status, reply.Error))
	}
	interval := time.Duration(reply.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	// Persist {RequestId, Nonce} before publishing the URL, so a crash
	// while waiting resumes polling the same request.
	if err := m.update(func(s *State) {
		s.Method, s.Name, s.Registrar = MethodApproval, m.cfg.Name, m.cfg.Registrar
		s.RequestID, s.Nonce, s.UserCode = reply.RequestID, nonce, reply.UserCode
		s.VerificationURI, s.VerificationURIComplete = reply.VerificationURI, reply.VerificationURIComplete
		s.RequestExpires = m.cfg.Now().Add(time.Duration(reply.ExpiresIn) * time.Second).Unix()
		s.PollInterval = int64(interval / time.Second)
	}); err != nil {
		return 0, fmt.Errorf("persisting the approval request: %w", err)
	}
	m.publishApproval(true)
	return interval, nil
}

func approvalURL(st *State) string {
	switch {
	case st.VerificationURIComplete != "":
		return st.VerificationURIComplete
	case st.VerificationURI != "":
		return st.VerificationURI + " (code " + st.UserCode + ")"
	}
	return "code " + st.UserCode
}

// publishApproval writes approval-url and status.json and logs the URL, at
// most every ApprovalLogInterval unless first is set.
func (m *Manager) publishApproval(first bool) {
	st := m.State()
	url := approvalURL(&st)
	if err := atomicfile.WriteFile(filepath.Join(m.cfg.StateDir, ApprovalURLFile), []byte(url+"\n"), 0o644); err != nil {
		m.log.Warn("ce: writing approval-url", "err", err)
	}
	m.setStatus(func(s *Status) {
		s.State = StateApprovalPending
		s.ApprovalURL, s.UserCode, s.RequestExpires = url, st.UserCode, st.RequestExpires
	})
	now := m.cfg.Now()
	m.mu.Lock()
	due := first || now.Sub(m.lastURLLog) >= m.cfg.ApprovalLogInterval
	if due {
		m.lastURLLog = now
	}
	m.mu.Unlock()
	if due {
		m.log.Info("ce: registration awaits approval: an administrator of the registrar must approve it at "+url,
			"name", m.cfg.Name, "code", st.UserCode,
			"expires", time.Unix(st.RequestExpires, 0).UTC().Format(time.RFC3339))
	}
}

func (m *Manager) endApproval() {
	if err := atomicfile.Remove(filepath.Join(m.cfg.StateDir, ApprovalURLFile)); err != nil {
		m.log.Warn("ce: removing approval-url", "err", err)
	}
}

func replyErr(status string, e protocol.Error) error {
	if err := e.AsError(); err != nil {
		return err
	}
	return fmt.Errorf("unexpected status %q", status)
}

func (m *Manager) pollApproval(ctx context.Context, st *State) (time.Duration, error) {
	interval := time.Duration(st.PollInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	m.publishApproval(false)
	cl, err := m.dialRegistrar(ctx, protocol.RegPoll)
	if err != nil {
		return 0, err
	}
	defer func() { _ = cl.Close() }()
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.Poll{RequestID: st.RequestID, Nonce: st.Nonce}); err != nil {
		return 0, err
	}
	var reply protocol.PollReply
	if err := protocol.Recv(ctx, cl.GetStream(), &reply); err != nil {
		return 0, err
	}
	switch reply.Status {
	case protocol.StatusPending:
		return interval, nil
	case protocol.StatusSlowDown:
		next := time.Duration(reply.Interval) * time.Second
		if next <= interval {
			next = interval + 5*time.Second
		}
		if err := m.update(func(s *State) { s.PollInterval = int64(next / time.Second) }); err != nil {
			return 0, err
		}
		return next, nil
	case protocol.StatusApproved:
		return 0, m.claimApproval(ctx, &reply.Grant)
	case protocol.StatusDenied:
		m.log.Error("ce: the registration request was denied", "name", m.cfg.Name, "code", st.UserCode)
		m.abandonRequest("request denied")
		return m.cfg.DeniedRetry, nil
	}
	// expired, claimed, revoked, or an error such as an unknown request:
	// this request is finished; start over.
	reason := reply.Status
	if e := reply.AsError(); e != nil {
		reason = e.Error()
	}
	m.log.Warn("ce: the approval request ended", "name", m.cfg.Name, "code", st.UserCode, "outcome", reason)
	m.abandonRequest("approval request ended: " + reason)
	return m.cfg.RetryMin, nil
}

func (m *Manager) abandonRequest(why string) {
	if err := m.update(func(s *State) { s.clearRequest() }); err != nil {
		m.log.Error("ce: clearing the approval request", "err", err)
	}
	m.endApproval()
	m.setStatus(func(s *Status) {
		s.ApprovalURL, s.UserCode, s.RequestExpires = "", "", 0
		s.LastError, s.LastErrorTime = why, m.cfg.Now().Unix()
	})
}

// claimApproval handles the first issuance with the same steps as a renewal: store the
// registration and its first secret as pending (step 2), install the token
// (step 3), reconfigure (step 4).
func (m *Manager) claimApproval(ctx context.Context, g *protocol.Grant) error {
	if g.RegistrationID == "" || g.RefreshSecret == "" || g.Token == "" {
		return errors.New("approved reply is missing RegistrationId, RefreshSecret or Token")
	}
	if err := m.update(func(s *State) {
		s.Method = MethodApproval
		s.RegistrationID, s.Current, s.Pending = g.RegistrationID, "", g.RefreshSecret
		s.clearRequest()
	}); err != nil {
		return fmt.Errorf("storing the registration: %w", err)
	}
	m.endApproval()
	if err := m.installToken(g.Token); err != nil {
		return err
	}
	m.log.Info("ce: registration approved", "name", m.cfg.Name, "registration", g.RegistrationID)
	m.reconfig(ctx)
	m.succeeded()
	return nil
}

// renewApproval renews with the newest stored refresh secret: present pending
// if set, else current; on a reply durably store {current: presented,
// pending: new}, then install the token, then reconfigure. A secret is retired
// only when a newer one is proven, and the CE presents a newer one only after
// storing it, so a crash at any point never revokes.
func (m *Manager) renewApproval(ctx context.Context, st *State) error {
	presented := st.Newest()
	reply, err := m.sendRenew(ctx, st.RegistrationID, presented)
	if err != nil {
		return err
	}
	if reply.Status != protocol.StatusOK && reply.Code == protocol.ErrUnknown &&
		st.Current != "" && st.Current != presented {
		// The newest secret is unknown to the registrar, which only happens
		// if someone else renewed with a copy of our state. Presenting our
		// current secret then either reissues (no harm) or hits a retired
		// secret and revokes the registration: best-effort theft detection.
		m.log.Warn("ce: the registrar does not know our newest refresh secret; presenting the current one",
			"registration", st.RegistrationID)
		presented = st.Current
		if reply, err = m.sendRenew(ctx, st.RegistrationID, presented); err != nil {
			return err
		}
	}
	if reply.Status != protocol.StatusOK {
		err := replyErr(reply.Status, reply.Error)
		switch reply.Code {
		case protocol.ErrRevoked, protocol.ErrExpired, protocol.ErrUnknown:
			m.log.Error("ce: the registration can no longer be renewed; a new request is needed",
				"registration", st.RegistrationID, "err", err.Error())
			if uerr := m.update(func(s *State) { s.clearRegistration() }); uerr != nil {
				return uerr
			}
		}
		return fmt.Errorf("renewal refused: %w", err)
	}
	if reply.RefreshSecret == "" || reply.Token == "" {
		return errors.New("renewal reply is missing Token or RefreshSecret")
	}
	// Step 2: durably store {current: presented, pending: new} before
	// installing the token.
	if err := m.update(func(s *State) { s.Current, s.Pending = presented, reply.RefreshSecret }); err != nil {
		return fmt.Errorf("storing refresh secrets: %w", err)
	}
	if err := m.installToken(reply.Token); err != nil { // step 3
		return err
	}
	m.reconfig(ctx) // step 4
	m.succeeded()
	return nil
}

func (m *Manager) sendRenew(ctx context.Context, regID, presented string) (*protocol.RenewReply, error) {
	cl, err := m.dialRegistrar(ctx, protocol.RegRenew)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cl.Close() }()
	if err := protocol.Send(ctx, cl.GetStream(), &protocol.Renew{RegistrationID: regID, RefreshSecret: presented}); err != nil {
		return nil, err
	}
	var reply protocol.RenewReply
	if err := protocol.Recv(ctx, cl.GetStream(), &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

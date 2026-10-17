// Package registrar is the CE-Collector side of htc-registrationd: it records
// requests and registrations, runs the callback exchange, mints tokens, and
// rotates approval-mode refresh secrets.
package registrar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
	"github.com/bbockelm/htc-registrationd/internal/ssrf"
)

// Config is the registrar's policy.
type Config struct {
	Minter *mint.Minter
	// SSRF is the callback-address policy.
	SSRF *ssrf.Policy
	// Names decides which names callback mode may register.
	Names NamePolicy
	// Approvers re-checks approvers at renewal when RecheckApprover is set.
	Approvers ApproverPolicy

	// CallbackSecurity returns the base client security config for dialing a
	// CE. The service forces SSL-only, required authentication and
	// encryption, ServerName = the requested name and a private session cache
	// on a copy of it.
	CallbackSecurity func() *security.SecurityConfig

	// Tunables are the settings a reconfig may change (Service.Reconfigure).
	Tunables Tunables

	Logger *slog.Logger
	Now    func() time.Time
}

// Tunables are the registrar settings that take effect without a restart.
type Tunables struct {
	RecheckApprover bool
	// MaxRegistrationAge caps a registration's age (0: no cap).
	MaxRegistrationAge time.Duration
	// RefreshIdleLifetime is how long a refresh secret stays usable after
	// its registration's last successful issuance (default 30 days).
	RefreshIdleLifetime time.Duration
	// MaxReissues is how many consecutive renewals with the current refresh
	// secret a registration may have before one more revokes it (default 5).
	MaxReissues int

	// CallbackConnectTimeout and CallbackTimeout bound the one callback attempt
	// a request gets (defaults 10 s / 30 s).
	CallbackConnectTimeout time.Duration
	CallbackTimeout        time.Duration
	// CallbackBackoff is the back-off after a failed callback, per name and
	// requesting network; it doubles per consecutive failure up to
	// CallbackBackoffMax.
	CallbackBackoff    time.Duration
	CallbackBackoffMax time.Duration

	// MaxPendingPerIP and MaxPending cap live requests, per requesting
	// network (an IPv6 /64, an IPv4 address) and in total.
	MaxPendingPerIP int
	MaxPending      int

	// ApprovalTTL is how long an approval request waits for a decision
	// (default 30 min); UnclaimedTTL how long an approved request waits for
	// its first poll (default 24 h).
	ApprovalTTL  time.Duration
	UnclaimedTTL time.Duration
	// PollInterval is the initial REG_POLL interval (default 5 s).
	PollInterval time.Duration
	// VerificationURI is where an administrator approves a request, e.g.
	// https://registrar.example.org/approve.
	VerificationURI string
	// RequestRetention is how long finished requests, and issued-token
	// records past their expiry, are kept (default 7 d).
	RequestRetention time.Duration
}

func (c *Tunables) setDefaults() {
	if c.RefreshIdleLifetime <= 0 {
		c.RefreshIdleLifetime = 30 * 24 * time.Hour
	}
	if c.MaxReissues <= 0 {
		c.MaxReissues = 5
	}
	if c.CallbackConnectTimeout <= 0 {
		c.CallbackConnectTimeout = 10 * time.Second
	}
	if c.CallbackTimeout <= 0 {
		c.CallbackTimeout = 30 * time.Second
	}
	if c.CallbackBackoff <= 0 {
		c.CallbackBackoff = time.Minute
	}
	if c.CallbackBackoffMax <= 0 {
		c.CallbackBackoffMax = time.Hour
	}
	if c.MaxPendingPerIP <= 0 {
		c.MaxPendingPerIP = 10
	}
	if c.MaxPending <= 0 {
		c.MaxPending = 1000
	}
	if c.ApprovalTTL <= 0 {
		c.ApprovalTTL = 30 * time.Minute
	}
	if c.UnclaimedTTL <= 0 {
		c.UnclaimedTTL = 24 * time.Hour
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.RequestRetention <= 0 {
		c.RequestRetention = 7 * 24 * time.Hour
	}
}

func (c *Config) setDefaults() {
	c.Tunables.setDefaults()
	if c.Names == nil {
		c.Names = AuthzNames{}
	}
	if c.Approvers == nil {
		c.Approvers = TrustCEDARApprovers{}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Service serves the registrar's CEDAR commands.
type Service struct {
	cfg   Config
	tun   atomic.Pointer[Tunables]
	store *Store
	log   *slog.Logger

	mu       sync.Mutex
	backoff  map[callbackKey]nameBackoff
	inflight map[callbackKey]bool
}

// callbackKey is what callback back-off and the in-flight slot are charged
// to: a name and the network asking for it, so that a requester failing a
// callback for a name never locks out the name's own CE.
type callbackKey struct{ name, net string }

type nameBackoff struct {
	failures int
	until    time.Time
}

// New returns a registrar service over store.
func New(cfg Config, store *Store) (*Service, error) {
	cfg.setDefaults()
	if cfg.Minter == nil {
		return nil, errors.New("registrar: a Minter is required")
	}
	if cfg.SSRF == nil {
		return nil, errors.New("registrar: an SSRF policy is required")
	}
	if cfg.CallbackSecurity == nil {
		return nil, errors.New("registrar: CallbackSecurity is required")
	}
	s := &Service{
		cfg:      cfg,
		store:    store,
		log:      cfg.Logger,
		backoff:  map[callbackKey]nameBackoff{},
		inflight: map[callbackKey]bool{},
	}
	t := cfg.Tunables
	s.tun.Store(&t)
	return s, nil
}

// Reconfigure replaces the tunables; requests already in progress finish
// under the old ones.
func (s *Service) Reconfigure(t Tunables) {
	t.setDefaults()
	s.tun.Store(&t)
}

// t returns the current tunables.
func (s *Service) t() *Tunables { return s.tun.Load() }

// Store returns the service's store.
func (s *Service) Store() *Store { return s.store }

// Register installs the registrar's commands on srv.
func (s *Service) Register(srv *cedarserver.Server) {
	srv.Handle(protocol.RegRequest, s.handleRequest, "ALLOW")
	srv.Handle(protocol.RegPoll, s.handlePoll, "ALLOW")
	srv.Handle(protocol.RegRenew, s.handleRenew, "ALLOW")
	srv.Handle(protocol.RegAdminList, s.handleAdminList, "ADMINISTRATOR")
	srv.Handle(protocol.RegAdminApprove, s.handleAdminDecide(true), "ADMINISTRATOR")
	srv.Handle(protocol.RegAdminDeny, s.handleAdminDecide(false), "ADMINISTRATOR")
	srv.Handle(protocol.RegAdminRevoke, s.handleAdminRevoke, "ADMINISTRATOR")
}

// Maintain runs periodic store maintenance until ctx ends.
func (s *Service) Maintain(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		tun := s.t()
		if err := s.store.Maintain(ctx, MaintainOptions{
			Retain:         tun.RequestRetention,
			UnclaimedTTL:   tun.UnclaimedTTL,
			TokenRetention: tun.RequestRetention,
		}); err != nil && ctx.Err() == nil {
			s.log.Error("registrar: store maintenance failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// encrypted reports whether the session is encrypted; every REG_* command
// refuses otherwise.
func encrypted(c *cedarserver.Conn) bool {
	return c.Negotiation != nil && c.Negotiation.Encryption
}

func sourceIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

// handlerTimeout bounds a handler's I/O so a stalled peer cannot hold it.
const handlerTimeout = 60 * time.Second

func (s *Service) refuse(ctx context.Context, c *cedarserver.Conn, perr *protocol.Error) error {
	_ = protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusError, Error: *perr})
	return perr
}

func (s *Service) handleRequest(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout+s.t().CallbackTimeout)
	defer cancel()
	if !encrypted(c) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "REG_REQUEST requires an encrypted session"))
	}
	var req protocol.Request
	if err := protocol.Recv(ctx, c.Stream, &req); err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "bad request: %v", err))
	}
	req.Name = NormalizeName(req.Name)
	if err := ValidName(req.Name); err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "bad name: %v", err))
	}
	if len(req.Nonce) < 32 || len(req.Nonce) > 512 {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "Nonce must be 32-512 characters"))
	}
	src := sourceIP(c.RemoteAddr)
	switch req.Method {
	case protocol.MethodCallback:
		return s.requestCallback(ctx, c, &req, src)
	case protocol.MethodApproval:
		return s.requestApproval(ctx, c, &req, src)
	}
	return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "unknown Method %q", req.Method))
}

// createRequest records r under the pending-request caps, refusing on c when
// they or the database say no.
func (s *Service) createRequest(ctx context.Context, c *cedarserver.Conn, r NewRequest) (int64, error) {
	t := s.t()
	r.MaxPerSource, r.MaxTotal = t.MaxPendingPerIP, t.MaxPending
	number, err := s.store.CreateRequest(ctx, r)
	var capErr *CapError
	if errors.As(err, &capErr) {
		s.log.Warn("registrar: request refused by caps", "name", r.Name, "source", r.SourceIP, "reason", capErr.Error())
		return 0, s.refuse(ctx, c, protocol.Err(protocol.ErrRateLimited, "%s", capErr.Error()))
	}
	if err != nil && !errors.Is(err, ErrUserCodeTaken) {
		s.log.Error("registrar: recording request", "err", err)
		return 0, s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	return number, err
}

func (s *Service) requestApproval(ctx context.Context, c *cedarserver.Conn, req *protocol.Request, src string) error {
	t := s.t()
	requestID, err := secret.NewID()
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "internal error"))
	}
	var code string
	var number int64
	for attempt := 0; ; attempt++ {
		if code, err = NewUserCode(); err != nil {
			return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "internal error"))
		}
		number, err = s.createRequest(ctx, c, NewRequest{
			RequestIDHash: secret.Hash(requestID),
			NonceHash:     secret.Hash(req.Nonce),
			Name:          req.Name,
			Method:        protocol.MethodApproval,
			SourceIP:      src,
			CEVersion:     req.CEVersion,
			UserCode:      code,
			Status:        ReqPending,
			TTL:           t.ApprovalTTL,
			PollInterval:  t.PollInterval,
		})
		if errors.Is(err, ErrUserCodeTaken) && attempt < 5 {
			continue
		}
		break
	}
	if errors.Is(err, ErrUserCodeTaken) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	if err != nil {
		return err // already refused
	}
	reply := protocol.RequestReply{
		Status:    protocol.StatusPending,
		RequestID: requestID,
		UserCode:  code,
		Interval:  int64(t.PollInterval / time.Second),
		ExpiresIn: int64(t.ApprovalTTL / time.Second),
	}
	if t.VerificationURI != "" {
		reply.VerificationURI = t.VerificationURI
		sep := "?"
		if strings.Contains(t.VerificationURI, "?") {
			sep = "&"
		}
		reply.VerificationURIComplete = t.VerificationURI + sep + "code=" + code
	}
	s.log.Info("registrar: approval requested", "request", number, "name", req.Name, "code", code,
		"source", src, "ce_version", req.CEVersion)
	return protocol.Send(ctx, c.Stream, &reply)
}

func (s *Service) handlePoll(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()
	if !encrypted(c) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "REG_POLL requires an encrypted session"))
	}
	var p protocol.Poll
	if err := protocol.Recv(ctx, c.Stream, &p); err != nil || p.RequestID == "" || p.Nonce == "" {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "REG_POLL needs RequestId and Nonce"))
	}
	res, err := s.store.Poll(ctx, p.RequestID, p.Nonce, PollOptions{
		UnclaimedTTL: s.t().UnclaimedTTL,
		SlowDownStep: 5 * time.Second,
	}, s.cfg.Minter.Mint)
	if errors.Is(err, ErrNotFound) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrUnknown, "unknown request"))
	}
	if err != nil {
		s.log.Error("registrar: REG_POLL failed", "err", err)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar error"))
	}
	reply := protocol.PollReply{Status: res.Status, Interval: int64(res.Interval / time.Second)}
	if res.Status == protocol.StatusApproved {
		reply.Grant = protocol.Grant{
			RegistrationID: res.RegistrationID,
			Token:          res.Token.Raw,
			Expiry:         res.Token.Expiry.Unix(),
			RefreshSecret:  res.RefreshSecret,
		}
		s.log.Info("registrar: issued first token", "request", res.Request.Number, "name", res.Request.Name,
			"registration", res.RegistrationID, "jti", res.Token.JTI, "expiry", res.Token.Expiry)
	}
	return protocol.Send(ctx, c.Stream, &reply)
}

func (s *Service) handleRenew(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()
	if !encrypted(c) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "REG_RENEW requires an encrypted session"))
	}
	var r protocol.Renew
	if err := protocol.Recv(ctx, c.Stream, &r); err != nil || r.RegistrationID == "" || r.RefreshSecret == "" {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "REG_RENEW needs RegistrationId and RefreshSecret"))
	}
	t := s.t()
	opts := RenewOptions{MaxAge: t.MaxRegistrationAge, IdleLifetime: t.RefreshIdleLifetime, MaxReissues: t.MaxReissues}
	if t.RecheckApprover {
		opts.Recheck = s.cfg.Approvers.StillAuthorized
	}
	res, err := s.store.Renew(ctx, r.RegistrationID, r.RefreshSecret, opts, s.cfg.Minter.Mint)
	var rerr *RenewError
	if errors.As(err, &rerr) {
		if res != nil && res.Registration.Status == RegRevoked {
			s.log.Error("registrar: REFRESH SECRET MISUSE: registration REVOKED "+
				"(possible theft of the CE's registration state)",
				"registration", r.RegistrationID, "name", res.Registration.Name, "source", c.RemoteAddr,
				"reason", res.Registration.RevokeReason)
		} else {
			s.log.Warn("registrar: REG_RENEW refused", "registration", r.RegistrationID, "source", c.RemoteAddr,
				"reason", rerr.Reason)
		}
		status := protocol.StatusError
		switch rerr.Code {
		case protocol.ErrRevoked:
			status = protocol.StatusRevoked
		case protocol.ErrExpired:
			status = protocol.StatusExpired
		}
		_ = protocol.Send(ctx, c.Stream, &protocol.RenewReply{Status: status,
			Error: protocol.Error{Code: int64(rerr.Code), Message: rerr.Reason}})
		return rerr
	}
	if err != nil {
		s.log.Error("registrar: REG_RENEW failed", "registration", r.RegistrationID, "err", err)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar error"))
	}
	s.log.Info("registrar: renewed", "registration", res.Registration.ID, "name", res.Registration.Name,
		"action", res.Action.String(), "jti", res.Token.JTI, "expiry", res.Token.Expiry)
	return protocol.Send(ctx, c.Stream, &protocol.RenewReply{
		Status: protocol.StatusOK,
		Grant: protocol.Grant{
			RegistrationID: res.Registration.ID,
			Token:          res.Token.Raw,
			Expiry:         res.Token.Expiry.Unix(),
			RefreshSecret:  res.RefreshSecret,
		},
	})
}

// approverIdentity is the CEDAR identity behind an admin command.
func approverIdentity(c *cedarserver.Conn) Identity {
	return Identity{Kind: "cedar", Principal: c.AuthorizationUser()}
}

func (s *Service) findRequest(ctx context.Context, t *protocol.AdminTarget) (*RequestRecord, error) {
	switch {
	case t.UserCode != "":
		return s.store.RequestByUserCode(ctx, NormalizeUserCode(t.UserCode))
	case t.RequestNumber != 0:
		return s.store.RequestByNumber(ctx, t.RequestNumber)
	}
	return nil, fmt.Errorf("a UserCode or RequestNumber is required")
}

func (s *Service) handleAdminDecide(approve bool) cedarserver.HandlerFunc {
	verb, cmd := "deny", "REG_ADMIN_DENY"
	if approve {
		verb, cmd = "approve", "REG_ADMIN_APPROVE"
	}
	return func(ctx context.Context, c *cedarserver.Conn) error {
		ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
		defer cancel()
		if !encrypted(c) {
			return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "%s requires an encrypted session", cmd))
		}
		var t protocol.AdminTarget
		if err := protocol.Recv(ctx, c.Stream, &t); err != nil {
			return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "bad request: %v", err))
		}
		if approve && t.Name == "" {
			// A user code alone approves whatever name the request carries,
			// which is how a device-code phish works: the approver must say
			// which CE they mean.
			return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest,
				"approving needs the CE name the request is expected to carry"))
		}
		r, err := s.findRequest(ctx, &t)
		if errors.Is(err, ErrNotFound) {
			return s.refuse(ctx, c, protocol.Err(protocol.ErrNotFound, "no such request"))
		}
		if err != nil {
			return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "%v", err))
		}
		who := approverIdentity(c)
		var opts DecideOptions
		if approve {
			opts = DecideOptions{ExpectName: t.Name, RefuseActive: true, Replace: t.Replace}
		}
		replaced, err := s.store.DecideChecked(ctx, r.Number, approve, who, t.Reason, opts)
		if err != nil {
			var mismatch *NameMismatchError
			if errors.As(err, &mismatch) {
				s.log.Warn("registrar: approval refused: the request is for another name", "request", r.Number,
					"name", r.Name, "expected", mismatch.Expected, "by", who.String())
			}
			return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "cannot %s request %d: %v", verb, r.Number, err))
		}
		for _, reg := range replaced {
			s.log.Warn("registrar: registration revoked: replaced", "registration", reg.ID, "name", reg.Name,
				"request", r.Number, "by", who.String())
		}
		s.log.Info("registrar: request "+verb+"d", "request", r.Number, "name", r.Name, "code", r.UserCode, "by", who.String())
		hint := fmt.Sprintf("request %d (%s) %sd", r.Number, r.Name, verb)
		if len(replaced) > 0 {
			hint += fmt.Sprintf("; revoked %d earlier approval-mode registration(s) of %s", len(replaced), r.Name)
		}
		return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK, Hint: hint})
	}
}

func (s *Service) handleAdminRevoke(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()
	if !encrypted(c) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "REG_ADMIN_REVOKE requires an encrypted session"))
	}
	var t protocol.AdminTarget
	if err := protocol.Recv(ctx, c.Stream, &t); err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "bad request: %v", err))
	}
	who := approverIdentity(c)
	revoked, err := s.store.Revoke(ctx, t.RegistrationID, NormalizeName(t.Name), who, t.Reason)
	if errors.Is(err, ErrNotFound) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotFound, "no active registration matches"))
	}
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrBadRequest, "%v", err))
	}
	var names []string
	for _, r := range revoked {
		names = append(names, s.cfg.Minter.Subject(r.Name))
		s.log.Warn("registrar: registration revoked", "registration", r.ID, "name", r.Name, "by", who.String())
	}
	hint := fmt.Sprintf("revoked %d registration(s); the current token stays valid until it expires. "+
		"For an immediate cut-off, add to the collector's configuration: DENY_ADVERTISE_SCHEDD = $(DENY_ADVERTISE_SCHEDD) %s",
		len(revoked), strings.Join(names, " "))
	return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK, Hint: hint})
}

func (s *Service) handleAdminList(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()
	if !encrypted(c) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNotEncrypted, "REG_ADMIN_LIST requires an encrypted session"))
	}
	reqs, err := s.store.ListRequests(ctx, s.cfg.Now().Add(-s.t().RequestRetention))
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	regs, err := s.store.ListRegistrations(ctx)
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	for _, r := range reqs {
		if err := protocol.SendAd(ctx, c.Stream, RequestAd(r)); err != nil {
			return err
		}
	}
	for _, r := range regs {
		if err := protocol.SendAd(ctx, c.Stream, RegistrationAd(r)); err != nil {
			return err
		}
	}
	end := protocol.Encode(&protocol.Ack{Status: protocol.StatusOK})
	_ = end.Set(protocol.AttrEnd, true)
	return protocol.SendAd(ctx, c.Stream, end)
}

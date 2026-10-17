package registrar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"

	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
	"github.com/bbockelm/htc-registrationd/internal/ssrf"
)

// callbackConn is an established, SSL-authenticated callback connection.
type callbackConn struct {
	st    *stream.Stream
	close func() error
}

// dialCallback makes the request's one callback attempt: SSL only, the CE's
// certificate verified against ServerName = name whatever host or alias the
// sinful carries, and encryption required. The registrar presents no
// certificate of its own.
//
// This is the one place the registrar dials an address a client chose, so the
// SSRF policy is installed as cedar's dial hook: it runs after cedar resolves
// the sinful's host, on each concrete address about to be connected (direct
// or shared-port), and refuses any the policy denies. CheckSinful has only
// checked the sinful's form and its IP literals.
func (s *Service) dialCallback(ctx context.Context, target *ssrf.Target, name string) (*callbackConn, error) {
	sc := cedarx.SSLOnly(s.cfg.CallbackSecurity(), protocol.RegCallback, name, target.Dial)
	ccfg := &client.ClientConfig{
		Address:     target.Dial,
		Security:    sc,
		Timeout:     s.cfg.CallbackConnectTimeout,
		ClientName:  "htc-registrationd",
		DialControl: s.cfg.SSRF.Control,
	}
	cl, err := cedarx.DialSSL(ctx, ccfg)
	if err != nil {
		return nil, err
	}
	return &callbackConn{st: cl.GetStream(), close: cl.Close}, nil
}

func (s *Service) nameBackedOff(name string) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.backoff[name]
	if !ok {
		return 0, false
	}
	if left := b.until.Sub(s.cfg.Now()); left > 0 {
		return left, true
	}
	return 0, false
}

func (s *Service) recordCallback(name string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		delete(s.backoff, name)
		return
	}
	b := s.backoff[name]
	b.failures++
	d := s.cfg.CallbackBackoff
	for i := 1; i < b.failures && d < s.cfg.CallbackBackoffMax; i++ {
		d *= 2
	}
	if d > s.cfg.CallbackBackoffMax {
		d = s.cfg.CallbackBackoffMax
	}
	b.until = s.cfg.Now().Add(d)
	s.backoff[name] = b
}

func (s *Service) claimInflight(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[name] {
		return false
	}
	s.inflight[name] = true
	return true
}

func (s *Service) releaseInflight(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, name)
}

// requestCallback handles a callback-mode REG_REQUEST. The
// reply carries the RequestId; the registrar then dials the CE, and a second
// reply on this connection reports the outcome. The token itself only ever
// travels on the callback connection.
func (s *Service) requestCallback(ctx context.Context, c *cedarserver.Conn, req *protocol.Request, src string) error {
	name := req.Name
	if left, ok := s.nameBackedOff(name); ok {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrRateLimited,
			"a recent callback to %s failed; retry in %s", name, left.Round(time.Second)))
	}
	revoked, err := s.store.NameRevoked(ctx, name)
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	if revoked {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrRevoked, "registrations for %s are revoked", name))
	}
	ok, why, err := s.cfg.Names.AllowCallbackName(ctx, name)
	if err != nil {
		s.log.Error("registrar: name policy failed", "name", name, "err", err)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "name policy error"))
	}
	if !ok {
		s.log.Warn("registrar: callback name refused", "name", name, "source", src, "reason", why)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrNameRefused, "%s", why))
	}
	target, err := s.cfg.SSRF.CheckSinful(req.CallbackAddress)
	if err != nil {
		s.log.Warn("registrar: callback address refused", "name", name, "source", src,
			"address", req.CallbackAddress, "err", err)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrCallbackDenied, "%v", err))
	}
	if !s.claimInflight(name) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrRateLimited, "a callback to %s is already in progress", name))
	}
	defer s.releaseInflight(name)

	requestID, err := secret.NewID()
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "internal error"))
	}
	nonceHash := secret.Hash(req.Nonce)
	number, err := s.store.CreateRequest(ctx, NewRequest{
		RequestIDHash:   secret.Hash(requestID),
		NonceHash:       nonceHash,
		Name:            name,
		Method:          protocol.MethodCallback,
		SourceIP:        src,
		CallbackAddress: req.CallbackAddress,
		CEVersion:       req.CEVersion,
		Status:          ReqCallbackPending,
		TTL:             s.cfg.CallbackTimeout + s.cfg.CallbackConnectTimeout,
	})
	if err != nil {
		s.log.Error("registrar: recording callback request", "err", err)
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "registrar database error"))
	}
	if err := protocol.Send(ctx, c.Stream, &protocol.RequestReply{
		Status: protocol.StatusCallbackPending, RequestID: requestID,
	}); err != nil {
		_ = s.store.FinishRequest(ctx, number, ReqFailed, "first reply not delivered", "")
		return err
	}

	regID, cerr := s.runCallback(ctx, number, name, src, requestID, nonceHash, target)
	s.recordCallback(name, cerr == nil)
	outcome := protocol.CallbackOutcome{Status: protocol.StatusIssued}
	if cerr != nil {
		reason := cerr.Error()
		s.log.Warn("registrar: callback failed", "request", number, "name", name, "address", target.Dial, "err", reason)
		_ = s.store.FinishRequest(ctx, number, ReqFailed, reason, regID)
		outcome = protocol.CallbackOutcome{Status: protocol.StatusFailed,
			Error: protocol.Error{Code: protocol.ErrCallbackFailed, Message: reason}}
	}
	return protocol.Send(ctx, c.Stream, &outcome)
}

// runCallback performs REG_CALLBACK against the CE and returns the
// registration id the token was issued under.
func (s *Service) runCallback(ctx context.Context, number int64, name, src, requestID, nonceHash string, target *ssrf.Target) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.CallbackTimeout)
	defer cancel()
	cc, err := s.dialCallback(ctx, target, name)
	if err != nil {
		return "", fmt.Errorf("callback to %s (as %s) failed: %w", target.Dial, name, err)
	}
	defer func() { _ = cc.close() }()

	if err := protocol.Send(ctx, cc.st, &protocol.CallbackHello{RequestID: requestID}); err != nil {
		return "", fmt.Errorf("callback: sending RequestId: %w", err)
	}
	var proof protocol.CallbackProof
	if err := protocol.Recv(ctx, cc.st, &proof); err != nil {
		return "", fmt.Errorf("callback: reading Nonce: %w", err)
	}
	if proof.Status != protocol.StatusOK {
		return "", fmt.Errorf("callback: the CE refused the request id: %s", proof.Message)
	}
	if !secret.Matches(proof.Nonce, nonceHash) {
		return "", errors.New("callback: the CE answered with a different Nonce than the request carried")
	}

	tok, err := s.cfg.Minter.Mint(name)
	if err != nil {
		s.log.Error("registrar: minting token", "name", name, "err", err)
		return "", errors.New("callback: the registrar could not mint a token")
	}
	regID, err := s.store.CallbackRegistration(ctx, number, name, src, tok)
	if err != nil {
		return "", fmt.Errorf("callback: %w", err)
	}
	if err := protocol.Send(ctx, cc.st, &protocol.CallbackDelivery{
		Name: name, Token: tok.Raw, Expiry: tok.Expiry.Unix(),
	}); err != nil {
		return regID, fmt.Errorf("callback: delivering token: %w", err)
	}
	var ack protocol.Ack
	if err := protocol.Recv(ctx, cc.st, &ack); err != nil {
		return regID, fmt.Errorf("callback: reading acknowledgement: %w", err)
	}
	if ack.Status != protocol.StatusOK {
		return regID, fmt.Errorf("callback: the CE did not install the token: %s", ack.Message)
	}
	if err := s.store.CallbackAcknowledged(ctx, number, regID, src, tok); err != nil {
		s.log.Error("registrar: recording acknowledged callback", "request", number, "err", err)
	}
	s.log.Info("registrar: issued token by callback", "request", number, "name", name, "registration", regID,
		"jti", tok.JTI, "expiry", tok.Expiry)
	return regID, nil
}

// RequestAd renders a request for REG_ADMIN_LIST.
func RequestAd(r *RequestRecord) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("Kind", "request")
	_ = ad.Set(protocol.AttrRequestNumber, r.Number)
	_ = ad.Set(protocol.AttrName, r.Name)
	_ = ad.Set(protocol.AttrMethod, r.Method)
	_ = ad.Set(protocol.AttrStatus, r.Status)
	_ = ad.Set("SourceIP", r.SourceIP)
	_ = ad.Set(protocol.AttrCEVersion, r.CEVersion)
	_ = ad.Set(protocol.AttrUserCode, r.UserCode)
	_ = ad.Set("CreatedAt", r.CreatedAt.Unix())
	_ = ad.Set("ExpiresAt", r.ExpiresAt.Unix())
	_ = ad.Set("DecidedBy", r.DecidedBy)
	_ = ad.Set(protocol.AttrReason, r.Reason)
	_ = ad.Set(protocol.AttrRegistrationID, r.RegistrationID)
	return ad
}

// RegistrationAd renders a registration for REG_ADMIN_LIST. Secret hashes are
// never included.
func RegistrationAd(r *RegistrationRecord) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("Kind", "registration")
	_ = ad.Set(protocol.AttrRegistrationID, r.ID)
	_ = ad.Set(protocol.AttrName, r.Name)
	_ = ad.Set(protocol.AttrMethod, r.Method)
	_ = ad.Set(protocol.AttrStatus, r.Status)
	_ = ad.Set("Approver", r.Approver)
	_ = ad.Set(protocol.AttrRequestNumber, r.RequestNumber)
	_ = ad.Set("CreatedAt", r.CreatedAt.Unix())
	_ = ad.Set("LastIssuedAt", r.LastIssuedAt.Unix())
	_ = ad.Set("TokenExpiry", r.TokenExpiry.Unix())
	_ = ad.Set("RevokedBy", r.RevokedBy)
	_ = ad.Set("RevokeReason", r.RevokeReason)
	return ad
}

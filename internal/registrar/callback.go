package registrar

import (
	"context"
	"errors"
	"fmt"

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
		Timeout:     s.t().CallbackConnectTimeout,
		ClientName:  "htc-registrationd",
		DialControl: s.cfg.SSRF.Control,
	}
	cl, err := cedarx.DialSSL(ctx, ccfg)
	if err != nil {
		return nil, err
	}
	return &callbackConn{st: cl.GetStream(), close: cl.Close}, nil
}

// callbackKeyFor is the back-off and in-flight key of a callback for name
// requested from src.
func callbackKeyFor(name, src string) callbackKey {
	return callbackKey{name: name, net: SourceNet(src)}
}

// backedOff reports whether callbacks for k are backing off.
func (s *Service) backedOff(k callbackKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.backoff[k]
	return ok && s.cfg.Now().Before(b.until)
}

// recordCallback records a callback's outcome. A failure backs off further
// requests for the name from the same network only; a success, which proves
// the requester is the name's CE, clears the back-off of every network for
// the name.
func (s *Service) recordCallback(k callbackKey, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if ok {
		for bk := range s.backoff {
			if bk.name == k.name {
				delete(s.backoff, bk)
			}
		}
		return
	}
	t := s.t()
	b := s.backoff[k]
	b.failures++
	d := t.CallbackBackoff
	for i := 1; i < b.failures && d < t.CallbackBackoffMax; i++ {
		d *= 2
	}
	if d > t.CallbackBackoffMax {
		d = t.CallbackBackoffMax
	}
	b.until = now.Add(d)
	s.backoff[k] = b
	// Drop entries whose back-off ended long ago, so the map stays bounded
	// by the requests of the last CallbackBackoffMax.
	for bk, bb := range s.backoff {
		if now.Sub(bb.until) > t.CallbackBackoffMax {
			delete(s.backoff, bk)
		}
	}
}

func (s *Service) claimInflight(k callbackKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[k] {
		return false
	}
	s.inflight[k] = true
	return true
}

func (s *Service) releaseInflight(k callbackKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, k)
}

// errCallbackDial is what a requester is told when the callback could not
// connect or the TLS handshake failed. The detail (connection refused, a
// timeout, a certificate for another name) goes to the registrar's log only:
// told to a requester, it would make the registrar a port prober.
var errCallbackDial = errors.New("the registrar could not connect to the callback address and verify " +
	"its certificate for the requested name; the registrar's log has the detail")

// requestCallback handles a callback-mode REG_REQUEST. The
// reply carries the RequestId; the registrar then dials the CE, and a second
// reply on this connection reports the outcome. The token itself only ever
// travels on the callback connection.
//
// Back-off after a failure and the one-callback-at-a-time slot are charged to
// the name and the requesting network together: an anonymous requester that
// fails callbacks for a name slows only itself, never the name's own CE. The
// pending-request caps bound how fast any one network can probe.
func (s *Service) requestCallback(ctx context.Context, c *cedarserver.Conn, req *protocol.Request, src string) error {
	name := req.Name
	key := callbackKeyFor(name, src)
	if s.backedOff(key) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrRateLimited,
			"a recent callback for %s requested from this network failed; try again later", name))
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
	if !s.claimInflight(key) {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrRateLimited, "a callback for %s is already in progress", name))
	}
	defer s.releaseInflight(key)

	t := s.t()
	requestID, err := secret.NewID()
	if err != nil {
		return s.refuse(ctx, c, protocol.Err(protocol.ErrInternal, "internal error"))
	}
	nonceHash := secret.Hash(req.Nonce)
	number, err := s.createRequest(ctx, c, NewRequest{
		RequestIDHash:   secret.Hash(requestID),
		NonceHash:       nonceHash,
		Name:            name,
		Method:          protocol.MethodCallback,
		SourceIP:        src,
		CallbackAddress: req.CallbackAddress,
		CEVersion:       req.CEVersion,
		Status:          ReqCallbackPending,
		TTL:             t.CallbackTimeout + t.CallbackConnectTimeout,
	})
	if err != nil {
		return err // already refused
	}
	if err := protocol.Send(ctx, c.Stream, &protocol.RequestReply{
		Status: protocol.StatusCallbackPending, RequestID: requestID,
	}); err != nil {
		_ = s.store.FinishRequest(ctx, number, ReqFailed, "first reply not delivered", "")
		return err
	}

	regID, cerr := s.runCallback(ctx, number, name, src, requestID, nonceHash, target)
	s.recordCallback(key, cerr == nil)
	outcome := protocol.CallbackOutcome{Status: protocol.StatusIssued}
	if cerr != nil {
		reason := cerr.Error()
		s.log.Warn("registrar: callback failed", "request", number, "name", name, "address", target.Dial,
			"source", src, "err", reason)
		_ = s.store.FinishRequest(ctx, number, ReqFailed, reason, regID)
		told := reason
		var de *dialError
		if errors.As(cerr, &de) {
			told = errCallbackDial.Error()
		}
		outcome = protocol.CallbackOutcome{Status: protocol.StatusFailed,
			Error: protocol.Error{Code: protocol.ErrCallbackFailed, Message: told}}
	}
	return protocol.Send(ctx, c.Stream, &outcome)
}

// dialError is a callback that failed before the CE was authenticated.
type dialError struct{ err error }

func (e *dialError) Error() string { return e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

// runCallback performs REG_CALLBACK against the CE and returns the
// registration id the token was issued under.
func (s *Service) runCallback(ctx context.Context, number int64, name, src, requestID, nonceHash string, target *ssrf.Target) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.t().CallbackTimeout)
	defer cancel()
	cc, err := s.dialCallback(ctx, target, name)
	if err != nil {
		return "", &dialError{fmt.Errorf("callback to %s (as %s) failed: %w", target.Dial, name, err)}
	}
	defer func() { _ = cc.close() }()

	// From here on the peer has proven it holds a certificate for name, so
	// what went wrong is told to the requester.
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

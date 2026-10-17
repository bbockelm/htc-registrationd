package ce

import (
	"context"
	"errors"
	"fmt"
	"time"

	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/secret"
)

// liveRequest is a callback-mode request this daemon made and is waiting to be
// called back for. The Nonce never leaves the process except as the answer to
// a callback carrying the matching RequestId.
type liveRequest struct {
	nonce     string
	requestID string        // set once the registrar's first reply arrives
	ready     chan struct{} // closed when requestID is set
	done      chan error    // receives the outcome of the token install
	used      bool
}

// readyWait bounds how long a callback waits for this daemon to record the
// RequestId of a request it just made: the registrar dials as soon as it has
// replied, so the callback can arrive before the reply is processed.
const readyWait = 5 * time.Second

func (m *Manager) addLive(nonce string) *liveRequest {
	lr := &liveRequest{nonce: nonce, ready: make(chan struct{}), done: make(chan error, 1)}
	m.mu.Lock()
	m.live[lr] = struct{}{}
	m.mu.Unlock()
	return lr
}

func (m *Manager) removeLive(lr *liveRequest) {
	m.mu.Lock()
	delete(m.live, lr)
	m.mu.Unlock()
}

func (m *Manager) setRequestID(lr *liveRequest, id string) {
	m.mu.Lock()
	lr.requestID = id
	m.mu.Unlock()
	close(lr.ready)
}

// claimLive finds and consumes the live request with requestID, comparing in
// constant time. A request is answered at most once.
func (m *Manager) claimLive(ctx context.Context, requestID string) *liveRequest {
	deadline := time.Now().Add(readyWait)
	for {
		var waiting []chan struct{}
		m.mu.Lock()
		for lr := range m.live {
			if lr.used {
				continue
			}
			if lr.requestID == "" {
				waiting = append(waiting, lr.ready)
				continue
			}
			if secret.Equal(lr.requestID, requestID) {
				lr.used = true
				m.mu.Unlock()
				return lr
			}
		}
		m.mu.Unlock()
		if len(waiting) == 0 || time.Now().After(deadline) {
			return nil
		}
		select {
		case <-waiting[0]:
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return nil
		}
	}
}

// requestCallback runs a callback-mode request: REG_REQUEST carries this
// daemon's own sinful and a fresh Nonce; the registrar replies with a
// RequestId, calls back (HandleCallback installs the token), then reports the
// outcome on the request connection. The token never arrives on that
// connection.
func (m *Manager) requestCallback(ctx context.Context) error {
	addr, err := m.cfg.CallbackAddress()
	if err != nil {
		return fmt.Errorf("callback address: %w", err)
	}
	nonce, err := secret.NewSecret()
	if err != nil {
		return err
	}
	lr := m.addLive(nonce)
	defer m.removeLive(lr)
	m.setStatus(func(s *Status) { s.State = StateCallbackPending })

	cl, err := m.dialRegistrar(ctx, protocol.RegRequest)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	st := cl.GetStream()
	if err := protocol.Send(ctx, st, &protocol.Request{
		Name: m.cfg.Name, Method: protocol.MethodCallback, CallbackAddress: addr, Nonce: nonce,
		CEVersion: m.cfg.Version,
	}); err != nil {
		return err
	}
	var reply protocol.RequestReply
	if err := protocol.Recv(ctx, st, &reply); err != nil {
		return err
	}
	if reply.Status != protocol.StatusCallbackPending || reply.RequestID == "" {
		return fmt.Errorf("callback request refused: %w", replyErr(reply.Status, reply.Error))
	}
	m.setRequestID(lr, reply.RequestID)

	waitCtx, cancel := context.WithTimeout(ctx, m.cur().CallbackWait)
	defer cancel()
	var outcome protocol.CallbackOutcome
	recvErr := protocol.Recv(waitCtx, st, &outcome)

	// The handler signals before it acknowledges, so by the time the outcome
	// arrives the install result is already here.
	var installErr error
	installed := false
	select {
	case installErr = <-lr.done:
		installed = installErr == nil
	default:
	}
	switch {
	case installed:
		registrar := m.cur().Registrar
		if err := m.update(func(s *State) {
			s.Method, s.Name, s.Registrar = MethodCallback, m.cfg.Name, registrar
			s.clearRegistration()
			s.clearRequest()
		}); err != nil {
			// The install already saved the token's state; only the method
			// bookkeeping is lost, and the next renewal rewrites it.
			m.log.Warn("ce: recording the callback registration", "err", err)
		}
		m.log.Info("ce: registered by callback", "name", m.cfg.Name)
		_ = m.reconfig(ctx)
		m.succeeded()
		return nil
	case installErr != nil:
		return fmt.Errorf("installing the delivered token: %w", installErr)
	case recvErr != nil:
		return fmt.Errorf("waiting for the callback outcome: %w", recvErr)
	case outcome.Status == protocol.StatusFailed:
		return fmt.Errorf("the registrar's callback failed: %s", outcome.Message)
	}
	return errors.New("the registrar reported success but no token was delivered")
}

// HandleCallback serves REG_CALLBACK. The registrar authenticated this
// daemon's SSL host certificate; this handler checks the RequestId is one of
// its own live requests, answers with that request's Nonce, receives and
// installs the token, and acknowledges.
func (m *Manager) HandleCallback(ctx context.Context, c *cedarserver.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if c.Negotiation == nil || !c.Negotiation.Encryption {
		_ = protocol.Send(ctx, c.Stream, &protocol.CallbackProof{Status: protocol.StatusError,
			Error: *protocol.Err(protocol.ErrNotEncrypted, "REG_CALLBACK requires an encrypted session")})
		return errors.New("REG_CALLBACK on an unencrypted session")
	}
	var hello protocol.CallbackHello
	if err := protocol.Recv(ctx, c.Stream, &hello); err != nil || hello.RequestID == "" {
		_ = protocol.Send(ctx, c.Stream, &protocol.CallbackProof{Status: protocol.StatusError,
			Error: *protocol.Err(protocol.ErrBadRequest, "REG_CALLBACK needs a RequestId")})
		return fmt.Errorf("REG_CALLBACK: bad hello: %w", err)
	}
	lr := m.claimLive(ctx, hello.RequestID)
	if lr == nil {
		m.log.Warn("ce: REG_CALLBACK with an unknown RequestId refused", "remote", c.RemoteAddr)
		_ = protocol.Send(ctx, c.Stream, &protocol.CallbackProof{Status: protocol.StatusError,
			Error: *protocol.Err(protocol.ErrUnknown, "no live request with that RequestId")})
		return errors.New("REG_CALLBACK: unknown RequestId")
	}
	if err := protocol.Send(ctx, c.Stream, &protocol.CallbackProof{Status: protocol.StatusOK, Nonce: lr.nonce}); err != nil {
		lr.done <- err
		return err
	}
	var d protocol.CallbackDelivery
	if err := protocol.Recv(ctx, c.Stream, &d); err != nil {
		lr.done <- err
		return err
	}
	if d.Token == "" {
		err := errors.New("no token delivered")
		lr.done <- err
		_ = protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusError,
			Error: *protocol.Err(protocol.ErrBadRequest, "no Token")})
		return err
	}
	err := m.installToken(d.Token)
	lr.done <- err
	if err != nil {
		m.log.Error("ce: installing the token delivered by callback", "err", err.Error())
		_ = protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusError,
			Error: *protocol.Err(protocol.ErrInternal, "%v", err)})
		return err
	}
	// The request may have given up waiting for the outcome by now, in which
	// case nobody else reconfigures for this token: wake the run loop, whose
	// next step reconfigures for any token installed since the last one.
	m.wakeUp()
	return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK})
}

// statusAd is the REG_STATUS reply.
type statusAd struct {
	State          string `ad:"State"`
	Method         string `ad:"Method"`
	Name           string `ad:"Name"`
	Registrar      string `ad:"Registrar"`
	RegistrationID string `ad:"RegistrationId"`
	TokenFile      string `ad:"TokenFile"`
	TokenExpiry    int64  `ad:"TokenExpiry"`
	NextRenewal    int64  `ad:"NextRenewal"`
	LastSuccess    int64  `ad:"LastSuccess"`
	LastError      string `ad:"LastError"`
	LastErrorTime  int64  `ad:"LastErrorTime"`
	ApprovalURL    string `ad:"ApprovalURL"`
	UserCode       string `ad:"UserCode"`
	RequestExpires int64  `ad:"RequestExpires"`
	LastPingTime   int64  `ad:"LastPingTime"`
	LastPingResult string `ad:"LastPingResult"`
	UpdatedAt      int64  `ad:"UpdatedAt"`
}

// StatusReply is the decoded REG_STATUS reply, for the CLI.
type StatusReply = statusAd

// HandleStatus serves REG_STATUS (READ).
func (m *Manager) HandleStatus(ctx context.Context, c *cedarserver.Conn) error {
	s := m.Status()
	return protocol.Send(ctx, c.Stream, &statusAd{
		State: s.State, Method: s.Method, Name: s.Name, Registrar: s.Registrar, RegistrationID: s.RegistrationID,
		TokenFile: s.TokenFile, TokenExpiry: s.TokenExpiry, NextRenewal: s.NextRenewal, LastSuccess: s.LastSuccess,
		LastError: s.LastError, LastErrorTime: s.LastErrorTime, ApprovalURL: s.ApprovalURL, UserCode: s.UserCode,
		RequestExpires: s.RequestExpires, LastPingTime: s.LastPingTime, LastPingResult: s.LastPingResult,
		UpdatedAt: s.UpdatedAt,
	})
}

// HandleRenewNow serves REG_RENEW_NOW (ADMINISTRATOR).
func (m *Manager) HandleRenewNow(ctx context.Context, c *cedarserver.Conn) error {
	m.log.Info("ce: REG_RENEW_NOW received", "remote", c.RemoteAddr, "user", c.AuthorizationUser())
	m.RenewNow()
	return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK, Hint: "renewal scheduled"})
}

// requestApprovalWait bounds how long REG_REQUEST_APPROVAL waits for the
// registrar to answer before replying without a URL.
const requestApprovalWait = 45 * time.Second

// HandleRequestApproval serves REG_REQUEST_APPROVAL (ADMINISTRATOR): start an
// approval-mode request now, or report the one already pending, and reply
// with its URL and code.
func (m *Manager) HandleRequestApproval(ctx context.Context, c *cedarserver.Conn) error {
	m.log.Info("ce: REG_REQUEST_APPROVAL received", "remote", c.RemoteAddr, "user", c.AuthorizationUser())
	done := m.RequestApproval()
	wctx, cancel := context.WithTimeout(ctx, requestApprovalWait)
	defer cancel()
	select {
	case err := <-done:
		if err != nil {
			return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusError,
				Error: protocol.Error{Code: protocol.ErrInternal, Message: "approval request failed: " + err.Error()}})
		}
	case <-wctx.Done():
		return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK,
			Hint: "approval request scheduled; the registrar has not answered yet (see htc-registration status)"})
	}
	s := m.Status()
	hint := "approve at " + s.ApprovalURL
	if s.RequestExpires != 0 {
		hint += " before " + time.Unix(s.RequestExpires, 0).UTC().Format(time.RFC3339)
	}
	return protocol.Send(ctx, c.Stream, &protocol.Ack{Status: protocol.StatusOK, Hint: hint})
}

// Register installs the CE's commands on srv.
func (m *Manager) Register(srv *cedarserver.Server) {
	srv.Handle(protocol.RegCallback, m.HandleCallback, "ALLOW")
	srv.Handle(protocol.RegStatus, m.HandleStatus, "READ")
	srv.Handle(protocol.RegRenewNow, m.HandleRenewNow, "ADMINISTRATOR")
	srv.Handle(protocol.RegRequestApproval, m.HandleRequestApproval, "ADMINISTRATOR")
}

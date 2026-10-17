// Package cedarx holds the cedar client plumbing the registrar and the CE
// share: an SSL-only, encryption-required client config, and a single-attempt
// dial that checks what the handshake actually negotiated.
package cedarx

import (
	"context"
	"fmt"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// SSLOnly returns a copy of base for one connection that must authenticate
// the server by its SSL certificate: SSL is the only method, authentication,
// encryption and integrity are required, the server certificate is verified
// against serverName (empty: cedar derives it from the address), this side
// presents neither a certificate nor a token, and the session cache is
// private so the handshake is never a resumption (which would skip the
// certificate check).
func SSLOnly(base *security.SecurityConfig, cmd int, serverName, peer string) *security.SecurityConfig {
	var sc security.SecurityConfig
	if base != nil {
		sc = *base
	}
	sc.Command = cmd
	sc.AuthCommand = 0
	sc.AuthMethods = []security.AuthMethod{security.AuthSSL}
	sc.Authentication = security.SecurityRequired
	sc.Encryption = security.SecurityRequired
	sc.Integrity = security.SecurityRequired
	if len(sc.CryptoMethods) == 0 {
		sc.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
	}
	sc.ServerName = serverName
	sc.PeerName = peer
	sc.CertFile, sc.KeyFile = "", ""
	sc.Token, sc.TokenFile, sc.TokenDir = "", "", ""
	sc.SessionCache = security.NewSessionCache()
	sc.SessionID = ""
	sc.PostAuthPolicy, sc.CommandPerms = nil, nil
	return &sc
}

// DialSSL connects to cfg.Address once (no retry: ConnectAndAuthenticate
// dials again after a failed connect), runs the handshake, and refuses the
// connection unless it negotiated SSL with encryption.
func DialSSL(ctx context.Context, cfg *client.ClientConfig) (*client.HTCondorClient, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	cl := client.NewClient(cfg)
	connectCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	err := cl.Connect(connectCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	neg, err := security.NewAuthenticator(cfg.Security, cl.GetStream()).ClientHandshake(ctx)
	if err != nil {
		_ = cl.Close()
		return nil, err
	}
	if neg.NegotiatedAuth != security.AuthSSL || !neg.Encryption {
		_ = cl.Close()
		return nil, fmt.Errorf("session negotiated auth=%q encrypted=%t; SSL and encryption are required",
			neg.NegotiatedAuth, neg.Encryption)
	}
	return cl, nil
}

// HardenCommands makes srv negotiate cmds with SSL as the only method and
// authentication, encryption and integrity required, layered over whatever
// per-command policy srv already has (e.g. daemon.InstallSecurityLevels). Call
// it after installing that policy. Handlers should still check
// Negotiation.Encryption: a kept-alive session is re-checked by cedar, but the
// check is cheap and keeps the rule local to the handler.
func HardenCommands(srv *cedarserver.Server, cmds ...int) {
	set := make(map[int]bool, len(cmds))
	for _, c := range cmds {
		set[c] = true
	}
	prev := srv.SecurityConfigForCommand
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		var sc *security.SecurityConfig
		if prev != nil {
			sc = prev(cmd)
		}
		if !set[cmd] {
			return sc
		}
		if sc == nil {
			sc = srv.SecurityConfig
		}
		c := *sc
		c.AuthMethods = []security.AuthMethod{security.AuthSSL}
		c.Authentication = security.SecurityRequired
		c.Encryption = security.SecurityRequired
		c.Integrity = security.SecurityRequired
		if len(c.CryptoMethods) == 0 {
			c.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
		}
		return &c
	}
}

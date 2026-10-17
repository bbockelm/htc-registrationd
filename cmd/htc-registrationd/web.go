package main

import (
	"context"
	"log/slog"
	"net"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"

	"github.com/bbockelm/htc-registrationd/internal/authz"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/webui"
)

// registrarWeb is the registrar's authorization backends
// (HTC_REGISTRATIOND_AUTHZ, HTC_REGISTRATIOND_ADMINS) and its approval web
// UI (the shared port, HTC_REGISTRATIOND_HTTPS_ADDR, HTTP_ADDR).
type registrarWeb struct {
	log    *slog.Logger
	policy *authz.Policy
	web    *webui.Config
}

// sharedPort is the listener for HTTP and TLS connections forwarded by the
// shared port, or nil when SHARED_PORT_HTTP_FORWARDING_ID does not name
// this daemon.
func newRegistrarWeb(d *daemon.Daemon, cfg *config.Config, sharedPort net.Listener) (*registrarWeb, error) {
	log := d.Slog()
	policy, err := authz.FromConfig(cfg, log)
	if err != nil {
		return nil, err
	}
	web, err := webui.FromConfig(cfg, sharedPort != nil)
	if err != nil {
		return nil, err
	}
	return &registrarWeb{log: log, policy: policy, web: web}, nil
}

// namePolicy is the HTC_REGISTRATIOND_CALLBACK_NAMES = authz policy: a
// name must be known to a backend.
func (w *registrarWeb) namePolicy() registrar.NamePolicy {
	if len(w.policy.Backends()) == 0 {
		w.log.Warn("HTC_REGISTRATIOND_CALLBACK_NAMES = authz, but HTC_REGISTRATIOND_AUTHZ names no backend; " +
			"callback registrations will be refused. Set HTC_REGISTRATIOND_AUTHZ, or set " +
			"HTC_REGISTRATIOND_CALLBACK_NAMES = any to accept every name proven by a trusted certificate.")
		return registrar.AuthzNames{}
	}
	return registrar.AuthzNames{Known: w.policy.Known}
}

// approvers re-checks web approvers against the backends at renewal;
// CEDAR (ADMINISTRATOR) approvals stay valid.
func (w *registrarWeb) approvers() registrar.ApproverPolicy {
	return registrar.TrustCEDARApprovers{Backend: w.policy}
}

// verificationURI is <public URL>/approve when the web UI is configured.
func (w *registrarWeb) verificationURI() string {
	if !w.web.Enabled() {
		return ""
	}
	return w.web.VerificationURI()
}

// start runs the backends and, if configured, the web UI. The returned
// function stops the web UI; it must run before the store is closed.
func (w *registrarWeb) start(ctx context.Context, d *daemon.Daemon, store *registrar.Store,
	sharedPort net.Listener) (func(), error) {
	w.policy.Start(ctx)
	if sharedPort != nil && !w.web.SharedPort {
		w.log.Warn("SHARED_PORT_HTTP_FORWARDING_ID names this daemon, but HTC_REGISTRATIOND_PUBLIC_URL is not set; " +
			"forwarded HTTP and TLS connections are closed")
		_ = sharedPort.Close()
	}
	var srv *webui.Server
	stop := func() {}
	if w.web.Enabled() {
		if len(w.policy.Backends()) == 0 && !w.policy.HasAdmins() {
			w.log.Warn("the web UI is enabled, but neither HTC_REGISTRATIOND_AUTHZ nor HTC_REGISTRATIOND_ADMINS " +
				"is set; nobody can approve a request in it")
		}
		c := *w.web
		c.Store, c.Authz, c.Logger = store, w.policy, w.log
		var err error
		if srv, err = webui.New(ctx, c); err != nil {
			return nil, err
		}
		if stop, err = srv.Start(ctx, sharedPort); err != nil {
			return nil, err
		}
	}
	d.OnReconfig(func(newCfg *config.Config) {
		w.policy.Reconfig(newCfg)
		if srv != nil {
			srv.Reload()
		}
	})
	w.log.Info("registrar authorization", "backends", w.policy.Backends(), "web_ui", w.web.Enabled(),
		"public_url", w.web.PublicURL, "web_ui_on_shared_port", w.web.SharedPort)
	return stop, nil
}

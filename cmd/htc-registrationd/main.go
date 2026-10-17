// Command htc-registrationd bootstraps CE → CE-Collector authentication.
//
// One binary, two daemon modes (-mode or HTC_REGISTRATIOND_MODE):
//
//   - ce: runs under an HTCondor-CE's condor_ce_master; requests, receives,
//     installs and renews an IDTOKEN for the CE's name;
//   - registrar: runs under the CE-Collector's master; verifies requests, mints
//     tokens and rotates refresh secrets.
//
// Invoked as htc-registration (or as "htc-registrationd cli ..."), it is the
// command-line tool; see cli.go.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"

	"github.com/bbockelm/htc-registrationd/internal/ce"
	"github.com/bbockelm/htc-registrationd/internal/cedarx"
	"github.com/bbockelm/htc-registrationd/internal/knobs"
	"github.com/bbockelm/htc-registrationd/internal/mint"
	"github.com/bbockelm/htc-registrationd/internal/protocol"
	"github.com/bbockelm/htc-registrationd/internal/registrar"
	"github.com/bbockelm/htc-registrationd/internal/ssrf"
)

// Subsys is the HTCondor subsystem name: it selects HTC_REGISTRATIOND_LOG,
// HTC_REGISTRATIOND_DEBUG, the address file and the ALLOW_* scoping.
const Subsys = "HTC_REGISTRATIOND"

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if filepath.Base(os.Args[0]) == "htc-registration" {
		os.Exit(runCLI(os.Args[1:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "cli" {
		os.Exit(runCLI(os.Args[2:]))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "htc-registrationd:", err)
		os.Exit(1)
	}
}

func run() error {
	modeFlag := flag.String("mode", "", "ce or registrar (default: HTC_REGISTRATIOND_MODE)")
	listen := flag.String("listen", ":0", "fallback TCP listen address when not inheriting a shared-port endpoint")
	showVersion := flag.Bool("version", false, "print version and exit")
	localName := flag.String("local-name", "", "HTCondor local-name; passed by condor_master")
	_ = flag.String("sock", "", "shared-port endpoint name; accepted for compatibility (fd inherited via CONDOR_INHERIT)")
	flag.Parse()
	if *showVersion {
		fmt.Println("htc-registrationd", version)
		return nil
	}

	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: Subsys, LocalName: *localName})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	mode := *modeFlag
	if mode == "" {
		mode = strings.ToLower(knobs.String(cfg, "HTC_REGISTRATIOND_MODE", ""))
	}
	if mode != "ce" && mode != "registrar" {
		return fmt.Errorf("set -mode or HTC_REGISTRATIOND_MODE to ce or registrar (got %q)", mode)
	}

	d, err := daemon.New(daemon.Options{Subsys: Subsys, LocalName: *localName, Config: cfg})
	if err != nil {
		return err
	}
	slog.SetDefault(d.Slog())
	log := d.Slog()

	ln, err := d.Listener(func() (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(context.Background(), "tcp", *listen)
	})
	if err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	defer func() { _ = ln.Close() }()

	sec, err := d.ServerSecurityConfig(protocol.RegStatus, "DEFAULT")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}
	sec.RemoteVersion = daemon.CondorVersion()
	srv := cedarserver.New(sec)
	if err := d.InstallSecurityLevels(srv); err != nil {
		return fmt.Errorf("building per-level security config: %w", err)
	}

	var policy atomic.Pointer[authz.Policy]
	p, err := authz.NewPolicy(cfg, Subsys)
	if err != nil {
		return fmt.Errorf("building authorization policy: %w", err)
	}
	policy.Store(p)
	srv.Authorizer = func(perm, peer, user string) bool { return policy.Load().Authorize(perm, peer, user) }
	if dom := knobs.String(cfg, "UID_DOMAIN", ""); dom != "" {
		// FS yields a bare user name; qualify it with UID_DOMAIN, as C++ does,
		// so ALLOW_* user@host entries match.
		srv.FQUMapper = func(authUser, _ string) string {
			if authUser == "" || strings.ContainsRune(authUser, '@') {
				return ""
			}
			return authUser + "@" + dom
		}
	}
	d.OnReconfig(func(newCfg *config.Config) {
		np, perr := authz.NewPolicy(newCfg, Subsys)
		if perr != nil {
			log.Error("reconfigure: keeping the old authorization policy", "err", perr)
		} else {
			policy.Store(np)
		}
		if r, ok := sec.Credentials.(htcondor.CredentialReloader); ok {
			r.Reload()
		}
	})
	d.RegisterDefaultCommands(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch mode {
	case "registrar":
		closeFn, err := setupRegistrar(ctx, d, cfg, srv)
		if err != nil {
			return err
		}
		defer closeFn()
	case "ce":
		if err := setupCE(ctx, d, cfg, srv, ln); err != nil {
			return err
		}
	}
	// Every command that carries a nonce, request id, refresh secret or token
	// negotiates SSL-only with encryption required, layered over the
	// per-level policy installed above.
	cedarx.HardenCommands(srv, protocol.EncryptedCommands...)

	if path := writeAddressFile(d, cfg, ln); path != "" {
		defer func() { _ = os.Remove(path) }()
	}
	log.Info("htc-registrationd starting", "mode", mode, "version", version,
		"listen", ln.Addr().String(), "address", advertisedAddr(d, ln), "under_master", d.UnderMaster())
	return d.Serve(ctx, ln, srv.Serve)
}

func advertisedAddr(d *daemon.Daemon, ln net.Listener) string {
	if s, ok := d.AdvertisedSinful(); ok {
		return s
	}
	return ln.Addr().String()
}

func writeAddressFile(d *daemon.Daemon, cfg *config.Config, ln net.Listener) string {
	path := htcondor.AddressFilePath(cfg, Subsys)
	if path == "" {
		return ""
	}
	if err := os.WriteFile(path, []byte("<"+strings.Trim(advertisedAddr(d, ln), "<>")+">\n"), 0o644); err != nil { //nolint:gosec // HTCondor address files are world-readable
		d.Slog().Warn("could not write the address file", "path", path, "err", err)
		return ""
	}
	return path
}

// stateDir resolves HTC_REGISTRATIOND_STATE_DIR (default
// $(SPOOL)/htc-registrationd), creates it 0700 and warns when condor_preen
// would remove it.
func stateDir(cfg *config.Config, log *slog.Logger) (string, error) {
	dir := knobs.String(cfg, "HTC_REGISTRATIOND_STATE_DIR", "")
	if dir == "" {
		spool := knobs.String(cfg, "SPOOL", "")
		if spool == "" {
			return "", errors.New("neither HTC_REGISTRATIOND_STATE_DIR nor SPOOL is set")
		}
		dir = filepath.Join(spool, "htc-registrationd")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating state directory %s: %w", dir, err)
	}
	if w := knobs.SpoolWarning(cfg, dir); w != "" {
		log.Warn(w)
	}
	return dir, nil
}

func trustDomain(cfg *config.Config) string {
	return knobs.String(cfg, "TRUST_DOMAIN", knobs.String(cfg, "UID_DOMAIN", ""))
}

// clientSecurity is the base client security config for outbound SSL
// connections: the pool's CLIENT policy, with the CA file named by
// caKnob or else AUTH_SSL_CLIENT_CAFILE (empty: system roots).
func clientSecurity(cfg *config.Config, cmd int, caKnob string) func() *security.SecurityConfig {
	return func() *security.SecurityConfig {
		sc, err := htcondor.GetSecurityConfig(cfg, cmd, "CLIENT")
		if err != nil || sc == nil {
			sc = &security.SecurityConfig{}
		}
		sc.CAFile = knobs.String(cfg, caKnob, knobs.String(cfg, "AUTH_SSL_CLIENT_CAFILE", ""))
		return sc
	}
}

func setupRegistrar(ctx context.Context, d *daemon.Daemon, cfg *config.Config, srv *cedarserver.Server) (func(), error) {
	log := d.Slog()
	dir, err := stateDir(cfg, log)
	if err != nil {
		return nil, err
	}
	store, err := registrar.OpenStore(filepath.Join(dir, "registrar.db"), nil)
	if err != nil {
		return nil, err
	}

	lifetime, err := knobs.Duration(cfg, "HTC_REGISTRATIOND_TOKEN_LIFETIME", 72*time.Hour)
	if err != nil {
		return nil, err
	}
	m := &mint.Minter{
		KeyDir:   knobs.String(cfg, "SEC_PASSWORD_DIRECTORY", ""),
		KeyID:    knobs.String(cfg, "HTC_REGISTRATIOND_SIGNING_KEY", "ce-registration"),
		Issuer:   trustDomain(cfg),
		Domain:   knobs.String(cfg, "HTC_REGISTRATIOND_IDENTITY_DOMAIN", knobs.String(cfg, "UID_DOMAIN", "")),
		Limits:   knobs.List(cfg, "HTC_REGISTRATIOND_TOKEN_LIMITS", []string{"ADVERTISE_SCHEDD"}),
		Lifetime: lifetime,
	}
	if err := m.Check(); err != nil {
		log.Error("the signing key is not usable; every issuance will fail until it is", "err", err)
	}

	allow, err := ssrf.ParseAllowList(knobs.String(cfg, "HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS", ""))
	if err != nil {
		return nil, fmt.Errorf("HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS: %w", err)
	}

	var names registrar.NamePolicy
	switch v := strings.ToLower(knobs.String(cfg, "HTC_REGISTRATIOND_CALLBACK_NAMES", "authz")); v {
	case "any":
		names = registrar.AnyName{}
	case "authz":
		names = registrar.AuthzNames{}
		log.Warn("HTC_REGISTRATIOND_CALLBACK_NAMES = authz, but this build has no authorization backend " +
			"(mapfile/topology); callback registrations will be refused. Set it to any to accept every name " +
			"proven by a trusted certificate.")
	default:
		return nil, fmt.Errorf("HTC_REGISTRATIOND_CALLBACK_NAMES must be authz or any, not %q", v)
	}
	if v := knobs.String(cfg, "HTC_REGISTRATIOND_AUTHZ", ""); v != "" {
		log.Warn("HTC_REGISTRATIOND_AUTHZ is set but this build implements no authorization backend yet", "value", v)
	}

	recheck, err := knobs.Bool(cfg, "HTC_REGISTRATIOND_RECHECK_APPROVER", true)
	if err != nil {
		return nil, err
	}
	var maxAge, connectTO, callbackTO, approvalTTL, unclaimed, poll time.Duration
	for knob, spec := range map[string]struct {
		dst *time.Duration
		def time.Duration
	}{
		"HTC_REGISTRATIOND_MAX_REGISTRATION_AGE":     {&maxAge, 0},
		"HTC_REGISTRATIOND_CALLBACK_CONNECT_TIMEOUT": {&connectTO, 10 * time.Second},
		"HTC_REGISTRATIOND_CALLBACK_TIMEOUT":         {&callbackTO, 30 * time.Second},
		"HTC_REGISTRATIOND_APPROVAL_TTL":             {&approvalTTL, 30 * time.Minute},
		"HTC_REGISTRATIOND_UNCLAIMED_TTL":            {&unclaimed, 24 * time.Hour},
		"HTC_REGISTRATIOND_POLL_INTERVAL":            {&poll, 5 * time.Second},
	} {
		v, err := knobs.Duration(cfg, knob, spec.def)
		if err != nil {
			return nil, err
		}
		*spec.dst = v
	}
	perIP, err := knobs.Int(cfg, "HTC_REGISTRATIOND_MAX_PENDING_PER_IP", 10)
	if err != nil {
		return nil, err
	}
	total, err := knobs.Int(cfg, "HTC_REGISTRATIOND_MAX_PENDING", 1000)
	if err != nil {
		return nil, err
	}
	verify := knobs.String(cfg, "HTC_REGISTRATIOND_VERIFICATION_URI", "")
	if verify == "" {
		if host := knobs.String(cfg, "FULL_HOSTNAME", ""); host != "" {
			verify = "https://" + host + "/approve"
		}
	}

	svc, err := registrar.New(registrar.Config{
		Minter:                 m,
		SSRF:                   ssrf.New(allow),
		Names:                  names,
		Approvers:              registrar.TrustCEDARApprovers{},
		RecheckApprover:        recheck,
		MaxRegistrationAge:     maxAge,
		CallbackSecurity:       clientSecurity(cfg, protocol.RegCallback, "HTC_REGISTRATIOND_CALLBACK_CAFILE"),
		CallbackConnectTimeout: connectTO,
		CallbackTimeout:        callbackTO,
		MaxPendingPerIP:        perIP,
		MaxPending:             total,
		ApprovalTTL:            approvalTTL,
		UnclaimedTTL:           unclaimed,
		PollInterval:           poll,
		VerificationURI:        verify,
		Logger:                 log,
	}, store)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	svc.Register(srv)
	go svc.Maintain(ctx, time.Minute)
	log.Info("registrar ready", "state_dir", dir, "signing_key", m.KeyID, "issuer", m.Issuer,
		"subject_domain", m.Domain, "limits", strings.Join(m.Limits, ","), "lifetime", lifetime.String(),
		"callback_allow", len(allow))
	return func() { _ = store.Close() }, nil
}

// sslServerAvailable reports whether the CE has an SSL server credential: SSL
// is among the server's authentication methods and one of the configured
// certificate/key candidate pairs loads. The pairs are read through the same
// credential reader cedar uses; which pair cedar would serve is cedar's
// decision, not this daemon's.
func sslServerAvailable(sc *security.SecurityConfig) (bool, string) {
	ssl := false
	for _, m := range sc.AuthMethods {
		if m == security.AuthSSL {
			ssl = true
		}
	}
	if !ssl {
		return false, "SSL is not an enabled authentication method"
	}
	if sc.CertFile == "" || sc.KeyFile == "" {
		return false, "no AUTH_SSL_SERVER_CERTFILE / AUTH_SSL_SERVER_KEYFILE configured"
	}
	read := os.ReadFile
	if sc.Credentials != nil {
		read = sc.Credentials.ReadCredential
	}
	certs, keys := splitList(sc.CertFile), splitList(sc.KeyFile)
	var lastErr error
	for i := 0; i < len(certs) && i < len(keys); i++ {
		c, err := read(certs[i])
		if err != nil {
			lastErr = err
			continue
		}
		k, err := read(keys[i])
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := tls.X509KeyPair(c, k); err != nil {
			lastErr = err
			continue
		}
		return true, ""
	}
	return false, fmt.Sprintf("no loadable SSL server certificate/key pair (%v)", lastErr)
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func setupCE(ctx context.Context, d *daemon.Daemon, cfg *config.Config, srv *cedarserver.Server, ln net.Listener) error {
	log := d.Slog()
	dir, err := stateDir(cfg, log)
	if err != nil {
		return err
	}
	name := knobs.String(cfg, "HTC_REGISTRATIOND_NAME",
		knobs.String(cfg, "SCHEDD_NAME", knobs.String(cfg, "FULL_HOSTNAME", "")))
	tokenDir := knobs.String(cfg, "SEC_TOKEN_SYSTEM_DIRECTORY", "")
	tokenFile := knobs.String(cfg, "HTC_REGISTRATIOND_TOKEN_FILE", "")
	if tokenFile == "" {
		if tokenDir == "" {
			return errors.New("SEC_TOKEN_SYSTEM_DIRECTORY is not set")
		}
		tokenFile = filepath.Join(tokenDir, "50-htc-registration")
	}
	serverSC, err := d.ServerSecurityConfig(protocol.RegCallback, "ALLOW")
	if err != nil {
		return err
	}
	mgr, err := ce.NewManager(ce.Config{
		Name:                name,
		Method:              strings.ToLower(knobs.String(cfg, "HTC_REGISTRATIOND_METHOD", ce.MethodAuto)),
		Registrar:           knobs.String(cfg, "HTC_REGISTRATIOND_REGISTRAR", ""),
		RegistrarServerName: knobs.String(cfg, "HTC_REGISTRATIOND_REGISTRAR_NAME", ""),
		StateDir:            dir,
		TokenFile:           tokenFile,
		Limits:              knobs.String(cfg, "HTC_REGISTRATIOND_TOKEN_LIMITS", "ADVERTISE_SCHEDD"),
		Version:             daemon.CondorVersion() + " htc-registrationd/" + version,
		CallbackAddress: func() (string, error) {
			if a := knobs.String(cfg, "HTC_REGISTRATIOND_CALLBACK_ADDRESS", ""); a != "" {
				return a, nil
			}
			if s, ok := d.AdvertisedSinful(); ok {
				return s, nil
			}
			return "", fmt.Errorf("no advertised address (not behind shared port); set HTC_REGISTRATIOND_CALLBACK_ADDRESS")
		},
		SSLServerAvailable: func() (bool, string) { return sslServerAvailable(serverSC) },
		ClientSecurity:     clientSecurity(cfg, protocol.RegRequest, "HTC_REGISTRATIOND_REGISTRAR_CAFILE"),
		Reconfig:           func(ctx context.Context) error { return reconfigMaster(ctx, d, cfg) },
		Ping:               pingViewHost(cfg),
		Logger:             log,
	})
	if err != nil {
		return err
	}
	mgr.Register(srv)
	go func() { _ = mgr.Run(ctx) }()
	log.Info("CE registration client ready", "name", name, "state_dir", dir, "token_file", tokenFile,
		"listen", ln.Addr().String())
	return nil
}

// reconfigMaster sends DC_RECONFIG_FULL to the local master, which re-reads
// tokens.d and reconfigures its children.
func reconfigMaster(ctx context.Context, d *daemon.Daemon, cfg *config.Config) error {
	addr := ""
	if m := d.Master(); m != nil {
		addr = m.Address()
	} else if path := htcondor.AddressFilePath(cfg, "MASTER"); path != "" {
		a, err := htcondor.ReadAddressFile(path)
		if err != nil {
			return err
		}
		addr = a
	}
	if addr == "" {
		return errors.New("cannot locate the local master")
	}
	ctx, cancel := context.WithTimeout(htcondor.WithDaemonCredential(ctx, "reconfigure the local master after a token install"), 30*time.Second)
	defer cancel()
	sc, err := htcondor.GetSecurityConfigOrDefault(ctx, cfg, commands.DC_RECONFIG_FULL, "CLIENT", addr)
	if err != nil {
		return err
	}
	cl, err := client.ConnectAndAuthenticate(ctx, addr, sc)
	if err != nil {
		return fmt.Errorf("connecting to the master at %s: %w", addr, err)
	}
	defer func() { _ = cl.Close() }()
	// DaemonCore's reconfig handler reads the end of the (empty) command message.
	if err := message.NewMessageForStream(cl.GetStream()).FinishMessage(ctx); err != nil {
		return fmt.Errorf("sending DC_RECONFIG_FULL: %w", err)
	}
	return nil
}

// pingViewHost returns a check of the installed token against
// CONDOR_VIEW_HOST at ADVERTISE_SCHEDD, or nil when there is no view host.
func pingViewHost(cfg *config.Config) func(context.Context) (string, error) {
	host := knobs.String(cfg, "CONDOR_VIEW_HOST", "")
	if host == "" {
		return nil
	}
	return func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(htcondor.WithDaemonCredential(ctx, "check the registration token"), 30*time.Second)
		defer cancel()
		res, err := htcondor.NewCollector(host).WithConfig(cfg).PingWithOptions(ctx,
			&htcondor.PingOptions{Command: htcondor.DCNopAdvertiseSchedd})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok: ADVERTISE_SCHEDD as %s via %s", res.User, res.AuthMethod), nil
	}
}

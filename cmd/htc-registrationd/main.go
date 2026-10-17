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
	"github.com/bbockelm/htc-registrationd/internal/portsplit"
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
	sock := flag.String("sock", "", "shared-port endpoint name; condor_master names the endpoint it hands this daemon after it")
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
	// webLn carries the HTTP and TLS connections HTCondor's shared port
	// forwards here when SHARED_PORT_HTTP_FORWARDING_ID names this daemon's
	// endpoint; CEDAR keeps the rest.
	var webLn net.Listener
	if id := d.SharedPortName(); id != "" && id == knobs.HTTPForwardingID(cfg) {
		split := portsplit.Split(ln, log)
		ln, webLn = split.CEDAR(), split.Web()
		log.Info("the shared port forwards HTTP and TLS connections to this daemon", "endpoint", id)
	}

	sec, err := d.ServerSecurityConfig(protocol.RegStatus, "DEFAULT")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}
	sec.RemoteVersion = daemon.CondorVersion()
	srv := cedarserver.New(sec)
	if err := d.InstallSecurityLevels(srv); err != nil {
		return fmt.Errorf("building per-level security config: %w", err)
	}

	// cur is the current configuration: everything read at connection or
	// request time reads it, so condor_reconfig takes effect without a
	// restart.
	var cur atomic.Pointer[config.Config]
	cur.Store(cfg)
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
		cur.Store(newCfg)
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
		closeFn, err := setupRegistrar(ctx, d, cfg, cur.Load, srv, webLn)
		if err != nil {
			return err
		}
		defer closeFn()
	case "ce":
		if webLn != nil {
			log.Warn("SHARED_PORT_HTTP_FORWARDING_ID names this daemon, which serves no web UI in ce mode; " +
				"forwarded HTTP and TLS connections are closed")
			_ = webLn.Close()
		}
		if err := setupCE(ctx, d, cfg, cur.Load, srv, ln); err != nil {
			return err
		}
	}
	// Every command that carries a nonce, request id, refresh secret or token
	// negotiates SSL-only with encryption required, layered over the
	// per-level policy installed above.
	cedarx.HardenCommands(srv, protocol.EncryptedCommands...)
	cedarx.RequireEncryption(srv, protocol.AdminCommands...)
	cedarx.ServerSSLTrust(func() knobs.Getter { return cur.Load() }, srv)
	if *sock != "" && d.SharedPortName() != *sock {
		log.Warn("not listening on the shared-port endpoint named by -sock; is HTC_REGISTRATIOND in DC_DAEMON_LIST?",
			"sock", *sock, "endpoint", d.SharedPortName())
	}

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

// writeAddressFile writes the address file the way DaemonCore does: to
// <path>.new, then renamed over <path>, so a reader never sees a partial one.
func writeAddressFile(d *daemon.Daemon, cfg *config.Config, ln net.Listener) string {
	path := htcondor.AddressFilePath(cfg, Subsys)
	if path == "" {
		return ""
	}
	if err := writeFileViaNew(path, []byte("<"+strings.Trim(advertisedAddr(d, ln), "<>")+">\n")); err != nil {
		d.Slog().Warn("could not write the address file", "path", path, "err", err)
		return ""
	}
	return path
}

func writeFileViaNew(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // HTCondor address files are world-readable
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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

// trustDomain is the issuer the registrar mints with: TRUST_DOMAIN, whose
// default comes from the configuration's parameter table as in HTCondor
// ($(UID_DOMAIN)). HTCondor refuses to mint without one and rejects tokens
// with an empty issuer, and an issuer may not contain white space or commas.
func trustDomain(cfg knobs.Getter) (string, error) {
	td := knobs.String(cfg, "TRUST_DOMAIN", "")
	if td == "" {
		return "", errors.New("TRUST_DOMAIN is not set; the registrar cannot mint tokens without an issuer")
	}
	if strings.ContainsAny(td, ", \t") {
		return "", fmt.Errorf("TRUST_DOMAIN %q may not contain spaces or commas", td)
	}
	return td, nil
}

// clientSecurity is the base client security config for outbound SSL
// connections: the pool's CLIENT policy in the current configuration,
// trusting what the AUTH_SSL_CLIENT_* CA knobs name.
func clientSecurity(cur func() *config.Config, cmd int) func() *security.SecurityConfig {
	return func() *security.SecurityConfig {
		cfg := cur()
		sc, err := htcondor.GetSecurityConfig(cfg, cmd, "CLIENT")
		if err != nil || sc == nil {
			sc = &security.SecurityConfig{}
		}
		cedarx.SSLTrust(cfg, "CLIENT", sc)
		return sc
	}
}

// registrarTunables reads the registrar settings a reconfig may change.
func registrarTunables(cfg knobs.Getter, web *registrarWeb) (registrar.Tunables, error) {
	t := registrar.Tunables{RecheckApprover: knobs.Bool(cfg, "HTC_REGISTRATIOND_RECHECK_APPROVER", true)}
	for knob, spec := range map[string]struct {
		dst *time.Duration
		def time.Duration
	}{
		"HTC_REGISTRATIOND_MAX_REGISTRATION_AGE":     {&t.MaxRegistrationAge, 0},
		"HTC_REGISTRATIOND_REFRESH_IDLE_LIFETIME":    {&t.RefreshIdleLifetime, 30 * 24 * time.Hour},
		"HTC_REGISTRATIOND_CALLBACK_CONNECT_TIMEOUT": {&t.CallbackConnectTimeout, 10 * time.Second},
		"HTC_REGISTRATIOND_CALLBACK_TIMEOUT":         {&t.CallbackTimeout, 30 * time.Second},
		"HTC_REGISTRATIOND_APPROVAL_TTL":             {&t.ApprovalTTL, 30 * time.Minute},
		"HTC_REGISTRATIOND_UNCLAIMED_TTL":            {&t.UnclaimedTTL, 24 * time.Hour},
		"HTC_REGISTRATIOND_POLL_INTERVAL":            {&t.PollInterval, 5 * time.Second},
	} {
		v, err := knobs.Duration(cfg, knob, spec.def)
		if err != nil {
			return t, err
		}
		*spec.dst = v
	}
	for knob, spec := range map[string]struct {
		dst *int
		def int
	}{
		"HTC_REGISTRATIOND_MAX_PENDING_PER_IP": {&t.MaxPendingPerIP, 10},
		"HTC_REGISTRATIOND_MAX_PENDING":        {&t.MaxPending, 1000},
		"HTC_REGISTRATIOND_MAX_REISSUES":       {&t.MaxReissues, 5},
	} {
		v, err := knobs.Int(cfg, knob, spec.def)
		if err != nil {
			return t, err
		}
		*spec.dst = v
	}
	t.VerificationURI = knobs.String(cfg, "HTC_REGISTRATIOND_VERIFICATION_URI", web.verificationURI())
	if t.VerificationURI == "" {
		if host := knobs.String(cfg, "FULL_HOSTNAME", ""); host != "" {
			t.VerificationURI = "https://" + host + "/approve"
		}
	}
	return t, nil
}

func setupRegistrar(ctx context.Context, d *daemon.Daemon, cfg *config.Config, cur func() *config.Config,
	srv *cedarserver.Server, webLn net.Listener) (func(), error) {
	log := d.Slog()
	issuer, err := trustDomain(cfg)
	if err != nil {
		return nil, err
	}
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
		KeyDir:      knobs.String(cfg, "SEC_PASSWORD_DIRECTORY", ""),
		PoolKeyFile: knobs.String(cfg, "SEC_TOKEN_POOL_SIGNING_KEY_FILE", ""),
		KeyID:       knobs.String(cfg, "HTC_REGISTRATIOND_SIGNING_KEY", "ce-registration"),
		Issuer:      issuer,
		Domain:      knobs.String(cfg, "HTC_REGISTRATIOND_IDENTITY_DOMAIN", knobs.String(cfg, "UID_DOMAIN", "")),
		Limits:      knobs.List(cfg, "HTC_REGISTRATIOND_TOKEN_LIMITS", []string{"ADVERTISE_SCHEDD"}),
		Lifetime:    lifetime,
	}
	// Like an HTCondor collector with its signing key, create the key when it
	// is missing, at startup and on every reconfig; an existing key is never
	// replaced.
	createKey := func() {
		if created, err := m.CreateKeyIfMissing(); err != nil {
			log.Error("could not create the token signing key", "err", err)
		} else if created {
			path, _ := m.KeyFile()
			log.Info("created the token signing key", "file", path)
		}
	}
	createKey()
	if err := m.Check(); err != nil {
		log.Error("the signing key is not usable; every issuance will fail until it is", "err", err)
	}

	allow, err := ssrf.ParseAllowList(knobs.String(cfg, "HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS", ""))
	if err != nil {
		return nil, fmt.Errorf("HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS: %w", err)
	}

	web, err := newRegistrarWeb(d, cfg, webLn)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	var names registrar.NamePolicy
	switch v := strings.ToLower(knobs.String(cfg, "HTC_REGISTRATIOND_CALLBACK_NAMES", "authz")); v {
	case "any":
		names = registrar.AnyName{}
	case "authz":
		names = web.namePolicy()
	default:
		return nil, fmt.Errorf("HTC_REGISTRATIOND_CALLBACK_NAMES must be authz or any, not %q", v)
	}

	tun, err := registrarTunables(cfg, web)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	svc, err := registrar.New(registrar.Config{
		Minter:           m,
		SSRF:             ssrf.New(allow),
		Names:            names,
		Approvers:        web.approvers(),
		CallbackSecurity: clientSecurity(cur, protocol.RegCallback),
		Tunables:         tun,
		Logger:           log,
	}, store)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	d.OnReconfig(func(newCfg *config.Config) {
		createKey()
		t, err := registrarTunables(newCfg, web)
		if err != nil {
			log.Error("reconfigure: keeping the previous registrar settings", "err", err)
			return
		}
		svc.Reconfigure(t)
	})
	svc.Register(srv)
	stopWeb, err := web.start(ctx, d, store, webLn)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	go svc.Maintain(ctx, time.Minute)
	log.Info("registrar ready", "state_dir", dir, "signing_key", m.KeyID, "issuer", m.Issuer,
		"subject_domain", m.Domain, "limits", strings.Join(m.Limits, ","), "lifetime", lifetime.String(),
		"callback_allow", len(allow))
	return func() { stopWeb(); _ = store.Close() }, nil
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

// tokenFile is where the CE installs its token: HTC_REGISTRATIOND_TOKEN_FILE,
// else 50-htc-registration in the directory the CE's daemons read tokens
// from. As in HTCondor's findTokens, SEC_TOKEN_DIRECTORY wins over
// SEC_TOKEN_SYSTEM_DIRECTORY when it is set.
func tokenFile(cfg knobs.Getter) (string, error) {
	if f := knobs.String(cfg, "HTC_REGISTRATIOND_TOKEN_FILE", ""); f != "" {
		return f, nil
	}
	dir := knobs.String(cfg, "SEC_TOKEN_DIRECTORY", knobs.String(cfg, "SEC_TOKEN_SYSTEM_DIRECTORY", ""))
	if dir == "" {
		return "", errors.New("neither SEC_TOKEN_DIRECTORY nor SEC_TOKEN_SYSTEM_DIRECTORY is set")
	}
	return filepath.Join(dir, "50-htc-registration"), nil
}

// ceSettings reads the CE settings a reconfig may change.
func ceSettings(cfg knobs.Getter) (ce.Settings, error) {
	file, err := tokenFile(cfg)
	if err != nil {
		return ce.Settings{}, err
	}
	s := ce.Settings{
		Method:              strings.ToLower(knobs.String(cfg, "HTC_REGISTRATIOND_METHOD", ce.MethodAuto)),
		Registrar:           knobs.String(cfg, "HTC_REGISTRATIOND_REGISTRAR", knobs.DefaultRegistrar(cfg)),
		RegistrarServerName: knobs.String(cfg, "HTC_REGISTRATIOND_REGISTRAR_NAME", ""),
		TokenFile:           file,
	}
	if s.ConnectTimeout, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_CONNECT_TIMEOUT", 30*time.Second); err != nil {
		return s, err
	}
	if s.CallbackWait, err = knobs.Duration(cfg, "HTC_REGISTRATIOND_CALLBACK_WAIT", 90*time.Second); err != nil {
		return s, err
	}
	return s, nil
}

func setupCE(ctx context.Context, d *daemon.Daemon, cfg *config.Config, cur func() *config.Config,
	srv *cedarserver.Server, ln net.Listener) error {
	log := d.Slog()
	dir, err := stateDir(cfg, log)
	if err != nil {
		return err
	}
	name, err := knobs.CEName(cfg, nil)
	if err != nil {
		return err
	}
	set, err := ceSettings(cfg)
	if err != nil {
		return err
	}
	serverSC, err := d.ServerSecurityConfig(protocol.RegCallback, "ALLOW")
	if err != nil {
		return err
	}
	mgr, err := ce.NewManager(ce.Config{
		Name:                name,
		Method:              set.Method,
		Registrar:           set.Registrar,
		RegistrarServerName: set.RegistrarServerName,
		StateDir:            dir,
		TokenFile:           set.TokenFile,
		ConnectTimeout:      set.ConnectTimeout,
		CallbackWait:        set.CallbackWait,
		Version:             version,
		CallbackAddress: func() (string, error) {
			if a := knobs.String(cur(), "HTC_REGISTRATIOND_CALLBACK_ADDRESS", ""); a != "" {
				return a, nil
			}
			if s, ok := d.AdvertisedSinful(); ok {
				return s, nil
			}
			return "", fmt.Errorf("no advertised address (not behind shared port); set HTC_REGISTRATIOND_CALLBACK_ADDRESS")
		},
		SSLServerAvailable: func() (bool, string) { return sslServerAvailable(serverSC) },
		ClientSecurity:     clientSecurity(cur, protocol.RegRequest),
		Reconfig:           func(ctx context.Context) error { return reconfigMaster(ctx, d, cur()) },
		Ping:               pingViewHost(cur),
		Logger:             log,
	})
	if err != nil {
		return err
	}
	d.OnReconfig(func(newCfg *config.Config) {
		set, err := ceSettings(newCfg)
		if err == nil {
			err = mgr.Reconfigure(set)
		}
		if err != nil {
			log.Error("reconfigure: keeping the previous settings", "err", err)
		}
		if n, err := knobs.CEName(newCfg, nil); err == nil && n != name {
			log.Warn("reconfigure: the CE name changed; restart the daemon to register the new name",
				"name", name, "new_name", n)
		}
	})
	mgr.Register(srv)
	go func() { _ = mgr.Run(ctx) }()
	log.Info("CE registration client ready", "name", name, "state_dir", dir, "token_file", set.TokenFile,
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

// pingViewHost returns a check of the installed token against the current
// CONDOR_VIEW_HOST at ADVERTISE_SCHEDD.
func pingViewHost(cur func() *config.Config) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		cfg := cur()
		host := knobs.String(cfg, "CONDOR_VIEW_HOST", "")
		if host == "" {
			return "no CONDOR_VIEW_HOST to check against", nil
		}
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

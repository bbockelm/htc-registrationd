# htc-registrationd

Bootstraps CE → CE-Collector authentication. An HTCondor-CE gets a short-lived
IDTOKEN for `<ce-name>@<domain>`, limited to `ADVERTISE_SCHEDD`, and renews it
automatically. It needs no client certificate.

One binary, two daemon modes:

| Mode | Runs under | Role |
|---|---|---|
| `ce` | the CE's `condor_ce_master` | requests, installs and renews the token |
| `registrar` | the CE-Collector's master | verifies requests, mints tokens, rotates refresh secrets |

Run as `htc-registration` (or `htc-registrationd cli ...`), the same binary is
the command-line tool.

A CE proves its name in one of two ways:

- **Callback**: the CE sends `REG_REQUEST` with its own sinful and a nonce. The
  registrar calls back over CEDAR, verifies the CE's *server* certificate
  against the requested name, checks the nonce, and delivers the token on the
  callback connection only. Renewal is a fresh exchange at half the token
  lifetime.
- **Approval**: the CE publishes an approval URL with a user code
  (`XXXX-XXXX`). An administrator opens the URL on the registrar's web UI,
  logs in with OIDC and approves it (or runs `htc-registration approve CODE`
  on the registrar), and the CE collects the token by polling.
  Renewal uses a refresh secret with two-phase rotation (current / pending /
  retired) that survives a crash at any point. A superseded secret that shows
  up again revokes the registration.

`auto` (the default) tries callback when an SSL server credential is available,
and falls back to approval.

## Build and test

```
make build        # bin/htc-registrationd, bin/htc-registration -> htc-registrationd
make test         # go test ./...
make test-race
make vet lint
make rpm          # dist/htc-registrationd-*.rpm (needs nfpm)
```

The RPM installs `/usr/sbin/htc-registrationd`, the `/usr/bin/htc-registration`
symlink, and two configuration files in `/etc/condor-ce/config.d/`:
`50-htc-registrationd-ce.conf` for a CE and
`50-htc-registrationd-registrar.conf` for the CE-Collector. Installing it
starts nothing: enable the daemon by uncommenting the `DAEMON_LIST` and
`HTC_REGISTRATIOND_MODE` lines in one of the two.

## Running under the master

The daemon must be a DaemonCore daemon to the master
(`DC_DAEMON_LIST = $(DC_DAEMON_LIST) +HTC_REGISTRATIOND`), so the master hands
it a shared-port endpoint. The master names that endpoint after the `-sock`
argument in `HTC_REGISTRATIOND_ARGS`; without one the name carries the
master's pid and a random tag and changes on every restart. Both shipped
configurations set `HTC_REGISTRATIOND_ARGS = -sock htc_registrationd`, so the
registrar is always at `<collector-host:port?sock=htc_registrationd>`.

The end-to-end tests in `internal/ce` run a registrar and a CE as two cedar
servers on loopback, using a generated test CA.

## Command numbers

77000-77013, defined in `internal/protocol`:

| Command | Number | Served by | Level |
|---|---|---|---|
| `REG_REQUEST` | 77000 | registrar | ALLOW, SSL + encryption |
| `REG_POLL` | 77001 | registrar | ALLOW, SSL + encryption |
| `REG_RENEW` | 77002 | registrar | ALLOW, SSL + encryption |
| `REG_CALLBACK` | 77003 | CE | ALLOW, SSL + encryption |
| `REG_STATUS` | 77004 | CE | READ |
| `REG_RENEW_NOW` | 77005 | CE | ADMINISTRATOR |
| `REG_REQUEST_APPROVAL` | 77006 | CE | ADMINISTRATOR |
| `REG_ADMIN_LIST` / `APPROVE` / `DENY` / `REVOKE` | 77010-77013 | registrar | ADMINISTRATOR |

## Configuration

All knobs are `HTC_REGISTRATIOND_*`. Durations are seconds, or Go durations
such as `72h`.

Both modes:

- `MODE`: `ce` or `registrar` (or `-mode`).
- `STATE_DIR`: default `$(SPOOL)/htc-registrationd`. Add `htc-registrationd`
  to `VALID_SPOOL_FILES` so that `condor_preen` keeps it. The daemon warns at
  startup if it is missing.

CE:

- `NAME`: default `$(SCHEDD_NAME)`, then `$(FULL_HOSTNAME)`. Must equal the
  Scheduler ad's `Name`.
- `METHOD`: `auto` | `callback` | `approval` (default `auto`).
- `REGISTRAR`: the registrar's address. Default: the host:port of the first
  `CONDOR_VIEW_HOST` entry (`COLLECTOR_PORT` when it names no port) with
  `sock=htc_registrationd`, e.g.
  `<collector.example.org:9619?sock=htc_registrationd>`. That is where a
  registrar running behind the CE-Collector's shared port listens, so a CE
  that already advertises to its CE-Collector needs no extra configuration.
- `REGISTRAR_NAME`: the name its certificate must carry. By default this is
  derived from the address.
- `CALLBACK_ADDRESS`: default: the daemon's shared-port sinful.
- `TOKEN_FILE`: default `$(SEC_TOKEN_SYSTEM_DIRECTORY)/50-htc-registration`.
  The daemon runs as condor and writes the file itself, so the directory must
  be writable by condor. On an HTCondor-CE it is `/etc/condor-ce/tokens.d`,
  which the CE package creates owned by condor, mode 0700.

Registrar:

- `SIGNING_KEY`: default `ce-registration`, the name of the signing key file
  in `SEC_PASSWORD_DIRECTORY`. When the file does not exist, the registrar
  creates it at startup and on every reconfig, as an HTCondor collector
  creates its own signing key: 64 random bytes, root-owned, mode 0600, in
  HTCondor's format. An existing file is never replaced. The collector on the
  same host reads the same file and so accepts the tokens. With two central
  collectors, copy the key file to the other one's `SEC_PASSWORD_DIRECTORY`
  (root-owned, mode 0600) and set the same `TRUST_DOMAIN` on both, so a token
  works on either. If a registrar there already created its own key, replace
  that file with the copy.
- `IDENTITY_DOMAIN`: default `$(UID_DOMAIN)`. The issuer is `TRUST_DOMAIN`.
- `TOKEN_LIMITS`: default `ADVERTISE_SCHEDD`.
- `TOKEN_LIFETIME`: default 72 h.
- `CALLBACK_NAMES`: `authz` | `any` (default `authz`: the name must be known
  to an `AUTHZ` backend; with no backend every callback is refused).
- `CALLBACK_ALLOW_NETWORKS`: CIDRs re-allowed for callbacks. Loopback, RFC
  1918, CGNAT, link-local, multicast, ULA, their IPv4-mapped / NAT64 / 6to4
  forms, and the registrar's own addresses are denied by default. The check
  runs at connect time on each address the callback actually dials, after
  the CE's host name is resolved.
- `CALLBACK_CONNECT_TIMEOUT` / `CALLBACK_TIMEOUT`: default 10 s / 30 s.
- `MAX_PENDING_PER_IP` / `MAX_PENDING`: default 10 / 1000.
- `APPROVAL_TTL` (30 min), `UNCLAIMED_TTL` (24 h), `POLL_INTERVAL` (5 s).
- `VERIFICATION_URI`: default `$(HTC_REGISTRATIOND_PUBLIC_URL)/approve` when
  the web UI is configured, else `https://$(FULL_HOSTNAME)/approve`. A CE is
  sent this and `<VERIFICATION_URI>?code=XXXX-XXXX`.
- `RECHECK_APPROVER` (true): at each approval-mode renewal, the person who
  approved the registration in the web UI must still be authorized for the
  name (an administrator, or allowed by an `AUTHZ` backend). Approvals made
  with `htc-registration approve` (CEDAR `ADMINISTRATOR`) are not re-checked.
- `MAX_REGISTRATION_AGE` (no cap).

Certificate trust uses the standard HTCondor knobs: `AUTH_SSL_CLIENT_CAFILE`,
`AUTH_SSL_CLIENT_CADIR` and `AUTH_SSL_CLIENT_USE_DEFAULT_CAS` (default true:
the system trust store is trusted too) for the connections the daemon makes,
the CE's to the registrar and the registrar's callbacks, and the
`AUTH_SSL_SERVER_*` variants for the connections it accepts.

### Web UI (registrar)

The registrar serves an approval page when a listener is configured. Login is
OpenID Connect (authorization code with PKCE, identity from the provider's
userinfo endpoint), done by the daemon itself; headers from a proxy are never
used as identity.

- `HTTPS_ADDR`, with `HTTPS_CERTFILE` and `HTTPS_KEYFILE`: the HTTPS listener,
  e.g. `:443`. The key may be root-only. A renewed certificate is picked up
  within a minute, and on `condor_reconfig`.
- `HTTP_ADDR`: a plain-HTTP listener on a loopback address (e.g.
  `127.0.0.1:8080`) for a reverse proxy that terminates TLS. The proxy must
  set `X-Forwarded-For`; on this listener its last entry is the address
  requests are rate-limited by, and it is used for nothing else.
- `PUBLIC_URL`: required; the `https://` origin browsers and CEs use, with no
  path (`http://` only for a loopback host).
- `OIDC_ISSUER`: the provider's issuer URL, read via
  `/.well-known/openid-configuration`. Register `<PUBLIC_URL>/oidc/callback`
  as the client's redirect URI.
- `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET_FILE` (may be root-only; re-read on
  reconfig).
- `OIDC_SCOPES`: default `openid email profile`. CILogon needs
  `openid email profile org.cilogon.userinfo` to release `osgid`.
- `OIDC_PRINCIPAL_CLAIM`: default `sub`. Configuration (`ADMINS`, the
  mapfile) names a user by this claim's value. With `sub`, the registrar
  records a user as `<issuer>,<sub>`, and a recorded user matches
  configuration only while `OIDC_ISSUER` is still that issuer. For OSG
  Topology, set `osgid`.
- `ADMINS`: registrar administrators, a comma- or space-separated list of
  users by `OIDC_PRINCIPAL_CLAIM` value. They may approve any name, and see
  and revoke every registration. Re-read on reconfig.
- `SESSION_IDLE` (1 h), `SESSION_LIFETIME` (12 h). Sessions are kept in the
  registrar's database; sign-ins in progress are kept in memory, so a
  restart asks those users to sign in again.

Pages: `/approve` (enter a code, or `/approve?code=XXXX-XXXX`: the request's
CE name, code, source address and its reverse DNS, time and CE version, and
whether the logged-in user may approve it and why), `/registrations` (the
registrations the user approved or is authorized for, all of them for an
administrator, with revoke), `/healthz`. Login and approve requests are
rate-limited per client address (per /64 for IPv6).

### Authorization backends (registrar)

- `AUTHZ`: `mapfile`, `topology`, or both as a list. A user may approve a
  name when any listed backend allows it (the first allow wins). A name is
  known for callback mode (`CALLBACK_NAMES = authz`) when any backend knows
  it. Changing the list takes a restart.

**mapfile** (`AUTHZ_MAPFILE`): an HTCondor map file. Lines of method `OIDC`
map a user, by `OIDC_PRINCIPAL_CLAIM` value, to the comma-separated CE names
the user may approve:

```
# method  user (literal, or /regex/)                 CE names
OIDC http://cilogon.org/serverA/users/1234          ce1.example.edu,*.grid.example.edu
OIDC /^ops-[0-9]+$/                                 ce2.example.edu
```

A regular expression is written between slashes, so a `/` inside it is
written `\/`. A name is literal or a `path.Match` glob (`*` also matches
dots); names compare without regard to case. As in any HTCondor map file, only the first
line whose user matches is used, so list all of a user's names on
that line. Only literal names are known for callback mode: a glob can approve
names but never makes one known, since callback mode needs the name written
out. The file is re-read when its modification time changes and on
reconfig; a file that fails to load leaves the last good one in use, and the
error is logged.

**topology**: OSG Topology. A user may approve a name when the name is the
FQDN of an active resource with a CE service and the user's principal (the
`osgid` claim: set `OIDC_PRINCIPAL_CLAIM = osgid`) is the `CILogonID` of a
contact in any of its Administrative Contact lists (Primary, Secondary or
Tertiary). A name is known when it is an active CE's FQDN. A contact
listed without a `CILogonID` can never approve.

- `TOPOLOGY_URL`: default `https://topology.opensciencegrid.org` (https only).
- `TOPOLOGY_INCLUDE_ITB`: default false: production resources only. When
  true, ITB resources are included too.
- `TOPOLOGY_REFRESH`: default 15 min.
- `TOPOLOGY_MAX_STALE`: default 24 h. When fetches fail, the last good copy
  is used until it is this old; after that every decision fails until a fetch
  succeeds. A document listing no active CE, or fewer than half the active
  CEs of the copy in use, counts as a failed fetch and is logged as an
  error; a restart accepts it.

### Command line

On a CE, `htc-registration request --approval` starts an approval request now,
even when the CE is configured for callback, and prints the URL and code.

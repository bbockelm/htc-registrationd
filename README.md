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
  (`XXXX-XXXX`). An administrator approves it (for now with
  `htc-registration approve CODE`), and the CE collects the token by polling.
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
- `CALLBACK_NAMES`: `authz` | `any` (default `authz`, which refuses every name
  until an authorization backend exists).
- `CALLBACK_ALLOW_NETWORKS`: CIDRs re-allowed for callbacks. Loopback, RFC
  1918, CGNAT, link-local, multicast, ULA, their IPv4-mapped / NAT64 / 6to4
  forms, and the registrar's own addresses are denied by default. The check
  runs at connect time on each address the callback actually dials, after
  the CE's host name is resolved.
- `CALLBACK_CONNECT_TIMEOUT` / `CALLBACK_TIMEOUT`: default 10 s / 30 s.
- `MAX_PENDING_PER_IP` / `MAX_PENDING`: default 10 / 1000.
- `APPROVAL_TTL` (30 min), `UNCLAIMED_TTL` (24 h), `POLL_INTERVAL` (5 s).
- `VERIFICATION_URI`: default `https://$(FULL_HOSTNAME)/approve`.
- `RECHECK_APPROVER` (true), `MAX_REGISTRATION_AGE` (no cap).

Certificate trust uses the standard HTCondor knobs: `AUTH_SSL_CLIENT_CAFILE`,
`AUTH_SSL_CLIENT_CADIR` and `AUTH_SSL_CLIENT_USE_DEFAULT_CAS` (default true:
the system trust store is trusted too) for the connections the daemon makes,
the CE's to the registrar and the registrar's callbacks, and the
`AUTH_SSL_SERVER_*` variants for the connections it accepts.

Not built yet: the HTTPS approval UI with OIDC login, and the mapfile and OSG
Topology authorization backends.

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
```

The end-to-end tests in `internal/ce` run a registrar and a CE as two cedar
servers on loopback, using a generated test CA. They need a cedar that can
complete a Go-to-Go SSL handshake. When the linked cedar cannot, they skip
with a message that names the failure. Set
`HTC_REGISTRATIOND_REQUIRE_GO_SSL=1` to make them fail instead.

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
- `REGISTRAR`: the registrar's address (required).
- `REGISTRAR_NAME`: the name its certificate must carry. By default this is
  derived from the address.
- `REGISTRAR_CAFILE`: default `AUTH_SSL_CLIENT_CAFILE`.
- `CALLBACK_ADDRESS`: default: the daemon's shared-port sinful.
- `TOKEN_FILE`: default `$(SEC_TOKEN_SYSTEM_DIRECTORY)/50-htc-registration`.

Registrar:

- `SIGNING_KEY`: default `ce-registration`, read from
  `SEC_PASSWORD_DIRECTORY`.
- `IDENTITY_DOMAIN`: default `$(UID_DOMAIN)`. The issuer is `TRUST_DOMAIN`.
- `TOKEN_LIMITS`: default `ADVERTISE_SCHEDD`.
- `TOKEN_LIFETIME`: default 72 h.
- `CALLBACK_NAMES`: `authz` | `any` (default `authz`, which refuses every name
  until an authorization backend exists).
- `CALLBACK_ALLOW_NETWORKS`: CIDRs re-allowed for callbacks. Loopback, RFC
  1918, CGNAT, link-local, multicast, ULA, their IPv4-mapped / NAT64 / 6to4
  forms, and the registrar's own addresses are denied by default.
- `CALLBACK_CAFILE`: default `AUTH_SSL_CLIENT_CAFILE`.
- `CALLBACK_CONNECT_TIMEOUT` / `CALLBACK_TIMEOUT`: default 10 s / 30 s.
- `MAX_PENDING_PER_IP` / `MAX_PENDING`: default 10 / 1000.
- `APPROVAL_TTL` (30 min), `UNCLAIMED_TTL` (24 h), `POLL_INTERVAL` (5 s).
- `VERIFICATION_URI`: default `https://$(FULL_HOSTNAME)/approve`.
- `RECHECK_APPROVER` (true), `MAX_REGISTRATION_AGE` (no cap).

Not built yet: the HTTPS approval UI with OIDC login, the mapfile and OSG
Topology authorization backends, packaging, and HTCondor-CE configuration
snippets.

# Protocol and internals

This page describes how htc-registrationd works: the CEDAR commands, the two
registration exchanges, renewal, and the checks the registrar makes. The
[README](../README.md) covers installation and operation.

## Commands

The commands use the block 77000-77013, defined in
[`internal/protocol`](../internal/protocol/commands.go). The block is unused
in HTCondor's `condor_commands.h`; re-check it there before a release.

| Command | Number | Served by | Level |
|---|---|---|---|
| `REG_REQUEST` | 77000 | registrar | ALLOW, SSL + encryption |
| `REG_POLL` | 77001 | registrar | ALLOW, SSL + encryption |
| `REG_RENEW` | 77002 | registrar | ALLOW, SSL + encryption |
| `REG_CALLBACK` | 77003 | CE | ALLOW, SSL + encryption |
| `REG_STATUS` | 77004 | CE | READ |
| `REG_RENEW_NOW` | 77005 | CE | ADMINISTRATOR |
| `REG_REQUEST_APPROVAL` | 77006 | CE | ADMINISTRATOR |
| `REG_ADMIN_LIST` / `APPROVE` / `DENY` / `REVOKE` | 77010-77013 | registrar | ADMINISTRATOR + encryption |

`REG_REQUEST`, `REG_POLL`, `REG_RENEW` and `REG_CALLBACK` carry nonces,
request ids, refresh secrets or tokens. They negotiate SSL only, require
encryption, and their handlers refuse an unencrypted session. The client
verifies the server's certificate: the CE verifies the registrar's, and the
registrar verifies the CE's on the callback. The administration commands
authenticate by any method the ADMINISTRATOR level allows, but require
encryption.

The token is an IDTOKEN for `<ce-name>@<IDENTITY_DOMAIN>`, issued by
`TRUST_DOMAIN`, signed with the registrar's signing key and limited to
`TOKEN_LIMITS` (default `ADVERTISE_SCHEDD`).

## Callback mode

1. The CE sends `REG_REQUEST` with its name, its own sinful (its shared-port
   address, or `CALLBACK_ADDRESS`) and a nonce.
2. The registrar checks the name against `CALLBACK_NAMES`, then connects to
   the sinful with `REG_CALLBACK` over SSL. It verifies the CE's server
   certificate against the requested name, and checks the nonce.
3. The registrar sends the token on the callback connection only. The reply
   to `REG_REQUEST` never carries it.

Renewal is a fresh exchange, started between 40% and 60% of the way through
the token's lifetime (drawn once per token).

A failed callback backs off further callbacks for that name from that
network (an IPv6 /64 or an IPv4 address) only; a success clears the name's
back-off. A requester learns that a callback failed, never how.

### Callback address checks

The registrar refuses to call back to loopback, RFC 1918, CGNAT,
link-local, multicast, ULA, the documentation, benchmarking and IETF
special-purpose ranges, the Azure WireServer address, the IPv4-mapped,
SIIT, NAT64 and 6to4 forms of all of these, and the registrar's own
addresses. `CALLBACK_ALLOW_NETWORKS` re-allows CIDRs. The check runs at
connect time on each address the callback dials, after the CE's host name
is resolved.

## Approval mode

1. The CE sends `REG_REQUEST` for approval. The registrar creates a request
   with a user code (`XXXX-XXXX`) and replies with `VERIFICATION_URI` and
   `<VERIFICATION_URI>?code=XXXX-XXXX`.
2. The CE logs the URL, writes it to `approval-url` in its state directory,
   and polls with `REG_POLL` every `POLL_INTERVAL`.
3. An administrator approves the request in the web UI after an OIDC login,
   or with `htc-registration approve CODE NAME` on the registrar. A request
   not decided within `APPROVAL_TTL` expires.
4. The next poll returns the token and a refresh secret. An approved request
   that is not collected within `UNCLAIMED_TTL` expires.

### Renewal and refresh secrets

In approval mode the token is an access token, and the refresh secret
outlives it. A CE whose token expired (it was down, or the registrar was
unreachable) renews with the secret. A person is needed again only when:

- the registration was revoked;
- the refresh secret was not used for `REFRESH_IDLE_LIFETIME`;
- the registration is older than `MAX_REGISTRATION_AGE`;
- `RECHECK_APPROVER` is true and the person who approved it in the web UI is
  no longer authorized for the name (an administrator, or allowed by an
  `AUTHZ` backend). Approvals made with `htc-registration approve` are not
  re-checked.

The secret rotates in two phases (current and pending), and the CE survives
a crash at any point of a rotation. The registrar stores only hashes of the
secrets. A superseded secret that is presented again (a retired one, or a
pending secret replaced by a renewal with the current one) revokes the
registration. So do more than `MAX_REISSUES` renewals in a row with the
current secret, the pending one never proven. Both mean that a copy of the
CE's state is in use. An honest CE renews with the current secret only when
it lost the reply to the previous renewal.

The CE never falls back to presenting an older secret.

## Names

A CE's name must equal its Scheduler ad's `Name`, because HTCondor-CE's
`COLLECTOR_REQUIREMENTS` accept a Scheduler ad only when its `Name` is the
user part of the identity it authenticated as. The CE uses
`HTC_REGISTRATIOND_NAME`, else the name the schedd advertises: `SCHEDD_NAME`
turned into a daemon name as the schedd does it, else `$(FULL_HOSTNAME)`. A
`SCHEDD_NAME` that is not this host's becomes `name@$(FULL_HOSTNAME)`, which
no token can match, so the CE refuses to start with it.

Names are lower-cased, and the registrar compares them without regard to
case.

## Registrar limits

`MAX_PENDING_PER_IP` and `MAX_PENDING` cap live requests per network (an
IPv6 /64, an IPv4 address) and in total. The web UI rate-limits sign-ins
and approvals per client address (per /64 for IPv6).

## Web UI login

Login is OpenID Connect, authorization code with PKCE, done by the daemon
itself. The identity comes from the provider's userinfo endpoint. Headers
from a proxy are never used as identity; on the `HTTP_ADDR` listener,
`X-Forwarded-For` from a trusted proxy is used only to rate-limit.

With `OIDC_PRINCIPAL_CLAIM = sub`, the registrar records a user as
`<issuer>,<sub>`, and configuration (`ADMINS`, the mapfile) names the user
by the bare `sub`. A recorded user matches configuration only while
`OIDC_ISSUER` is still that issuer. Any other claim is used as its bare
value, with no issuer attached and no verification check, so it must be an
identifier that the provider never reassigns, such as `osgid`. The daemon
refuses `email`.

Sessions are kept in the registrar's database; sign-ins in progress are
kept in memory, so a restart asks those users to sign in again. A sign-in
that reaches the UI under another host name is sent to `PUBLIC_URL` first.

## Signing key

`SIGNING_KEY` names a file in `SEC_PASSWORD_DIRECTORY` (`POOL` means the
pool key, read from `SEC_TOKEN_POOL_SIGNING_KEY_FILE`). As HTCondor requires,
the file must be owned by the daemon's real uid (root under a root master)
and not be readable by group or others. When the file does not exist, the
registrar creates it at startup and on every reconfig, as an HTCondor
collector creates its own signing key: 64 random bytes, written as
HTCondor writes a signing key, root-owned, mode 0600. An existing file is
never replaced.

## Authorization backends

A user may approve a name when the user is in `ADMINS` or any backend in
`AUTHZ` allows it; the first allow wins. For callback mode with
`CALLBACK_NAMES = authz`, a name is known when any backend knows it. When no
backend allows a name and one could not answer (for example, stale
Topology data), the answer is an error rather than a denial.

The mapfile is re-read when its modification time or size changes (checked
at most once a second) and on reconfig. A file that fails to load leaves the
last good one in use, and the error is logged.

The Topology backend reads `rgsummary` from `TOPOLOGY_URL` every
`TOPOLOGY_REFRESH`. When fetches fail, the last good copy is used until it
is `TOPOLOGY_MAX_STALE` old; after that every decision fails until a fetch
succeeds. A document listing no active CE, or fewer than half the active CEs
of the copy in use, counts as a failed fetch and is logged as an error; a
restart accepts it.

## Files

On the CE, in `STATE_DIR`:

| File | Contents |
|---|---|
| `registration.json` | registration id, refresh secrets, token times (mode 0600) |
| `status.json` | the state `htc-registration status` reports |
| `approval-url` | the pending approval URL, while a request waits |

On the registrar, `registrar.db` in `STATE_DIR` holds requests,
registrations, secret hashes and web sessions.

## Reconfiguration

On the CE, `condor_reconfig` re-reads `METHOD`, `REGISTRAR`,
`REGISTRAR_NAME`, `CALLBACK_ADDRESS`, the token directory, the timeouts,
`CONDOR_VIEW_HOST` and the `AUTH_SSL_*` CA knobs. A changed token directory
gets a token at once. A changed CE name takes a restart.

On the registrar, `condor_reconfig` re-reads `APPROVAL_TTL`,
`UNCLAIMED_TTL`, `POLL_INTERVAL`, `VERIFICATION_URI`, `RECHECK_APPROVER`,
`MAX_REGISTRATION_AGE`, `REFRESH_IDLE_LIFETIME`, `MAX_REISSUES`,
`MAX_PENDING`, `MAX_PENDING_PER_IP`, the callback timeouts, `ADMINS`,
`AUTHZ_MAPFILE` and the mapfile, the OIDC client secret file and the web
UI's certificate and key. It also creates the signing key if it is missing.
Every other knob takes a restart. The web UI's certificate is also re-read
within a minute of changing.

After installing a token, the CE sends `DC_RECONFIG_FULL` to its master, so
the CE's daemons read the new token, then checks it with an
`ADVERTISE_SCHEDD` ping of `CONDOR_VIEW_HOST`.

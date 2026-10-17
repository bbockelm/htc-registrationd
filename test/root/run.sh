#!/usr/bin/env bash
# Runs htc-registrationd as it is deployed: under condor_master, started as
# root, dropping to the condor account, with every credential root:root
# 0600. Three AlmaLinux 9 containers with HTCondor and HTCondor-CE from the
# HTCondor 25.x repository:
#
#   collector.test  htcondor-ce-collector; the registrar, with its web UI on
#                   the shared port (9619) through SHARED_PORT_HTTP_FORWARDING_ID,
#                   a test OpenID provider on 8443 and a test SciToken issuer
#                   on 8444
#   ce1.test        htcondor-ce; htc-registrationd in ce mode, and a
#                   one-machine HTCondor pool (minicondor) the CE routes to
#   factory.test    a pilot factory: an unprivileged account holding only a
#                   SciToken, which it exchanges at ce1.test for an IDTOKEN
#                   and submits a job with
#
# Both use the shipped configuration files, enabled by uncommenting their
# "enable" lines. The 9619 and 8443 ports of collector.test are published on
# 127.0.0.1 for the browser tests.
#
# Usage: test/root/run.sh            build, start, check; KEEP=1 leaves the
#                                    containers running afterwards, for
#                                    e2e/tests/sharedport.spec.ts
#        test/root/run.sh logs       print the daemons' logs
#        test/root/run.sh clean      remove the containers and network
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${WORK:-$repo/test/root/.work}
net=hrd-root
reg=hrd-root-collector
ce=hrd-root-ce1
fac=hrd-root-factory
regimg=hrd-root-collector:latest
ceimg=hrd-root-ce:latest
ce_config=/etc/condor-ce/condor_config

say() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

clean() {
	docker rm -f "$reg" "$ce" "$fac" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
}


in_reg() { docker exec -e CONDOR_CONFIG=$ce_config "$reg" "$@"; }
in_ce() { docker exec -e CONDOR_CONFIG=$ce_config "$ce" "$@"; }
# in_pool: the CE's local HTCondor pool, under its own configuration.
in_pool() { docker exec "$ce" "$@"; }
# in_factory: the factory's unprivileged account, with HTCondor-CE's client
# configuration.
in_factory() { docker exec -u factory -w /home/factory -e CONDOR_CONFIG=$ce_config "$fac" "$@"; }

# wait_for DESCRIPTION SECONDS COMMAND...: run COMMAND every 2 s until it
# succeeds.
wait_for() {
	local what=$1 limit=$2
	shift 2
	local deadline=$((SECONDS + limit))
	until "$@" >/dev/null 2>&1; do
		if ((SECONDS >= deadline)); then
			fail "timed out after ${limit}s: $what"
		fi
		sleep 2
	done
}

dump_logs() {
	for c in "$reg" "$ce"; do
		docker inspect "$c" >/dev/null 2>&1 || continue
		for f in MasterLog SharedPortLog CollectorLog SchedLog HtcRegistrationdLog; do
			echo "----- $c: $f"
			docker exec "$c" sh -c "tail -n 150 /var/log/condor-ce/$f 2>/dev/null" || true
		done
	done
	for f in JobRouterLog AuditLog; do
		echo "----- $ce: $f"
		docker exec "$ce" sh -c "tail -n 100 /var/log/condor-ce/$f 2>/dev/null" || true
	done
	for f in SchedLog NegotiatorLog StartLog; do
		echo "----- $ce: local pool $f"
		docker exec "$ce" sh -c "tail -n 100 /var/log/condor/$f 2>/dev/null" || true
	done
	echo "----- $reg: identity provider"
	docker exec "$reg" sh -c 'cat /var/log/idp.log 2>/dev/null' || true
	echo "----- $reg: SciToken issuer"
	docker exec "$reg" sh -c 'cat /var/log/issuer.log 2>/dev/null' || true
}

case ${1:-} in
clean)
	clean
	exit 0
	;;
logs)
	dump_logs
	exit 0
	;;
esac

on_exit() {
	local rc=$?
	if ((rc != 0)); then
		dump_logs
	fi
	if [[ -z ${KEEP:-} ]]; then
		clean
	fi
	exit $rc
}

# --- build -----------------------------------------------------------------
say "building the daemon and the test identity provider"
arch=$(docker version --format '{{.Server.Arch}}')
rm -rf "$work"
mkdir -p "$work/bin" "$work/pki"
(cd "$repo" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$work/bin/htc-registrationd" ./cmd/htc-registrationd)
(cd "$repo" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$work/bin/htc-registrationd-demo" ./cmd/htc-registrationd-demo)

say "building the images"
docker build -q -t "$regimg" --build-arg PACKAGES=htcondor-ce-collector -f "$here/Containerfile" "$here" >/dev/null
# The factory runs from the CE image too: it needs only HTCondor-CE's client
# tools, which htcondor-ce depends on.
docker build -q -t "$ceimg" --build-arg PACKAGES="htcondor-ce htcondor-ce-condor minicondor" -f "$here/Containerfile" "$here" >/dev/null

# --- PKI -------------------------------------------------------------------
say "creating a test CA and host certificates"
pki=$work/pki
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=htc-registrationd test CA" \
	-keyout "$pki/ca.key" -out "$pki/ca.crt" 2>/dev/null
for h in collector.test ce1.test; do
	openssl req -newkey rsa:2048 -nodes -subj "/CN=$h" -keyout "$pki/$h.key" -out "$pki/$h.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$h" >"$pki/$h.ext"
	openssl x509 -req -in "$pki/$h.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial -days 2 \
		-extfile "$pki/$h.ext" -out "$pki/$h.crt" 2>/dev/null
done
head -c 24 /dev/urandom | base64 | tr -d '/+=' >"$work/oidc-secret"
# The mounted files are the user's; the containers install root-owned
# copies.
chmod -R a+rX "$work"

# --- containers ------------------------------------------------------------
clean
trap on_exit EXIT
docker network create "$net" >/dev/null
subnet=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Subnet}}')
docker run -d --name "$reg" --hostname collector.test --network "$net" --network-alias collector.test \
	-p 127.0.0.1:9619:9619 -p 127.0.0.1:8443:8443 \
	-v "$repo:/src:ro" -v "$work:/work:ro" "$regimg" sleep infinity >/dev/null
docker run -d --name "$ce" --hostname ce1.test --network "$net" --network-alias ce1.test \
	-v "$repo:/src:ro" -v "$work:/work:ro" "$ceimg" sleep infinity >/dev/null
docker run -d --name "$fac" --hostname factory.test --network "$net" --network-alias factory.test \
	-v "$repo:/src:ro" -v "$work:/work:ro" "$ceimg" sleep infinity >/dev/null

say "installing htc-registrationd on both hosts, and the factory"
docker exec "$reg" /src/test/root/install.sh registrar "$subnet"
docker exec "$ce" /src/test/root/install.sh ce "$subnet"
docker exec "$fac" /src/test/root/install.sh factory "$subnet"

say "starting the identity provider, the SciToken issuer and the masters, as root"
docker exec -d "$reg" sh -c '/work/bin/htc-registrationd-demo idp -listen :8443 \
	-issuer https://collector.test:8443 -redirect-uri https://collector.test:9619/oidc/callback \
	-client-secret-file /etc/condor-ce/htc-registrationd-oidc-secret \
	-cert /etc/grid-security/hostcert.pem -key /etc/grid-security/hostkey.pem >/var/log/idp.log 2>&1'
docker exec -d "$reg" sh -c '/work/bin/htc-registrationd-demo scitoken-issuer -listen :8444 \
	-issuer https://collector.test:8444 \
	-cert /etc/grid-security/hostcert.pem -key /etc/grid-security/hostkey.pem >/var/log/issuer.log 2>&1'
in_reg condor_master
in_ce condor_master
in_pool condor_master

# --- checks ----------------------------------------------------------------
say "the registrar"
wait_for "the registrar's signing key" 60 in_reg test -s /etc/condor-ce/passwords.d/ce-registration
mode=$(in_reg stat -c '%u:%g %a' /etc/condor-ce/passwords.d/ce-registration)
[[ $mode == "0:0 600" ]] || fail "signing key is $mode, want 0:0 600"
pass "the registrar created its signing key root:root 0600 in the root-only passwords.d"

condor_uid=$(in_reg id -u condor)
for c in "$reg" "$ce"; do
	pid=$(docker exec "$c" pgrep -f '^htc-registrationd -')
	ids=$(docker exec "$c" awk '/^Uid:/ {print $2, $3}' "/proc/$pid/status")
	[[ $ids == "0 $condor_uid" ]] || fail "$c: htc-registrationd real/effective uid $ids, want 0 $condor_uid"
	pass "$c: htc-registrationd runs with real uid 0 and effective uid condor ($condor_uid)"
done

say "the CE registers by callback through its shared port"
ce_status() { in_ce htc-registration status; }
wait_for "ce1.test to register" 120 sh -c "docker exec -e CONDOR_CONFIG=$ce_config $ce htc-registration status | grep -Eq 'State:[[:space:]]+registered'"
ce_status
ce_status | grep -Eq 'Method:[[:space:]]+callback' || fail "ce1.test did not register by callback"
# The daemon has no TCP listener of its own, only its shared-port endpoint,
# so the registrar's REG_CALLBACK reached it through the CE's port 9619.
if in_ce ss -Hltnp | grep -q 'htc-registrati'; then
	fail "htc-registrationd on ce1.test has a TCP listener of its own"
fi
in_reg grep -q 'issued token by callback.*name=ce1.test' /var/log/condor-ce/HtcRegistrationdLog ||
	fail "the registrar did not log the callback issuance"
pass "ce1.test registered by REG_CALLBACK, delivered through its shared port"

tok=/etc/condor-ce/tokens.d/50-htc-registration
mode=$(in_ce stat -c '%U:%G %a' "$tok")
# HTCondor reads tokens.d as root and refuses a token root does not own.
[[ $mode == "root:root 600" ]] || fail "token is $mode, want root:root 600"
pass "the token is in tokens.d, root:root 0600"

say "the CE-Collector accepts ce1.test's Scheduler ad"
schedds() { in_reg condor_status -schedd -af Name AuthenticatedIdentity; }
wait_for "ce1.test's Scheduler ad at the collector" 180 sh -c \
	"docker exec -e CONDOR_CONFIG=$ce_config $reg condor_status -schedd -af Name AuthenticatedIdentity | grep -q '^ce1.test ce1.test@users.htcondor.org$'"
schedds
pass "condor_status -schedd: ce1.test, authenticated as ce1.test@users.htcondor.org"

say "a Scheduler ad with a forged Name is rejected"
advertise() { # NAME MARKER
	in_ce sh -c "printf 'MyType = \"Scheduler\"\nName = \"%s\"\nMachine = \"%s\"\ngrid_resource = \"condor %s %s:9619\"\nRootTestMarker = \"%s\"\n' $1 $1 $1 $1 $2 >/tmp/$2.ad &&
		_CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS=IDTOKENS condor_advertise -pool collector.test:9619 -tcp UPDATE_SCHEDD_AD /tmp/$2.ad"
}
advertise ce1.test genuine
wait_for "an ad ce1.test advertises under its own name" 30 sh -c \
	"docker exec -e CONDOR_CONFIG=$ce_config $reg condor_status -schedd -constraint 'RootTestMarker == \"genuine\"' -af Name | grep -q ce1.test"
advertise ce2.test forged
sleep 5
forged=$(in_reg condor_status -schedd -constraint 'RootTestMarker == "forged"' -af Name)
[[ -z $forged ]] || fail "the collector accepted a Scheduler ad named ce2.test from ce1.test's token"
pass "ce1.test's token advertises ce1.test, and an ad claiming ce2.test is rejected"

say "the web UI on the shared port"
curl_sp() { curl -sS --cacert "$pki/ca.crt" --resolve collector.test:9619:127.0.0.1 --resolve collector.test:8443:127.0.0.1 "$@"; }
code=$(curl_sp -o /dev/null -w '%{http_code}' https://collector.test:9619/healthz)
[[ $code == 200 ]] || fail "GET https://collector.test:9619/healthz: $code"
pass "https://collector.test:9619/healthz: 200, TLS with the host certificate"
loc=$(curl_sp -L -o /dev/null -w '%{url_effective}' https://collector.test:9619/registrations)
[[ $loc == https://collector.test:8443/authorize?* && $loc == *redirect_uri=https%3A%2F%2Fcollector.test%3A9619%2Foidc%2Fcallback* ]] ||
	fail "GET /registrations did not send the browser to the identity provider: $loc"
pass "/registrations sends a browser to sign in, with a redirect URI on the shared port"
plain=$(curl -sS --resolve collector.test:9619:127.0.0.1 http://collector.test:9619/healthz || true)
[[ $plain == *"HTTP request to an HTTPS server"* ]] || fail "plain HTTP on the shared port: $plain"
pass "plain HTTP on the shared port is refused (400)"
ce_status | grep -Eq 'Registrar:[[:space:]]+<collector.test:9619\?sock=htc_registrationd>' ||
	fail "ce1.test did not reach the registrar at <collector.test:9619?sock=htc_registrationd>"
pass "CEDAR to the registrar on the same port: ce1.test registered through <collector.test:9619?sock=htc_registrationd>"

say "a factory exchanges a SciToken at ce1.test and runs a job with the IDTOKEN"
# mint SUB AUD FILE: the factory gets a SciToken from its VO's issuer.
mint() {
	in_factory sh -c "curl -sSf -d sub=$1 -d aud=$2 https://collector.test:8444/mint >$3"
}
# claim FILE CLAIM: a claim of the JWT in the factory's FILE.
claim() {
	in_factory python3 -c 'import base64, json, sys
p = open(sys.argv[1]).read().strip().split(".")[1]
print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get(sys.argv[2]))' "$1" "$2"
}
# exchange CREDENTIAL TOKEN: present TOKEN for exchange at ce1.test, found
# through the CE-Collector, authenticating with the SciToken CREDENTIAL.
exchange() {
	in_factory env BEARER_TOKEN_FILE=/home/factory/$1 _condor_SEC_CLIENT_AUTHENTICATION_METHODS=SCITOKENS \
		condor_scitoken_exchange -scitoken "$2" -pool collector.test:9619 -name ce1.test
}
# The hand-made ads above replaced ce1.test's address; its schedd's next
# update restores it.
wait_for "ce1.test's own Scheduler ad at the collector" 60 sh -c \
	"docker exec -e CONDOR_CONFIG=$ce_config $reg condor_status -schedd -constraint 'Name == \"ce1.test\"' -af MyAddress | grep -q sock=schedd"
wait_for "the SciToken issuer" 30 in_factory curl -sSf https://collector.test:8444/.well-known/openid-configuration
mint pilot ce1.test:9619 scitoken
in_factory ls -l /etc/grid-security/hostcert.pem /etc/condor-ce/tokens.d/50-htc-registration 2>/dev/null &&
	fail "the factory holds a host certificate or an HTCondor token"
pass "the factory holds a SciToken for ce1.test:9619 from https://collector.test:8444, and no other credential"

# XFAIL. condor_ce_scitoken_exchange first fetches a READ token for the CE
# from the CE-Collector (condor_token_fetch -remote: IMPERSONATION_TOKEN_REQUEST),
# which it cannot get:
#   1. the CE-Collector authenticates the request at DAEMON level, where
#      HTCondor-CE allows FS and IDTOKENS only, and the factory holds only a
#      SciToken;
#   2. a request that does authenticate (root, by FS, on the collector) still
#      fails: the collector looks up the CE schedd's Capability in the ad's
#      public attributes, but keeps it with the private ones.
# When either check below stops failing, make the bootstrap a pass.
if out=$(in_factory condor_ce_scitoken_exchange -p collector.test -n ce1.test -s scitoken 2>&1); then
	fail "condor_ce_scitoken_exchange now succeeds; make its bootstrap a pass: $out"
fi
[[ $out == *"Failed to acquire a token from collector"* && $out == *"Failed to authenticate using IDTOKENS"* ]] ||
	fail "condor_ce_scitoken_exchange failed unexpectedly: $out"
printf 'XFAIL: condor_ce_scitoken_exchange: the factory cannot authenticate IMPERSONATION_TOKEN_REQUEST to the CE-Collector\n'
if out=$(in_reg condor_token_fetch -pool collector.test:9619 -name ce1.test -remote -authz READ -lifetime 600 2>&1); then
	fail "IMPERSONATION_TOKEN_REQUEST now succeeds; make the bootstrap a pass"
fi
[[ $out == *"Schedd ce1.test is not known to the collector"* ]] ||
	fail "IMPERSONATION_TOKEN_REQUEST failed unexpectedly: $out"
printf 'XFAIL: IMPERSONATION_TOKEN_REQUEST, authenticated: %s\n' "Schedd ce1.test is not known to the collector"

# The exchange itself (DC_EXCHANGE_SCITOKEN), authenticated by the SciToken.
idtoken=$(exchange scitoken scitoken) || fail "the SciToken exchange at ce1.test failed"
printf '%s\n' "$idtoken" | docker exec -i -u factory -w /home/factory "$fac" sh -c 'umask 077; cat >idtoken'
sub=$(claim idtoken sub) scope=$(claim idtoken scope) iss=$(claim idtoken iss)
[[ $sub == pilot@users.htcondor.org ]] || fail "exchanged token subject $sub, want pilot@users.htcondor.org"
# HTCondor grants a SciToken's compute.* scopes as READ and WRITE.
[[ $scope == "condor:/DENY condor:/READ condor:/WRITE" ]] || fail "exchanged token scope $scope, want condor:/READ condor:/WRITE"
[[ $(claim idtoken exp) == $(claim scitoken exp) ]] || fail "exchanged token outlives the SciToken"
pass "ce1.test exchanged the SciToken for an IDTOKEN: iss $iss, sub $sub, scope \"$scope\", the SciToken's expiry"

mint intruder ce1.test:9619 unmapped
mint pilot ce2.test:9619 wrongaud
out=$(exchange scitoken unmapped 2>&1) && fail "ce1.test exchanged an unmapped SciToken"
[[ $out == *"Failed to map SciToken to a local identity"* ]] || fail "unmapped SciToken: $out"
pass "an unmapped subject is refused: Failed to map SciToken to a local identity"
out=$(exchange scitoken wrongaud 2>&1) && fail "ce1.test exchanged a SciToken for another audience"
[[ $out == *"'aud' claim verification failed"* ]] || fail "wrong-audience SciToken: $out"
pass "a SciToken for ce2.test:9619 is refused: 'aud' claim verification failed"
out=$(exchange wrongaud wrongaud 2>&1) && fail "a factory holding only a wrong-audience SciToken exchanged it"
[[ $out == *"Failed to authenticate using SCITOKENS"* ]] || fail "wrong-audience credential: $out"
pass "a factory holding only a wrong-audience SciToken cannot authenticate to ce1.test"

# condor_ce_trace finds ce1.test through the CE-Collector, which knows it
# only from its registration, and submits with the IDTOKEN alone.
in_factory sh -c 'mkdir -p -m 0700 .condor/tokens.d && install -m 0600 idtoken .condor/tokens.d/ce1.test'
in_factory env _condor_SEC_CLIENT_AUTHENTICATION_METHODS=IDTOKENS _condor_CONDOR_CE_TRACE_ATTEMPTS=180 \
	condor_ce_trace --skip-scitokens -s ce1.test collector.test:9619 | tee "$work/trace.txt" ||
	fail "condor_ce_trace failed"
grep -q 'Job was successful' "$work/trace.txt" || fail "condor_ce_trace did not report success"
jti=$(claim idtoken jti)
wait_for "the trace job in ce1.test's history" 30 sh -c "docker exec -e CONDOR_CONFIG=$ce_config $ce condor_history -limit 1 -af AuthTokenId | grep -qx $jti"
read -r _ sub owner routed <<<"$(in_ce condor_history -limit 1 -af:j AuthTokenSubject Owner RoutedToJobId)"
[[ $sub == pilot@users.htcondor.org && $owner == pilot ]] ||
	fail "ce1.test's job was submitted as $sub, owner $owner"
wait_for "the routed job in the local pool's history" 30 sh -c "docker exec $ce condor_history $routed -af Owner | grep -q ."
pool_job=$(in_pool condor_history "$routed" -af Owner JobStatus ExitCode)
[[ $pool_job == "pilot 4 0" ]] || fail "routed job $routed: owner, status, exit code $pool_job; want pilot 4 0"
pass "the job was submitted with the exchanged IDTOKEN (AuthTokenId $jti) and ran as pilot in ce1.test's pool, as $routed"

say "an approval request for the browser test (E2E_SHAREDPORT_APPROVAL)"
in_ce htc-registration request --approval | tee "$work/approval.txt"
say "all checks passed"

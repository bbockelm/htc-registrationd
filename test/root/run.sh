#!/usr/bin/env bash
# Runs htc-registrationd as it is deployed: under condor_master, started as
# root, dropping to the condor account, with every credential root:root
# 0600. Two AlmaLinux 9 containers with HTCondor and HTCondor-CE from the
# HTCondor 25.x repository:
#
#   collector.test  htcondor-ce-collector; the registrar, with its web UI on
#                   the shared port (9619) through SHARED_PORT_HTTP_FORWARDING_ID,
#                   and a test OpenID provider on 8443
#   ce1.test        htcondor-ce; htc-registrationd in ce mode
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
regimg=hrd-root-collector:latest
ceimg=hrd-root-ce:latest
ce_config=/etc/condor-ce/condor_config

say() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

clean() {
	docker rm -f "$reg" "$ce" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
}


in_reg() { docker exec -e CONDOR_CONFIG=$ce_config "$reg" "$@"; }
in_ce() { docker exec -e CONDOR_CONFIG=$ce_config "$ce" "$@"; }

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
	echo "----- $reg: identity provider"
	docker exec "$reg" sh -c 'cat /var/log/idp.log 2>/dev/null' || true
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
docker build -q -t "$ceimg" --build-arg PACKAGES=htcondor-ce -f "$here/Containerfile" "$here" >/dev/null

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

say "installing htc-registrationd on both hosts"
docker exec "$reg" /src/test/root/install.sh registrar "$subnet"
docker exec "$ce" /src/test/root/install.sh ce "$subnet"

say "starting the identity provider and both masters, as root"
docker exec -d "$reg" sh -c '/work/bin/htc-registrationd-demo idp -listen :8443 \
	-issuer https://collector.test:8443 -redirect-uri https://collector.test:9619/oidc/callback \
	-client-secret-file /etc/condor-ce/htc-registrationd-oidc-secret \
	-cert /etc/grid-security/hostcert.pem -key /etc/grid-security/hostkey.pem >/var/log/idp.log 2>&1'
in_reg condor_master
in_ce condor_master

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

say "an approval request for the browser test (E2E_SHAREDPORT_APPROVAL)"
in_ce htc-registration request --approval | tee "$work/approval.txt"
say "all checks passed"

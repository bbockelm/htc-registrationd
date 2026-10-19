#!/usr/bin/env bash
# Installs htc-registrationd on an HTCondor-CE host the way the RPM does,
# enables it as an administrator would (uncommenting the shipped "enable"
# lines), and installs every credential root:root 0600. Run as root inside
# the container by run.sh: install.sh registrar|ce|factory SUBNET
#
# A factory host gets no host certificate and no HTCondor credential: only
# the test CA, as a real factory trusts the CAs its peers use, and an
# unprivileged account.
set -euo pipefail
role=$1 subnet=$2
host=$(hostname -f)
conf=/etc/condor-ce/config.d

trust_ca() {
	install -d -m 0755 /etc/grid-security /etc/grid-security/certificates
	install -m 0644 /work/pki/ca.crt /etc/grid-security/certificates/htc-registrationd-test-ca.pem
	openssl rehash /etc/grid-security/certificates
	install -m 0644 /work/pki/ca.crt /etc/pki/ca-trust/source/anchors/htc-registrationd-test-ca.pem
	update-ca-trust
}

if [[ $role == factory ]]; then
	trust_ca
	useradd -m factory
	exit 0
fi

install -m 0755 /work/bin/htc-registrationd /usr/sbin/htc-registrationd
ln -sf /usr/sbin/htc-registrationd /usr/bin/htc-registration
install -m 0644 /src/packaging/50-htc-registrationd-ce.conf /src/packaging/50-htc-registrationd-registrar.conf "$conf/"

trust_ca
install -o root -g root -m 0644 "/work/pki/$host.crt" /etc/grid-security/hostcert.pem
install -o root -g root -m 0600 "/work/pki/$host.key" /etc/grid-security/hostkey.pem

ids="$(id -u condor).$(id -g condor)"
case $role in
registrar)
	sed -i -E 's/^#((DAEMON_LIST|HTC_REGISTRATIOND_MODE|SHARED_PORT_HTTP_FORWARDING_ID|COLLECTOR\.SEC_ADVERTISE_SCHEDD_AUTHENTICATION_METHODS) *=)/\1/' \
		"$conf/50-htc-registrationd-registrar.conf"
	install -o root -g root -m 0600 /work/oidc-secret /etc/condor-ce/htc-registrationd-oidc-secret
	printf 'OIDC alice ce1.test\n' >/etc/condor-ce/htc-registrationd.map
	cat >"$conf/99-htc-registrationd-test.conf" <<CONF
CONDOR_IDS = $ids
COLLECTOR_DEBUG = \$(COLLECTOR_DEBUG) D_MACHINE
HTC_REGISTRATIOND_DEBUG = general:debug cedar:info
HTC_REGISTRATIOND_CALLBACK_ALLOW_NETWORKS = $subnet
HTC_REGISTRATIOND_AUTHZ = mapfile
HTC_REGISTRATIOND_AUTHZ_MAPFILE = /etc/condor-ce/htc-registrationd.map
HTC_REGISTRATIOND_ADMINS = admin
HTC_REGISTRATIOND_PUBLIC_URL = https://collector.test:9619
HTC_REGISTRATIOND_HTTPS_CERTFILE = /etc/grid-security/hostcert.pem
HTC_REGISTRATIOND_HTTPS_KEYFILE = /etc/grid-security/hostkey.pem
HTC_REGISTRATIOND_OIDC_ISSUER = https://collector.test:8443
HTC_REGISTRATIOND_OIDC_CLIENT_ID = htc-registrationd-demo
HTC_REGISTRATIOND_OIDC_CLIENT_SECRET_FILE = /etc/condor-ce/htc-registrationd-oidc-secret
CONF
	;;
ce)
	sed -i -E 's/^#((DAEMON_LIST|HTC_REGISTRATIOND_MODE) *=)/\1/' "$conf/50-htc-registrationd-ce.conf"
	cat >"$conf/99-htc-registrationd-test.conf" <<CONF
CONDOR_IDS = $ids
CONDOR_VIEW_HOST = collector.test:9619
SCHEDD_INTERVAL = 15
HTC_REGISTRATIOND_DEBUG = general:debug cedar:info

# Pilots: the factory's SciTokens are for this CE, and the IDTOKENs this CE
# exchanges them for are accepted for submission.
SCITOKENS_SERVER_AUDIENCE = $host:9619
SCHEDD.SEC_READ_AUTHENTICATION_METHODS = \$(SCHEDD.SEC_READ_AUTHENTICATION_METHODS), IDTOKENS
SCHEDD.SEC_WRITE_AUTHENTICATION_METHODS = \$(SCHEDD.SEC_WRITE_AUTHENTICATION_METHODS), IDTOKENS
JOB_ROUTER_POLLING_PERIOD = 2
CONF
	# The issuer's subject "pilot" runs as the local account pilot. The
	# domain is explicit: an exchanged IDTOKEN carries the mapped name as
	# its subject, and ALLOW_WRITE is *@users.htcondor.org.
	useradd -m pilot
	cat >/etc/condor-ce/mapfiles.d/50-htc-registrationd-test.conf <<'MAP'
SCITOKENS /^https:\/\/collector\.test:8444,pilot$/ pilot@users.htcondor.org
MAP
	;;
*)
	echo "usage: install.sh registrar|ce|factory SUBNET" >&2
	exit 2
	;;
esac
grep -E '^(DAEMON_LIST|HTC_REGISTRATIOND_MODE|SHARED_PORT_HTTP_FORWARDING_ID|COLLECTOR\.SEC_ADVERTISE)' "$conf"/50-htc-registrationd-*.conf

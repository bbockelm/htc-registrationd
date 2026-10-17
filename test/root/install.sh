#!/usr/bin/env bash
# Installs htc-registrationd on an HTCondor-CE host the way the RPM does,
# enables it as an administrator would (uncommenting the shipped "enable"
# lines), and installs every credential root:root 0600. Run as root inside
# the container by run.sh: install.sh registrar|ce SUBNET
set -euo pipefail
role=$1 subnet=$2
host=$(hostname -f)
conf=/etc/condor-ce/config.d

install -m 0755 /work/bin/htc-registrationd /usr/sbin/htc-registrationd
ln -sf /usr/sbin/htc-registrationd /usr/bin/htc-registration
install -m 0644 /src/packaging/50-htc-registrationd-ce.conf /src/packaging/50-htc-registrationd-registrar.conf "$conf/"

install -d -m 0755 /etc/grid-security /etc/grid-security/certificates
install -o root -g root -m 0644 "/work/pki/$host.crt" /etc/grid-security/hostcert.pem
install -o root -g root -m 0600 "/work/pki/$host.key" /etc/grid-security/hostkey.pem
install -m 0644 /work/pki/ca.crt /etc/grid-security/certificates/htc-registrationd-test-ca.pem
openssl rehash /etc/grid-security/certificates
install -m 0644 /work/pki/ca.crt /etc/pki/ca-trust/source/anchors/htc-registrationd-test-ca.pem
update-ca-trust

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
CONF
	;;
*)
	echo "usage: install.sh registrar|ce SUBNET" >&2
	exit 2
	;;
esac
grep -E '^(DAEMON_LIST|HTC_REGISTRATIOND_MODE|SHARED_PORT_HTTP_FORWARDING_ID|COLLECTOR\.SEC_ADVERTISE)' "$conf"/50-htc-registrationd-*.conf

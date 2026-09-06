#!/usr/bin/env bash
# One-time root CA setup. Run interactively, by an operator who has already
# authenticated through the existing MFA'd server login -- that login
# session is the trust boundary for this action, no separate auth is added.
#
# Besides generating the key and self-signed root certificate, this installs
# openssl-ca.cnf into the CA directory with its `dir` pointed at that
# directory, and generates the first CRL. Both services fail closed when the
# CRL is missing (see CrlRevocationChecker), so a CA without one would
# reject every client; producing it here means a freshly initialized CA is
# immediately usable rather than usable only after a follow-up step someone
# has to remember.
#
# Usage: sudo -u ca-svc ./init-ca.sh [ca-dir]
set -euo pipefail

CA_DIR="${1:-/etc/pki/internal-ca}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$CA_DIR/private/ca.key.pem" ]; then
  echo "Refusing to overwrite existing CA key at $CA_DIR/private/ca.key.pem" >&2
  exit 1
fi

umask 077
mkdir -p "$CA_DIR"/{private,certs,newcerts,crl,tmp}
touch "$CA_DIR/index.txt"
touch "$CA_DIR/index.txt.attr"
echo 1000 > "$CA_DIR/serial"
echo 1000 > "$CA_DIR/crlnumber"
chmod 700 "$CA_DIR/private"

# The root's own profile is pinned here rather than inherited from whatever
# /etc/pki/tls/openssl.cnf happens to contain on this host. `openssl req
# -x509` with no explicit extensions takes its profile from the system
# config, which differs between OpenSSL 1.1.1 and 3.x (3.x emits no keyUsage
# at all), so the most important certificate in the system would otherwise be
# the only one this project does not specify.
ROOT_CNF="$(mktemp)"
trap 'rm -f "$ROOT_CNF"' EXIT
cat > "$ROOT_CNF" <<EOF
[ req ]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_root_ca

[ req_dn ]
CN = Internal File Transfer CA

[ v3_root_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl ecparam -genkey -name prime256v1 -noout -out "$CA_DIR/private/ca.key.pem"
chmod 400 "$CA_DIR/private/ca.key.pem"

openssl req -x509 -new -sha256 -days 3650 \
  -config "$ROOT_CNF" \
  -extensions v3_root_ca \
  -key "$CA_DIR/private/ca.key.pem" \
  -out "$CA_DIR/certs/ca.cert.pem" \
  -subj "/CN=Internal File Transfer CA"

# Install the CA config with `dir` pointing at this CA, so nothing downstream
# has to remember to rewrite that line.
sed -E "s|^dir[[:space:]]*=.*|dir = $CA_DIR|" \
  "$SCRIPT_DIR/openssl-ca.cnf" > "$CA_DIR/openssl-ca.cnf"

# First CRL: an empty but validly signed one, so revocation checking works
# from the moment the services start.
"$SCRIPT_DIR/gen-crl.sh" "$CA_DIR"

echo
echo "Root CA initialized at $CA_DIR"
openssl x509 -in "$CA_DIR/certs/ca.cert.pem" -noout -subject -enddate
echo
echo "Next: issue each service its TLS identity with ./issue-server-cert.sh,"
echo "and schedule ./gen-crl.sh to run periodically (see"
echo "deploy/systemd-user/gen-crl.timer) -- the CRL carries its own expiry and"
echo "both services reject clients once it goes stale."

#!/usr/bin/env bash
# Issues a TLS server identity certificate from the internal CA and packages
# it as the PKCS12 keystore a service loads as `server.keystore`. Run once
# for ca-service and once for file-receiver.
#
# This is the certificate a connecting agent validates: it proves the agent
# is talking to the server it dialed, not merely to something the internal
# CA once signed. Two properties matter and are enforced here rather than
# left to whoever types the command:
#
#   - subjectAltName. The agent verifies the hostname against the SAN
#     (see common/.../HttpClients.java), so every server certificate must
#     carry one. It is supplied below via `openssl ca -extfile`, server-side
#     -- copy_extensions = none means a CSR could never request it anyway.
#   - Lifetime. openssl-ca.cnf's `default_days = 5` is the *client*
#     certificate lifetime, and only client certificates are renewed
#     automatically (RenewalLoop). A server certificate that inherited 5 days
#     would take the whole system down within a week of deployment, so an
#     explicit, long -days is passed on every call.
#
# Run by an operator authenticated through the existing MFA'd server login --
# the same trust boundary as init-ca.sh, issue-token.sh and revoke.sh.
#
# Usage: ./issue-server-cert.sh <hostname> <out-prefix> [ca-dir] [days]
#   hostname    the name agents will dial, e.g. receiver.internal.example.com
#   out-prefix  output path prefix; writes <prefix>.key.pem, <prefix>.cert.pem
#               and <prefix>.p12
#   ca-dir      defaults to /etc/pki/internal-ca
#   days        defaults to 397
#
# Environment:
#   P12_PASSWORD  required; password for the generated PKCS12 keystore, to be
#                 set as server.keystore.password in the service properties
#   EXTRA_SAN     optional; additional SAN entries appended to DNS:<hostname>,
#                 e.g. "DNS:receiver-alt.example.com,IP:10.0.0.5"
set -euo pipefail

SERVER_HOSTNAME="${1:?Usage: issue-server-cert.sh <hostname> <out-prefix> [ca-dir] [days]}"
OUT_PREFIX="${2:?Usage: issue-server-cert.sh <hostname> <out-prefix> [ca-dir] [days]}"
CA_DIR="${3:-/etc/pki/internal-ca}"
DAYS="${4:-397}"
CONFIG="$CA_DIR/openssl-ca.cnf"

: "${P12_PASSWORD:?Set P12_PASSWORD to the password for the generated PKCS12 keystore}"
export P12_PASSWORD

SERVER_SAN="DNS:${SERVER_HOSTNAME}"
if [ -n "${EXTRA_SAN:-}" ]; then
  SERVER_SAN="${SERVER_SAN},${EXTRA_SAN}"
fi

EXT_FILE="$(mktemp)"
CSR_FILE="$(mktemp)"
trap 'rm -f "$EXT_FILE" "$CSR_FILE"' EXIT

umask 077

cat > "$EXT_FILE" <<EOF
[ server_cert_ext ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName         = ${SERVER_SAN}
EOF

openssl ecparam -genkey -name prime256v1 -noout -out "${OUT_PREFIX}.key.pem"
openssl req -new -key "${OUT_PREFIX}.key.pem" -out "$CSR_FILE" \
  -subj "/CN=${SERVER_HOSTNAME}"

# -subj forces the CN server-side, exactly as OpenSslCaInvoker does for
# client certificates: the CSR's own subject is never trusted.
openssl ca -config "$CONFIG" -batch \
  -extfile "$EXT_FILE" -extensions server_cert_ext \
  -days "$DAYS" \
  -subj "/CN=${SERVER_HOSTNAME}" \
  -in "$CSR_FILE" \
  -out "${OUT_PREFIX}.cert.pem"

# env: rather than pass:, so the password never appears in the process list.
openssl pkcs12 -export \
  -inkey "${OUT_PREFIX}.key.pem" \
  -in "${OUT_PREFIX}.cert.pem" \
  -certfile "$CA_DIR/certs/ca.cert.pem" \
  -name server \
  -out "${OUT_PREFIX}.p12" \
  -passout env:P12_PASSWORD

NOT_AFTER="$(openssl x509 -in "${OUT_PREFIX}.cert.pem" -noout -enddate | cut -d= -f2-)"

echo
echo "Issued server identity certificate"
echo "  hostname : ${SERVER_HOSTNAME}"
echo "  SAN      : ${SERVER_SAN}"
echo "  keystore : ${OUT_PREFIX}.p12"
echo "  expires  : ${NOT_AFTER}"
echo
echo "Point the service's server.keystore at ${OUT_PREFIX}.p12 and set"
echo "server.keystore.password to the P12_PASSWORD you used."
echo
echo "Nothing renews this certificate automatically. Diary the expiry date"
echo "above and re-run this script before it passes -- the service logs a"
echo "warning from 30 days out, and every client handshake fails after it."

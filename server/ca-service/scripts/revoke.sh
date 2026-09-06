#!/usr/bin/env bash
# Revokes every currently-valid certificate issued to a client_id, then
# regenerates the CRL. Run by an operator authenticated through the
# existing MFA'd server login -- same trust boundary as init-ca.sh /
# issue-token.sh, no separate auth layer here either.
#
# Usage: ./revoke.sh <client_id> [ca-dir]
set -euo pipefail

CLIENT_ID="${1:?Usage: revoke.sh <client_id> [ca-dir]}"
CA_DIR="${2:-/etc/pki/internal-ca}"
CONFIG="$CA_DIR/openssl-ca.cnf"

SERIALS=$(awk -F'\t' -v cn="/CN=${CLIENT_ID}" '$1=="V" && $6==cn {print $4}' "$CA_DIR/index.txt")

if [ -z "$SERIALS" ]; then
  echo "No currently-valid certificate found for client_id=$CLIENT_ID" >&2
  exit 1
fi

for serial in $SERIALS; do
  echo "Revoking serial $serial for $CLIENT_ID"
  openssl ca -config "$CONFIG" -revoke "$CA_DIR/newcerts/${serial}.pem"
done

"$(dirname "$0")/gen-crl.sh" "$CA_DIR"
echo "Revoked $(echo "$SERIALS" | wc -l) certificate(s) for client_id=$CLIENT_ID"

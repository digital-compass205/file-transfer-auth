#!/usr/bin/env bash
# Regenerates the CRL that RenewHandler and the file-receiver both read
# directly off local disk. Run after revoke.sh, and periodically (e.g. via a
# systemd timer) since a CRL has its own expiry (default_crl_days in
# openssl-ca.cnf) even with no new revocations.
set -euo pipefail

CA_DIR="${1:-/etc/pki/internal-ca}"
CONFIG="$CA_DIR/openssl-ca.cnf"

openssl ca -config "$CONFIG" -gencrl -out "$CA_DIR/crl/ca.crl.pem"
echo "CRL regenerated at $CA_DIR/crl/ca.crl.pem"

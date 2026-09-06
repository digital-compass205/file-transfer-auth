#!/usr/bin/env bash
# Mints a one-time enrollment token for a client_id. Run by an operator
# authenticated through the existing MFA'd server login -- see
# IssueTokenCli.java for why this has no auth of its own.
#
# Usage: ./issue-token.sh <client_id> [validity_hours]
set -euo pipefail

JAR="${CA_SERVICE_JAR:-/opt/ca-service/ca-service.jar}"
CONFIG="${CA_SERVICE_CONFIG:-/etc/ca-service/ca-service.properties}"

exec java -cp "$JAR" com.filetransfer.ca.IssueTokenCli "$CONFIG" "$@"

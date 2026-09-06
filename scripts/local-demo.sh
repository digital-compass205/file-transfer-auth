#!/usr/bin/env bash
# Runs the whole system (CA-service + file-receiver + client agent) on a
# single machine, in a throwaway directory, so you can see the real
# enrollment -> upload -> renewal -> revocation flow end to end without
# touching a RHEL 8 box or any real infrastructure. It is a demo harness,
# not the production deployment (see README.md "Production deployment on
# RHEL 8" for that).
#
# Requirements: a JDK 17 + `openssl` on PATH, and the project already built
# (`./build.sh` from the repo root -- no Maven, no network access, no
# third-party jars). If you don't want to install a JDK on your own
# machine, see README.md "Building without installing anything locally"
# for a container-based way to run both that and this script.
#
# Usage:
#   scripts/local-demo.sh [work-dir]
# work-dir defaults to /tmp/file-transfer-demo and is wiped at the start of
# each run.

set -eu
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-/tmp/file-transfer-demo}"
CA_DIR="$WORK/pki/internal-ca"

JAR_AGENT="$REPO_ROOT/build/jars/agent.jar"
JAR_CA="$REPO_ROOT/build/jars/ca-service.jar"
JAR_RECV="$REPO_ROOT/build/jars/file-receiver.jar"

for jar in "$JAR_AGENT" "$JAR_CA" "$JAR_RECV"; do
  if [ ! -f "$jar" ]; then
    echo "Missing $jar -- run './build.sh' from $REPO_ROOT first." >&2
    exit 1
  fi
done

CA_PID=""
RECV_PID=""
AGENT_PID=""
RENEW_PID=""
IPTEST_PID=""
cleanup() {
  echo
  echo "==> Shutting down demo processes"
  for pid in "$IPTEST_PID" "$RENEW_PID" "$AGENT_PID" "$RECV_PID" "$CA_PID"; do
    [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# Prints the serial number of the client certificate inside a PKCS12
# keystore, or nothing if the file is momentarily unreadable (the agent
# replaces it by atomic rename during renewal).
cert_serial() {
  openssl pkcs12 -in "$1" -passin pass:changeit -nokeys -clcerts 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2 || true
}

cert_pubkey() {
  openssl pkcs12 -in "$1" -passin pass:changeit -nokeys -clcerts 2>/dev/null \
    | openssl x509 -noout -pubkey 2>/dev/null || true
}

rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> 1. Initializing a throwaway private CA at $CA_DIR"
# init-ca.sh also installs openssl-ca.cnf with `dir` pointed here and
# generates the first CRL -- both services fail closed without one.
bash "$REPO_ROOT/server/ca-service/scripts/init-ca.sh" "$CA_DIR"

echo "==> 2. Issuing TLS server identity certs for ca-service and file-receiver"
# Both services answer on localhost here, so both certs get SAN DNS:localhost
# and nothing else -- the hostname-binding step below relies on 127.0.0.1
# *not* being covered.
for name in ca-svc receiver-svc; do
  P12_PASSWORD=changeit bash "$REPO_ROOT/server/ca-service/scripts/issue-server-cert.sh" \
    localhost "$WORK/$name" "$CA_DIR" 397 >/dev/null
done

echo "==> 3. Writing server config"
cat > "$WORK/ca-service.properties" <<EOF
port=9443
server.keystore=$WORK/ca-svc.p12
server.keystore.password=changeit
ca.openssl.config=$CA_DIR/openssl-ca.cnf
ca.cert=$CA_DIR/certs/ca.cert.pem
ca.crl=$CA_DIR/crl/ca.crl.pem
ca.workdir=$CA_DIR/tmp
openssl.binary=openssl
ca.tokenstore=$CA_DIR/tokens.tsv
log.file=$WORK/ca-service.jsonl
EOF

cat > "$WORK/receiver.properties" <<EOF
port=8443
server.keystore=$WORK/receiver-svc.p12
server.keystore.password=changeit
ca.cert=$CA_DIR/certs/ca.cert.pem
ca.crl=$CA_DIR/crl/ca.crl.pem
storage.incoming=$WORK/incoming
storage.quarantine=$WORK/quarantine
log.file=$WORK/receiver.jsonl
upload.max_bytes=1073741824
EOF

echo "==> 4. Starting ca-service (:9443) and file-receiver (:8443)"
java -jar "$JAR_CA" "$WORK/ca-service.properties" > "$WORK/ca-service.out" 2>&1 &
CA_PID=$!
java -jar "$JAR_RECV" "$WORK/receiver.properties" > "$WORK/receiver.out" 2>&1 &
RECV_PID=$!
sleep 2
cat "$WORK/ca-service.out" "$WORK/receiver.out"

echo "==> 5. Operator issues a one-time enrollment token for 'demo-client'"
TOKEN=$(java -cp "$JAR_CA" com.filetransfer.ca.IssueTokenCli "$WORK/ca-service.properties" demo-client 24 \
  | tee /dev/stderr | awk '/^token:/ {print $2}')

echo "==> 6. Client agent enrolls (consumes the token) and starts watching a folder"
mkdir -p "$WORK/watched"
cat > "$WORK/agent.properties" <<EOF
client.id=demo-client
ca.service.url=https://localhost:9443
receiver.url=https://localhost:8443
ca.cert=$CA_DIR/certs/ca.cert.pem
keystore.path=$WORK/agent-keystore.p12
keystore.password=changeit
watch.folders=$WORK/watched
journal.path=$WORK/upload-journal.jsonl
log.file=$WORK/agent.jsonl
watch.stable_seconds=2
watch.poll_interval_seconds=1
renew.check_interval_hours=6
EOF
# One invocation both enrolls (because a token is given) and then keeps
# running as the normal watch/upload/renew loop -- this is the agent's
# real, documented behavior, not demo-only shortcut.
java -jar "$JAR_AGENT" "$WORK/agent.properties" "$TOKEN" > "$WORK/agent.out" 2>&1 &
AGENT_PID=$!
sleep 2
cat "$WORK/agent.out"

echo "==> 7. Dropping a file into the watched folder"
echo "hello from the local demo, $(date)" > "$WORK/watched/hello.txt"
EXPECTED_SHA=$(sha256sum "$WORK/watched/hello.txt" | awk '{print $1}')

echo "==> 8. Waiting for it to be picked up, hashed, and uploaded over mTLS"
for i in $(seq 1 20); do
  [ -f "$WORK/incoming/demo-client/hello.txt" ] && break
  sleep 1
done
if [ -f "$WORK/incoming/demo-client/hello.txt" ]; then
  ACTUAL_SHA=$(sha256sum "$WORK/incoming/demo-client/hello.txt" | awk '{print $1}')
  echo "    File arrived at $WORK/incoming/demo-client/hello.txt"
  echo "    sha256 on the client : $EXPECTED_SHA"
  echo "    sha256 on the server : $ACTUAL_SHA"
  [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] && echo "    MATCH -- upload verified end to end." \
    || { echo "    MISMATCH -- something is wrong."; exit 1; }
else
  echo "    File never arrived within 20s -- something is wrong." >&2
  echo "--- agent.jsonl ---"; cat "$WORK/agent.jsonl" 2>&1
  echo "--- receiver.jsonl ---"; cat "$WORK/receiver.jsonl" 2>&1
  exit 1
fi

echo "==> 9. Confirming certificates rotate themselves, keys and all"
# Renewal is the least observable part of the system: in production it fires
# once every couple of days, so nothing else here would ever exercise it.
# This agent is configured to check every few seconds and to treat any
# certificate as due (renew.below_fraction=1.0), which compresses the real
# renewal path -- new key pair, CSR, mTLS-authenticated /renew, atomic
# keystore swap -- into something observable in half a minute.
RENEW_TOKEN=$(java -cp "$JAR_CA" com.filetransfer.ca.IssueTokenCli \
  "$WORK/ca-service.properties" renew-client 24 | awk '/^token:/ {print $2}')
mkdir -p "$WORK/watched-renew"
sed -e "s|^client.id=.*|client.id=renew-client|" \
    -e "s|^keystore.path=.*|keystore.path=$WORK/agent-renew.p12|" \
    -e "s|^watch.folders=.*|watch.folders=$WORK/watched-renew|" \
    -e "s|^journal.path=.*|journal.path=$WORK/upload-journal-renew.jsonl|" \
    -e "s|^log.file=.*|log.file=$WORK/agent-renew.jsonl|" \
    -e "s|^renew.check_interval_hours=.*|renew.check_interval_seconds=5\nrenew.below_fraction=1.0|" \
    "$WORK/agent.properties" > "$WORK/agent-renew.properties"

java -jar "$JAR_AGENT" "$WORK/agent-renew.properties" "$RENEW_TOKEN" > "$WORK/agent-renew.out" 2>&1 &
RENEW_PID=$!

FIRST_SERIAL=""
for i in $(seq 1 20); do
  FIRST_SERIAL="$(cert_serial "$WORK/agent-renew.p12")"
  [ -n "$FIRST_SERIAL" ] && break
  sleep 1
done
if [ -z "$FIRST_SERIAL" ]; then
  echo "    renew-client never enrolled -- check $WORK/agent-renew.out" >&2
  cat "$WORK/agent-renew.out" >&2
  exit 1
fi
FIRST_PUBKEY="$(cert_pubkey "$WORK/agent-renew.p12")"
echo "    initial certificate serial: $FIRST_SERIAL"

# Collect distinct serials until two rotations have happened.
SERIALS="$FIRST_SERIAL"
DISTINCT=1
for i in $(seq 1 40); do
  S="$(cert_serial "$WORK/agent-renew.p12")"
  if [ -n "$S" ] && ! echo "$SERIALS" | grep -qx "$S"; then
    SERIALS="$SERIALS
$S"
    DISTINCT=$((DISTINCT + 1))
    echo "    rotated to certificate serial: $S"
    [ "$DISTINCT" -ge 3 ] && break
  fi
  sleep 1
done

if [ "$DISTINCT" -lt 3 ]; then
  echo "    Only saw $DISTINCT certificate(s) across two expected rotations." >&2
  echo "--- agent-renew.jsonl ---"; cat "$WORK/agent-renew.jsonl" 2>&1
  exit 1
fi
echo "    Two rotation cycles completed ($DISTINCT distinct certificates)."

LAST_PUBKEY="$(cert_pubkey "$WORK/agent-renew.p12")"
if [ "$FIRST_PUBKEY" = "$LAST_PUBKEY" ]; then
  echo "    FAIL -- the public key never changed, so renewal reused the old key." >&2
  exit 1
fi
echo "    Public key changed too -- renewal rotates keys, not just certificates."

# The agent must still be able to upload with the certificate it just
# swapped in. This is what catches a client that cached TLS material from
# the superseded keystore.
echo "post-rotation upload, $(date)" > "$WORK/watched-renew/after-rotation.txt"
for i in $(seq 1 20); do
  [ -f "$WORK/incoming/renew-client/after-rotation.txt" ] && break
  sleep 1
done
if [ -f "$WORK/incoming/renew-client/after-rotation.txt" ]; then
  echo "    Upload after rotation succeeded, using the freshly issued certificate."
else
  echo "    FAIL -- could not upload after renewal; the agent is still on the old identity." >&2
  echo "--- agent-renew.jsonl ---"; cat "$WORK/agent-renew.jsonl" 2>&1
  exit 1
fi
kill "$RENEW_PID" >/dev/null 2>&1 || true
wait "$RENEW_PID" 2>/dev/null || true
RENEW_PID=""

echo "==> 10. Confirming the agent checks the server's hostname, not just its CA"
# Same keystore, same CA, same listening socket -- only the name dialed
# differs. The server cert says SAN=DNS:localhost, so dialing 127.0.0.1 must
# fail the handshake. If it succeeds, hostname verification is off and any
# certificate this CA ever signed would be accepted for any server.
cp "$WORK/agent-keystore.p12" "$WORK/agent-keystore-iptest.p12"
mkdir -p "$WORK/watched-iptest"
sed -e "s|^receiver.url=.*|receiver.url=https://127.0.0.1:8443|" \
    -e "s|^keystore.path=.*|keystore.path=$WORK/agent-keystore-iptest.p12|" \
    -e "s|^watch.folders=.*|watch.folders=$WORK/watched-iptest|" \
    -e "s|^journal.path=.*|journal.path=$WORK/upload-journal-iptest.jsonl|" \
    -e "s|^log.file=.*|log.file=$WORK/agent-iptest.jsonl|" \
    "$WORK/agent.properties" > "$WORK/agent-iptest.properties"

java -jar "$JAR_AGENT" "$WORK/agent-iptest.properties" > "$WORK/agent-iptest.out" 2>&1 &
IPTEST_PID=$!
echo "should not arrive" > "$WORK/watched-iptest/must-not-upload.txt"
for i in $(seq 1 15); do
  grep -q '"event":"upload_failed_will_retry"' "$WORK/agent-iptest.jsonl" 2>/dev/null && break
  sleep 1
done
kill "$IPTEST_PID" >/dev/null 2>&1 || true
wait "$IPTEST_PID" 2>/dev/null || true
IPTEST_PID=""

if [ -f "$WORK/incoming/demo-client/must-not-upload.txt" ]; then
  echo "    FAIL -- file uploaded over a connection whose hostname did not match the cert." >&2
  exit 1
elif grep -q '"event":"upload_failed_will_retry"' "$WORK/agent-iptest.jsonl" 2>/dev/null; then
  echo "    Agent refused to upload to 127.0.0.1 against a DNS:localhost cert, as expected."
else
  echo "    Inconclusive -- no upload attempt recorded; check $WORK/agent-iptest.jsonl" >&2
  exit 1
fi

echo "==> 11. Revoking demo-client and confirming it's immediately locked out"
bash "$REPO_ROOT/server/ca-service/scripts/revoke.sh" demo-client "$CA_DIR" >/dev/null
echo "second file, dropped after revocation" > "$WORK/watched/after-revoke.txt"
sleep 5
if grep -q '"reason":"revoked"' "$WORK/receiver.jsonl"; then
  echo "    Receiver rejected the post-revocation upload with 401/revoked, as expected."
else
  echo "    Did not see a revocation rejection in receiver.jsonl -- check $WORK/receiver.jsonl" >&2
  exit 1
fi

echo
echo "==> Demo complete. Inspect $WORK for full logs (agent.jsonl, receiver.jsonl,"
echo "    ca-service.jsonl) and the CA state under $CA_DIR. Re-run this script any"
echo "    time; it wipes and recreates $WORK from scratch."

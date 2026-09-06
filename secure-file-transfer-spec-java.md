# Secure Unattended File Transfer System — Build Spec (Java client / RHEL 8 Java server)

## 1. Goal

Build a system where an unattended background agent, installed on a
non-technical client's machine (Windows or Linux), watches specified folders
and securely uploads files to a central server. The server runs **RHEL 8**.
Authentication uses short-lived (5-day) mTLS client certificates issued by a
private CA, auto-renewed with no human interaction after initial enrollment.
The client is **Java**. The server is **Java**, deliberately minimizing added
third-party runtime dependencies.

Non-goals: this is not a general file-sync tool (no bidirectional sync, no
conflict resolution), not a remote-management/RAT tool (agent has zero
exec/shell capability), and not a public SaaS product (single-tenant, your
infra only).

## 2. Threat model / security requirements

Unchanged from the original design:

- Client machines are semi-trusted: assume they could be lost, stolen, or on
  a hostile network. Compromise of one client must not compromise others or
  the server.
- No inbound ports open on client machines. Agent only makes outbound
  connections.
- No long-lived shared secrets. No single API key baked into every
  installer.
- All transport is TLS 1.2+ (prefer 1.3), server identity always validated,
  no disabled certificate checks anywhere in the code.
- Client identity is proven via a private key that never leaves the client
  machine and was generated on that machine.
- Compromised/stolen client credentials should have a short blast radius
  and be explicitly revocable immediately. Precisely: a stolen keystore is
  useless 5 days after the *legitimate* agent last renewed — but an attacker
  who holds the keystore and its password can keep renewing it indefinitely,
  because renewal authenticates with exactly that material. The 5-day
  lifetime bounds a credential that is stolen and then goes unused; it does
  not bound one that is actively used. Revocation, not expiry, is what stops
  a detected compromise.
- Agent runs as a low-privilege account, filesystem access limited to the
  folders it's configured to watch.
- Agent has no code-execution surface: no shell-out, no eval, no dynamic
  plugin loading. Its only jobs are: watch folder → checksum → upload →
  renew own certificate.
- Server validates every uploaded filename/path server-side; a
  client-supplied filename must never be used to construct a raw filesystem
  path (path traversal prevention).
- Every transfer is logged (client identity, file hash, size, timestamp) on
  both sides.

## 3. High-level architecture

```
 ┌─────────────────────┐        outbound only, mTLS          ┌──────────────────────────────┐
 │  Client Agent         │ ───────────────────────────────────▶│  RHEL 8 Server                │
 │  (Java, JDK built-ins │                                      │                               │
 │   only -- no third-   │◀───────────────────────────────────│  ┌─────────────────────────┐  │
 │   party dependencies) │   signed cert / upload ack           │  │ ca-service (Java)        │  │
 │  - folder watcher     │                                      │  │  - HttpsServer (JDK)     │  │
 │  - enrollment client  │                                      │  │  - shells out to system  │  │
 │  - renewal loop       │                                      │  │    `openssl ca` to sign  │  │
 │  - upload client      │                                      │  │  - issues 5-day certs    │  │
 │  - local key store    │                                      │  │  - CRL via openssl       │  │
 └─────────────────────┘                                       │  └─────────────────────────┘  │
                                                                 │  ┌─────────────────────────┐  │
                                                                 │  │ file-receiver (Java)    │  │
                                                                 │  │  - HttpsServer (JDK)    │  │
                                                                 │  │  - requires client cert │  │
                                                                 │  │  - verifies hash         │  │
                                                                 │  │  - checks local CRL      │  │
                                                                 │  │  - writes per-client dir │  │
                                                                 │  └─────────────────────────┘  │
                                                                 └──────────────────────────────┘
```

Two server-side services, both running as systemd units under RHEL 8, both
plain Java processes with **no application server / web framework**:

1. **CA-service** — issues and renews client certificates. It does not
   implement any X.509 signing logic itself; it shells out to the system
   `openssl` binary (already a base RHEL 8 package, not a new install) for
   the actual `openssl ca` signing and `openssl ca -gencrl` CRL generation.
   Revocation and the one-time root CA key generation are operator actions —
   see §6/§13.
2. **File-receiver** — a small custom HTTPS service that requires a valid
   client certificate (mTLS), accepts file uploads, verifies integrity,
   checks the cert against the locally-generated CRL, and writes to storage.

## 4. Why these technology choices

- **Java client, zero dependencies**: `java.net.http.HttpClient` (JDK 11+)
  for outbound mTLS calls, `java.nio.file.WatchService` for cross-platform
  (Windows/Linux) folder watching, `java.security.MessageDigest` for
  SHA-256, `java.security.KeyStore` (PKCS12) for local key storage — all
  built into the JDK. The JDK has no public API to build a PKCS#10 CSR, so
  the one non-trivial piece (`agent/.../crypto/CsrBuilder.java` +
  `Der.java`) hand-encodes that one fixed ASN.1 structure: key generation
  and signing are still 100% delegated to the JDK's own providers
  (`KeyPairGenerator`, `Signature`) — only the DER *structuring* around
  already-computed, already-correct bytes is hand-written, which is a data
  layout task, not a cryptographic one. This was chosen over a third-party
  CSR library (e.g. Bouncy Castle) specifically so the "minimize third
  parties" requirement — originally scoped to the server only — ends up
  applying to the whole project: nothing here needs network access or a
  dependency manager to build, on RHEL 8 or anywhere else. See the
  project README's appendix for the detailed reasoning and how this was
  verified.
- **Java server, zero extra runtime deps**: `com.sun.net.httpserver.HttpsServer`
  (ships with every JDK) makes mTLS enforcement a config setting
  (`SSLParameters.setNeedClientAuth(true)`), not custom TLS code. No Spring,
  no Netty, no Jetty. `X509CRL.isRevoked(cert)` (also built into the JDK)
  covers revocation checks against a locally-regenerated CRL file — no
  OCSP/CRL-fetching client code needed.
- **OpenSSL CLI for the CA**: already present and patched via `dnf` like any
  base RHEL 8 package, so it doesn't count against "minimize third parties"
  the way installing a dedicated CA binary (e.g. step-ca) would. The
  tradeoff is that the CA-service manages OpenSSL's flat-file CA state
  (`index.txt`, `serial`, `openssl-ca.cnf`) and invokes it as a subprocess
  rather than doing certificate issuance in-process.
- **Bootstrap trust rides on the existing MFA'd server login, not a new
  side-channel.** Root CA key generation and per-client enrollment-token
  issuance are plain CLI scripts (`init-ca.sh`, `issue-token.sh`) that an
  operator runs after authenticating through the organization's existing
  MFA-gated server login. No separate token-issuance auth layer (e.g. a web
  portal with its own auth) is built — that already-audited login session
  *is* the trust boundary for these actions.
- **Upload framing is a small custom protocol, not multipart/form-data.**
  Since both the client and server are our own code, uploads use a simple
  length-prefixed framing — `[4-byte big-endian manifest length][UTF-8 JSON
  manifest][raw file bytes]` — instead of implementing a general
  multipart/form-data parser. This avoids a notoriously fiddly parsing
  surface for no real benefit here. See §9.
- **Firewall configuration is out of scope** — already managed outside this
  project. This doc lists the two ports the server processes bind to
  (informational, for whoever maintains the existing firewall rules) but
  does not include `firewall-cmd` setup.

## 5. RHEL 8 server setup

### 5.1 Base packages
```bash
sudo dnf install -y java-17-openjdk-devel openssl policycoreutils-python-utils
```

### 5.2 OpenSSL-based CA layout
Standard `openssl ca` directory structure under `/etc/pki/internal-ca/`:
```
/etc/pki/internal-ca/
  private/ca.key.pem      (0400, owned by the CA-service's dedicated user)
  certs/ca.cert.pem
  newcerts/                # openssl ca writes one file per issued cert here
  crl/ca.crl.pem
  index.txt                # openssl ca's certificate database
  index.txt.attr
  serial
  crlnumber
  openssl-ca.cnf
```

`openssl-ca.cnf` (key settings):
```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir             = /etc/pki/internal-ca
certs           = $dir/certs
new_certs_dir   = $dir/newcerts
database        = $dir/index.txt
serial          = $dir/serial
private_key     = $dir/private/ca.key.pem
certificate     = $dir/certs/ca.cert.pem
default_md      = sha256
default_days    = 5
policy          = policy_loose
copy_extensions = none        # never honor extensions/SANs requested in a CSR
x509_extensions = client_cert_ext

[ policy_loose ]
commonName = supplied

[ client_cert_ext ]
basicConstraints       = CA:FALSE
keyUsage                = critical, digitalSignature
extendedKeyUsage        = clientAuth
subjectKeyIdentifier    = hash
```
`copy_extensions = none` is the important line: it guarantees a client's CSR
can never smuggle in its own SANs, `CA:TRUE`, or other extensions — the
server-side x509_extensions section is the sole source of truth for what a
signed cert can do.

Two more settings are load-bearing and easy to mistake for boilerplate:

- `unique_subject = no`. Renewal issues a second, third, ... certificate for
  the same `CN=<client_id>`, and OpenSSL's default is to refuse a duplicate
  subject. Without this line `openssl ca` fails with `Error creating name
  index` on the first renewal, which would break every client a few days
  after deployment.
- `default_crl_days = 1`, which is what makes the CRL's `nextUpdate` a day
  out and therefore what the `gen-crl` timer cadence is set against (§7).

`init-ca.sh` generates the key and the self-signed root, installs this file
into the CA directory with `dir` rewritten to point at it, and produces the
first CRL. The root certificate's own profile (`CA:TRUE`, `keyCertSign`,
`cRLSign`) is pinned by that script rather than inherited from the host's
`/etc/pki/tls/openssl.cnf`, which differs between OpenSSL 1.1.1 and 3.x —
the most important certificate in the system should not be the one whose
shape depends on which box it was generated on.

One-time root CA key generation (`init-ca.sh`) and per-client enrollment
token issuance (`issue-token.sh`) are run interactively by an operator **who
has already authenticated via the existing MFA-gated server login** — see
§6 and §13. Whether to run a single-tier CA (root key lives on this host) or
a two-tier CA (offline root + an online issuing CA) is a decision left to
the operator; two-tier is the better-practice default, single-tier is an
acceptable prototype shortcut. Either way, the *initiation* of key
generation rides on the same MFA login — no separate auth surface is added
for it.

### 5.3 systemd units
Two services, each a plain `java -jar` process — see `deploy/systemd-user/`,
plus a `gen-crl` service/timer pair covered in §7.

Ideally each service runs under its own unprivileged account (`ca-svc`,
`receiver-svc`), so that only `ca-svc` may invoke `openssl ca` against the CA
directory and `receiver-svc` has no access to CA material at all — privilege
separation between "can sign certs" and "handles internet-facing uploads".

**What is actually shipped is weaker than that**, and the README is the
authoritative deployment guide: the units are `systemd --user` units and the
README runs both under a single account (`servacc`), relying on
`ProtectSystem=strict` plus `ReadOnlyPaths` to keep the receiver away from
the CA private key. That stops accidents and most bugs but is not the
OS-enforced separation two accounts would give. Running one `systemd --user`
instance per account is the upgrade path; see the README's "Known
limitations".

### 5.4 SELinux
If SELinux is enforcing (default on RHEL 8), label the receiver's storage
directory and confirm the JVM process can bind its port and read/write its
data dir:
```bash
sudo semanage fcontext -a -t var_t "/var/lib/file-receiver(/.*)?"
sudo restorecon -Rv /var/lib/file-receiver
```
Exact labels depend on packaging; avoid `semanage permissive` in shipped
configuration.

### 5.5 Ports (informational — firewall managed elsewhere)
- CA-service: `9443/tcp`
- File-receiver: `8443/tcp`

### 5.6 Storage layout
```
/var/lib/file-receiver/
  incoming/<client-id>/        # per-client, created on first successful upload
  quarantine/<client-id>/      # failed hash checks land here for review
/var/log/file-receiver/
/etc/pki/internal-ca/          # see §5.2
/var/log/ca-service/
```

### 5.7 Server TLS identity certificates

Each of the two services presents its own certificate to connecting agents.
These are distinct from the client certificates the CA issues to agents, in
profile and in lifecycle, and are issued by `issue-server-cert.sh`:

```bash
P12_PASSWORD='<keystore-password>' issue-server-cert.sh <hostname> <out-prefix> [ca-dir] [days]
```

Profile (supplied to `openssl ca` via `-extfile`, not from the CSR):
```ini
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName         = DNS:<hostname>
```

Two properties are enforced by the script rather than left to whoever types
the command:

- **A `subjectAltName` naming the host.** Agents verify the hostname they
  dialed against this SAN (§10), so a server certificate without one, or
  with the wrong one, is rejected at the handshake. `copy_extensions = none`
  means a CSR can no more request its own SAN than its own extensions, so
  the name is set server-side from the script's argument. `keyEncipherment`
  is deliberately absent: these are EC keys negotiating ECDHE, so only
  `digitalSignature` is ever exercised.
- **An explicit, long lifetime (default 397 days).** `default_days = 5` in
  `openssl-ca.cnf` is the *client* certificate lifetime, and client
  certificates are the only ones anything renews automatically. A server
  certificate that inherited 5 days would take the whole system down within
  a week of deployment: both services would present expired certificates,
  every agent handshake would fail, and because `/renew` is served over the
  same TLS, every client certificate would then expire too — putting every
  client back to needing an operator-issued enrollment token. Server
  certificates therefore keep their profile out of `openssl-ca.cnf`
  entirely, so they cannot silently inherit that default.

Nothing renews these automatically. Both services read their own
certificate at startup, log its `notAfter` and remaining days, and warn on
stderr below 30 days remaining (`ServerIdentityCheck`).

## 6. Enrollment flow (detailed)

1. **Operator side, once per client, no new auth layer:** the operator,
   already authenticated through the existing MFA'd server login, runs
   `issue-token.sh <client_id>` on the CA-service host. It generates a
   random one-time token, stores `{token, client_id, expires_at, used}` in a
   small flat file, and prints the token for the operator to relay
   out-of-band (email/SMS/portal) to the client, along with the agent
   installer — this delivery step is unchanged from a conventional design.
2. **Client side, first run:**
   - Agent generates an EC (P-256) keypair locally via the JDK's
     `KeyPairGenerator`. The private key never leaves the device.
   - Agent builds a PKCS#10 CSR (hand-encoded ASN.1, see §4) for `CN=<client_id>`, where
     `client_id` is whatever it was told to use (embedded in the installer
     or entered from the enrollment message).
   - Agent calls `POST /enroll` on the CA-service (TLS server-auth only —
     no client cert exists yet) with `{token, client_id, csr_pem}`.
   - CA-service validates the token (exists, unused, unexpired, matches
     `client_id`), rejects the CSR outright if its public key is below the
     CA's floor (EC < 256 bits, RSA < 2048 bits, or any other algorithm),
     then invokes `openssl ca -config openssl-ca.cnf -batch
     -subj "/CN=<client_id>" -in <csr> -out <cert>` — note the CN is forced
     via `-subj`, **never taken from the CSR's own subject**, so a client
     cannot request an identity it wasn't issued a token for. `client_id` is
     validated against a strict allow-list charset (`[A-Za-z0-9._-]{1,64}`)
     before ever being interpolated into `-subj`, since that flag's value is
     itself a `/type=value/...` mini-DSL — an unvalidated `client_id`
     containing `/` could otherwise inject extra RDNs into the signed
     subject.
   - Token is marked used. CA-service returns the signed certificate.
   - Agent verifies, before storing anything, that the returned certificate
     matches the key it just generated, carries the expected CN, and was
     signed by the CA root it already trusts — then stores the private key
     and certificate in its local keystore (see §8).
   - The CA root the agent trusts is **not** taken from this response. It is
     provisioned with the installer as the `ca.cert` file (§10.1); a trust
     anchor learned from the exchange it is meant to secure would not be an
     anchor. If signing fails, the CA-service returns the one-time token to
     unused rather than burning it, so the client can simply retry.
3. The one-time token is now consumed and cannot be reused — from this point
   on, trust is entirely based on the client's own private key.

## 7. Renewal flow (detailed)

- Agent's background loop checks current cert expiry on every startup and
  every 6h.
- When remaining lifetime drops below ~40% (48h left of a 5-day/120h cert,
  i.e. during day 3), agent:
  1. Generates a **new keypair** (rotating keys, not just certs).
  2. Builds a new CSR for the same `client_id`.
  3. Calls `POST /renew` on the CA-service, authenticated via **mTLS with
     its current, still-valid cert** — no token needed post-bootstrap.
  4. CA-service extracts `client_id` from the **verified peer certificate**
     (never from the request body — same principle as the receiver's
     filename handling), confirms it isn't revoked (`X509CRL.isRevoked`),
     and signs the new CSR the same way as initial enrollment, pinned to
     that same `client_id`.
  5. Agent atomically swaps: write new key+cert to temp files, `rename()`
     over the old ones, only then discard old key material. Never leave the
     agent with no valid cert on disk.
- If renewal fails (network down, server unreachable): retry with
  exponential backoff, log locally, keep using the still-valid old cert.
  If the cert fully expires before renewal succeeds: fail closed — stop
  uploading, keep queuing/logging locally, keep retrying — never fall back
  to an insecure channel.
- **Revocation** is an operator action, run the same way as CA init and
  token issuance: an MFA-authenticated operator runs `revoke.sh
  <client_id>`, which looks up *every* still-valid serial for that client in
  `index.txt` (renewal leaves more than one), runs `openssl ca -revoke` on
  each, then `openssl ca -gencrl` to regenerate `crl/ca.crl.pem`. The
  file-receiver and CA-service both read that CRL directly off local disk
  (all on the same host) — no network CRL fetch.
- **The revocation check fails closed.** Both services refuse the request
  with `503` when the CRL is absent, unparseable, not signed by the CA root,
  or aged past its own `nextUpdate` (plus a 12h grace). Failing open would be
  silent — a typo in `ca.crl`, or a `gen-crl` timer that stopped running,
  would disable revocation enforcement with nothing in the logs to say so.
  Each service also logs `crl_ok` / `crl_unavailable` at startup.
- Because of that, keeping the CRL fresh is part of the deployment, not an
  optional extra: `openssl-ca.cnf` sets `default_crl_days = 1`, and
  `deploy/systemd-user/gen-crl.timer` regenerates it every 6h. `init-ca.sh`
  generates the first CRL so a new CA is usable immediately.

## 8. Client-side key storage

A password-protected PKCS12 keystore (`KeyStore.getInstance("PKCS12")`,
built into the JDK) holding the private key + cert, restricted by OS
filesystem permissions — `0600` on Linux. On Windows, this prototype runs
the agent by hand under a normal user account, so it relies on that user's
normal profile-directory ACLs; OS-native secure storage (DPAPI/Credential
Manager on Windows, keyring on Linux) is documented as future work, not
built now.

## 9. File-receiver service — API contract

Both endpoints require mTLS (client cert validated during the TLS
handshake against the CA root; the app layer additionally checks the
locally-generated CRL and rejects revoked certs with `401`).

### `POST /v1/upload`
Body is a small custom framing, not multipart/form-data (see §4):
```
[4 bytes: big-endian int32 manifest length N]
[N bytes: UTF-8 JSON manifest: {"filename": "...", "sha256": "...", "size_bytes": M}]
[M bytes: raw file content]
```
Server behavior:
1. Extract `client_id` from the **verified certificate's CN**, never from
   the manifest.
2. Check the peer cert against the local CRL; `401` if revoked.
3. Sanitize `filename`: reject empty, reject any path separator (`/` or
   `\`), reject `..`, reject non-printable/control characters. Construct the
   final path server-side as `incoming/<cert-derived-client-id>/<sanitized-filename>`,
   then re-verify that the resolved path still falls under that client's
   directory before any write — twice over, and deliberately so. First
   lexically with `Path.normalize()` + `startsWith()`; then, once the
   directory exists, with a `toRealPath()` comparison of the resolved parent
   against the resolved client directory, which is the check that notices a
   symlinked directory the string-level checks cannot see. Note that
   `client_id` itself is validated (§6) to exclude `.` and `..`, without
   which the "client directory" could be made to resolve above the storage
   root and every containment check would then pass against an
   already-escaped base.
4. Stream to a temp file while computing SHA-256.
5. Compare computed hash to the manifest hash. Mismatch → move to
   `quarantine/<client_id>/`, respond `422`, log. Match → atomically move
   into `incoming/<client_id>/`.
6. On success, respond `200` with `{"status": "ok", "sha256": "..."}`.
7. Log every attempt (success/failure) with client id, filename, hash, size,
   timestamp, source IP as one JSON line.

## 10. Client agent — functional spec

Language: Java (JDK 17). Started by hand for enrollment on both Windows and
Linux. On Linux it can then run as a persistent service via the shipped
`deploy/systemd-user/agent.service`; on Windows there is still no
service-wrapper packaging (WinSW, Commons Daemon, etc.) — see §13.

Responsibilities:
1. **Config**: a properties file specifying watched folder(s), server URL,
   CA root cert path, client identity, poll interval.
2. **Enrollment mode**: triggered on first run if no valid keystore exists.
   Reads the one-time token (CLI arg / config value), performs enrollment
   (§6), exits enrollment mode once a cert is stored.
3. **Main loop**:
   - Watch configured folder(s) via `WatchService` (works on both Windows
     and Linux).
   - Symbolic links are skipped, not followed. Anyone who can drop a file
     into a watched folder can drop a symlink into it too, and following one
     would make the agent a reader of arbitrary files its account can reach
     — exactly the surface §10.5 says it does not have.
   - On detected file: wait for the file to be stable (size unchanged for N
     seconds), compute SHA-256, upload via §9's endpoint over mTLS.
   - On success: log locally, and record the uploaded file's size and mtime;
     leave the source file in place unless configured otherwise. That
     fingerprint is what makes a file edited in place after a successful
     upload count as new work rather than as already delivered — keyed on
     path alone, the edit would be lost silently.
   - On failure: retry with backoff; keep a local JSON-lines journal of
     pending uploads that survives an agent restart — never drop a file
     silently. On startup the journal is replayed: entries that never
     reached `UPLOADED` are re-queued if the file is still there, and logged
     as `upload_abandoned_file_gone` if it is not.
   - Run the renewal check (§7) on its own scheduled ticker in parallel.
4. **Outbound TLS**: every outbound call — enrollment, renewal, upload —
   goes through one `HttpClient` factory (`common/.../http/HttpClients.java`)
   that pins TLS 1.2+, trusts only the internal CA root (never the platform
   trust store), and sets
   `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` so the
   presented certificate's `subjectAltName` must match the host dialed.
   Every request also carries an explicit timeout: `connectTimeout` alone
   bounds only connection setup, and both the renewal ticker and the watcher
   poll are single-threaded, so one server that accepts a connection and
   then stalls would otherwise wedge renewal or all later uploads
   permanently. The mTLS `HttpClient` is built once and reused (one per
   uploaded file would leak a selector thread each time), but is rebuilt
   whenever the keystore's mtime changes — an `SSLContext` captures key
   material when it is created, so a client cached across a renewal would
   keep presenting the superseded certificate.
   Chain validation alone would accept any certificate this CA ever signed,
   including the other service's; the name check is what binds a connection
   to the service it was meant for. It must be set explicitly, because
   supplying custom `SSLParameters` replaces the client's defaults wholesale
   and a blank parameter set leaves the field unset.
5. **No shell-out, no exec, no dynamic code loading.** The agent's attack
   surface is limited to: file I/O in the watched folders, and HTTPS calls
   to the one configured server hostname.
6. **Local logging**: structured JSON-lines logs, readable by the running
   account only (`0600` where the OS supports it), rotated by size — 16 MiB
   per file, five generations. The agent appends a line per upload attempt
   and a persistently failing upload retries every few minutes forever, so
   unrotated files would grow without bound.

## 11. Directory / repo layout

```
/common/                              — shared code (JSON helper, SHA-256,
                                          CRL check, structured logging)
/agent/                                — client
  src/main/java/.../enroll/EnrollmentClient.java
  src/main/java/.../renew/RenewalLoop.java
  src/main/java/.../watch/FolderWatcher.java
  src/main/java/.../upload/UploadClient.java
  src/main/java/.../http/AgentHttpClient.java
  src/main/java/.../keystore/ClientKeyStore.java
  src/main/java/.../crypto/CsrBuilder.java
  src/main/java/.../queue/UploadJournal.java
  src/main/java/.../Main.java
  src/main/resources/agent.example.properties
/server/ca-service/
  src/main/java/.../ca/EnrollHandler.java
  src/main/java/.../ca/RenewHandler.java
  src/main/java/.../ca/OpenSslCaInvoker.java
  src/main/java/.../ca/TokenStore.java
  scripts/openssl-ca.cnf
  scripts/init-ca.sh
  scripts/issue-token.sh
  scripts/issue-server-cert.sh
  scripts/revoke.sh
  scripts/gen-crl.sh
/server/file-receiver/
  src/main/java/.../receiver/UploadHandler.java
  src/main/java/.../receiver/PathSanitizer.java
/deploy/systemd-user/ca-service.service
/deploy/systemd-user/file-receiver.service
/deploy/systemd-user/agent.service
/deploy/systemd-user/gen-crl.service
/deploy/systemd-user/gen-crl.timer
/scripts/local-demo.sh                 — end-to-end demo, doubles as the
                                          automated check for §12
```

## 12. Acceptance criteria / test plan

`scripts/local-demo.sh` is the executable part of this plan: it stands the
whole system up in a throwaway directory and fails with a non-zero exit if
any of the criteria marked *(demo)* below regress. Run it after any change.

- [x] Fresh client with only an enrollment token and installer can enroll
      with zero further manual steps. *(demo, step 6)*
- [x] Agent successfully renews its cert automatically before expiry,
      verified across ≥2 rotation cycles using a shortened test cert
      lifetime. *(demo, step 9 — also asserts the public key changes, i.e.
      that keys rotate and not just certificates, and that an upload
      succeeds afterwards on the new identity)*
- [x] A revoked client certificate is rejected by the file-receiver
      (`/v1/upload`) with `401` immediately after `revoke.sh` runs.
      *(demo, step 11)*
- [x] An agent pointed at an address not covered by the server
      certificate's `subjectAltName` refuses the connection, even though
      that certificate is signed by the pinned CA and the agent's own
      certificate is valid. *(demo, step 10)*
- [x] Uploading a file whose manifest hash doesn't match the actual bytes
      lands in `quarantine/`, not `incoming/`, and answers `422`. An upload
      that ends early is treated the same way rather than as a server error.
- [x] A manifest filename containing `../../etc/passwd`, an absolute path,
      or embedded control characters is rejected, not used to write outside
      the client's directory.
- [x] A `client_id` containing `/` or other `-subj`-special characters — or
      equal to `.` or `..` — is rejected before ever reaching `openssl ca`.
- [x] With the CRL missing, unverifiable or stale, both services reject
      clients (`503`) instead of admitting them.
- [x] A CSR carrying a key below the CA's floor is refused, and the
      one-time token is not consumed by that refusal.

Still verified by hand, not by the demo:

- [ ] Killing network connectivity during a renewal window causes retries,
      not a crash or silent auth failure; resumes when connectivity returns.
- [ ] A revoked client is rejected by the CA-service (`/renew`) as well as
      the receiver. (Same `CrlRevocationChecker` path as the receiver, which
      the demo does cover.)
- [ ] Server enforces TLS 1.2+ only; a plain HTTP or TLS 1.0/1.1 connection
      attempt is rejected.
- [ ] Each service logs its own certificate's expiry at startup, and warns
      when under 30 days remain.
- [ ] All uploads and rejections appear in server logs with client
      identity, hash, and timestamp.

## 13. Open decisions / explicitly deferred

- Single-tier vs two-tier CA (root key on the CA-service host vs a separate
  offline root).
- Whether receiver storage is local disk vs an object store behind it.
- Retention/rotation policy for logs and quarantined files.
- **Partly deferred:** service packaging for the client agent. Linux has a
  `systemd --user` unit (`deploy/systemd-user/agent.service`); Windows has
  no equivalent (WinSW, Commons Daemon, etc.) and is run by hand or from a
  Scheduled Task at logon.
- **Deferred:** OS-native secure storage for the agent's private key
  (DPAPI/Credential Manager on Windows, keyring on Linux). Today it is a
  password-protected PKCS12 restricted by filesystem permissions (§8), with
  the password sitting in the agent's properties file.
- **Deferred:** pruning consumed and long-expired enrollment tokens from
  `tokens.tsv`; the file only grows today.

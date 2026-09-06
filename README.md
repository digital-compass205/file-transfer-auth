# File Transfer Auth

An unattended, agent-based file transfer system: a small Java client watches
folders on a user's machine and securely uploads new files to a central
server, with **no long-lived passwords or API keys anywhere** and **no
person needed after initial setup**. Authentication is mutual TLS (mTLS)
using short-lived (5-day) client certificates issued by a private
certificate authority (CA) that this project also builds and runs.

This repository is a full, runnable implementation: a client agent
(Windows or Linux), a certificate-issuing service, and a file-receiving
service (both intended for RHEL 8), plus scripts to stand up the CA, enroll
clients, and revoke them. The detailed design document is
[`secure-file-transfer-spec-java.md`](secure-file-transfer-spec-java.md);
this README is the practical "what is this, how do I build it, how do I run
it" guide, followed by an appendix that explains, in depth, why this
approach is secure.

## Table of contents

- [The problem this solves](#the-problem-this-solves)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Building](#building)
- [Try it in 2 minutes (local demo)](#try-it-in-2-minutes-local-demo)
- [Production deployment on RHEL 8](#production-deployment-on-rhel-8)
- [Enrolling a client](#enrolling-a-client)
- [Revoking a client](#revoking-a-client)
- [Configuration reference](#configuration-reference)
- [Known limitations / prototype scope](#known-limitations--prototype-scope)
- [Appendix: why this is a secure design](#appendix-why-this-is-a-secure-design)
- [License](#license)

## The problem this solves

Imagine you need files from a non-technical person's computer to show up
reliably and safely on your server, without that person ever having to
manage a password, an API key, or a VPN connection, and without you having
to trust their machine's network. That means:

- **No inbound network access to the client** — the agent only ever makes
  outbound HTTPS connections; nothing needs to open a port or accept a
  connection on the client machine.
- **No shared secret to leak or copy around** — there is no single API key
  baked into an installer that, if leaked, grants access to everything.
  Every client proves its own, unique identity using a private key that
  never leaves its own machine.
- **A stolen or compromised client has a short, bounded blast radius** —
  client credentials expire on their own after 5 days, and can be revoked
  immediately and explicitly by an operator. (Expiry bounds a credential
  that is stolen and then goes unused; revocation is what stops one that is
  actively being used. See
  [appendix §17](#17-what-this-design-does-not-claim-to-solve).)
- **The client software itself has essentially no attack surface** — it
  cannot execute arbitrary code, run a shell command, or read anything
  outside the folder it was told to watch.

This is not a general-purpose file-sync tool (no bidirectional sync, no
conflict resolution) and not a remote-management tool (the agent cannot
execute commands on the client). It does one thing: watch a folder, and
push new files to a server it has cryptographically proven its identity to.

## How it works

```
 ┌─────────────────────┐        outbound only, mTLS          ┌──────────────────────────────┐
 │  Client Agent         │ ───────────────────────────────────▶│  Server                       │
 │  (Java)               │                                      │                               │
 │  - folder watcher     │◀───────────────────────────────────│  ┌─────────────────────────┐  │
 │  - enrollment client  │   signed cert / upload ack           │  │ ca-service (Java)        │  │
 │  - renewal loop       │                                      │  │  - HttpsServer (JDK)     │  │
 │  - upload client      │                                      │  │  - shells out to system  │  │
 │  - local key store    │                                      │  │    `openssl ca` to sign  │  │
 └─────────────────────┘                                       │  │  - issues 5-day certs     │  │
                                                                 │  │  - CRL via openssl        │  │
                                                                 │  └─────────────────────────┘  │
                                                                 │  ┌─────────────────────────┐  │
                                                                 │  │ file-receiver (Java)     │  │
                                                                 │  │  - HttpsServer (JDK)     │  │
                                                                 │  │  - requires client cert   │  │
                                                                 │  │  - verifies hash          │  │
                                                                 │  │  - checks revocation      │  │
                                                                 │  │  - writes per-client dir  │  │
                                                                 │  └─────────────────────────┘  │
                                                                 └──────────────────────────────┘
```

There are three moving pieces, and four things that happen over time:

1. **Enrollment (once per client).** An operator, after logging into the
   server through the organization's existing MFA-protected login, runs a
   one-line script to mint a single-use token for a specific client
   identity, and sends that token to the person receiving the agent
   installer. On first run, the agent generates its own key pair locally
   (the private key never leaves the machine), builds a certificate signing
   request (CSR), and trades the one-time token + CSR for a signed,
   5-day-lived client certificate from `ca-service`. The token is consumed
   and can never be reused.
2. **Watching and uploading (continuous).** The agent watches its
   configured folder(s). When a file appears and stops changing size (so we
   don't upload a half-written file), the agent hashes it (SHA-256) and
   uploads it to `file-receiver` over mTLS. The receiver independently
   re-hashes the bytes it receives; if the hash doesn't match what the
   client claimed, the file is quarantined, not accepted.
3. **Renewal (continuous, automatic).** Before its certificate expires
   (specifically, once less than 40% of its 5-day lifetime remains), the
   agent generates a **new key pair** and asks `ca-service` to sign a new
   certificate for it — authenticating that request with its current,
   still-valid certificate. No human and no token is involved after the
   initial enrollment.
4. **Revocation (as needed, operator-triggered).** If a client machine is
   lost, stolen, or decommissioned, an operator runs a one-line script to
   revoke its certificate. Both servers pick up the change immediately (no
   restart) and will reject that client on its very next request.

See [the appendix](#appendix-why-this-is-a-secure-design) for a detailed
walkthrough of why each of these steps is actually secure, not just
"probably fine."

## Repository layout

```
common/            Shared library code (TLS setup, JSON, hashing, logging) used by
                    both the server and the client -- pure JDK, no third-party deps.
agent/             The client agent (Java). Also pure JDK, including a small
                    hand-written ASN.1/DER encoder (agent/.../crypto/Der.java)
                    used only to build the one CSR structure the JDK has no
                    public API for -- see the appendix for why that's safe.
server/ca-service/ Issues and renews client certificates. Shells out to the system
                    `openssl` binary rather than doing X.509 signing itself. Its
                    scripts/ also hold the operator-run CA lifecycle commands
                    (init, issue-token, issue-server-cert, revoke, gen-crl).
server/file-receiver/  Accepts uploads over mTLS, verifies integrity, checks revocation.
scripts/           local-demo.sh -- runs the whole system on one machine, and doubles
                    as this project's end-to-end test: it exits non-zero if enrollment,
                    upload, renewal, hostname binding or revocation regress.
deploy/systemd-user/  systemd --user units: ca-service, file-receiver, the client agent,
                    and a gen-crl service/timer pair that keeps the CRL fresh.
build.sh           Builds everything with just `javac`/`jar` -- no build tool, no deps.
secure-file-transfer-spec-java.md   The detailed design/build specification.
```

## Requirements

This project has **zero dependencies**, build-time or run-time: no Maven,
no Gradle, no third-party jars, no network access needed to build it.

To **build**: a JDK 17 (specifically its `javac` and `jar` tools -- on RHEL
8, the `java-17-openjdk-devel` package; a JRE-only install won't have
`javac`).

To **run** `ca-service`: additionally, the `openssl` CLI on PATH (RHEL 8
ships this by default; this project deliberately avoids adding any other
CA library).

To **run** the agent or `file-receiver`: just a JRE 17+.

## Building

```bash
./build.sh
```
That's the whole build: it compiles everything with `javac` and packages
three self-contained runnable jars with `jar` --
- `build/jars/agent.jar`
- `build/jars/ca-service.jar`
- `build/jars/file-receiver.jar`

No dependency resolution, no download step, nothing to go wrong because a
registry was unreachable. This is intentional (see the appendix) and is
exactly what makes the project buildable on a network-restricted RHEL 8
box with nothing beyond the JDK devel package already on it.

### Without installing a JDK locally

If you don't want a JDK on your own machine either, build inside a
container instead (works with Docker or Podman; examples use Podman) --
note this only needs a plain JDK image, not anything Maven-specific:

```bash
podman run --rm -v "$PWD:/workspace" -w /workspace \
  docker.io/library/eclipse-temurin:17-jdk \
  bash build.sh
```
(On Windows with Git Bash, prefix the command with `MSYS_NO_PATHCONV=1` so
the `/workspace` path isn't mangled: `MSYS_NO_PATHCONV=1 podman run ...`.)

## Try it in 2 minutes (local demo)

[`scripts/local-demo.sh`](scripts/local-demo.sh) runs the entire system --
a throwaway CA, both servers, and a client agent -- on one machine, in a
throwaway directory. It enrolls a demo client, uploads a real file over real
mTLS and verifies the hash on both ends, drives two full certificate
rotation cycles and checks the key changes each time, confirms the agent
refuses a server whose certificate doesn't name the host it dialed, then
revokes the client and confirms it's immediately locked out.

It exits non-zero if any of that fails, so it is also the closest thing this
project has to a test suite -- run it after any change. (Its renewal step is
the only automated coverage of the renewal path: in production that code
fires once every couple of days, so nothing else would ever exercise it.)

```bash
./build.sh                     # build first, if you haven't
scripts/local-demo.sh          # everything happens under /tmp/file-transfer-demo
```
Or, without installing a JDK locally, do both steps inside the same
container:
```bash
MSYS_NO_PATHCONV=1 podman run --rm -v "$PWD:/workspace" -w /workspace \
  docker.io/library/eclipse-temurin:17-jdk \
  bash -c "bash build.sh && bash scripts/local-demo.sh"
```
Expected output ends with something like:
```
    sha256 on the client : b4c9dc73edfca2753d5901fde24491667f044a3b698363bdd6cd45d70a78511f
    sha256 on the server : b4c9dc73edfca2753d5901fde24491667f044a3b698363bdd6cd45d70a78511f
    MATCH -- upload verified end to end.
==> 9. Confirming certificates rotate themselves, keys and all
    initial certificate serial: 1004
    rotated to certificate serial: 1005
    rotated to certificate serial: 1006
    Two rotation cycles completed (3 distinct certificates).
    Public key changed too -- renewal rotates keys, not just certificates.
    Upload after rotation succeeded, using the freshly issued certificate.
==> 10. Confirming the agent checks the server's hostname, not just its CA
    Agent refused to upload to 127.0.0.1 against a DNS:localhost cert, as expected.
==> 11. Revoking demo-client and confirming it's immediately locked out
    Receiver rejected the post-revocation upload with 401/revoked, as expected.
```
The script prints where every log file and CA artifact lives so you can
poke around afterward; re-running it wipes and recreates its working
directory from scratch.

## Production deployment on RHEL 8

These instructions use `servacc` as the account that runs both
`ca-service` and `file-receiver`, under one directory it owns,
`~/file-transfer`. Log in as `servacc` for all of the following (SSH in
directly, or however your organization normally accesses that account):

```bash
mkdir -p ~/file-transfer/ca-service ~/file-transfer/file-receiver \
         ~/file-transfer/file-receiver/incoming ~/file-transfer/file-receiver/quarantine \
         ~/file-transfer/logs

# CA init -- run this after logging in via the existing MFA'd server login.
# No new authentication mechanism is introduced for this step; see the
# appendix for why that's deliberate.
#
# This also installs openssl-ca.cnf into the CA directory with its `dir`
# pointed there, and generates the first CRL. Neither is optional:
# revocation checking fails closed, so a CA with no CRL rejects every
# client.
server/ca-service/scripts/init-ca.sh ~/file-transfer/pki
```

The CRL carries its own expiry (`default_crl_days = 1`) and the services
start refusing clients once it goes stale, so regenerating it is a scheduled
job rather than a chore someone has to remember. Install the shipped timer:

```bash
mkdir -p ~/file-transfer/scripts ~/.config/systemd/user
cp server/ca-service/scripts/gen-crl.sh ~/file-transfer/scripts/
cp deploy/systemd-user/gen-crl.service deploy/systemd-user/gen-crl.timer \
   ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now gen-crl.timer
```

Each service also needs its own TLS server identity certificate -- the
certificate a connecting agent validates, distinct from the client
certificates the CA issues to agents. `issue-server-cert.sh` generates the
key, gets it signed by the internal CA with the `serverAuth` profile, and
packages the result as the PKCS12 keystore the service loads:
```bash
P12_PASSWORD='<keystore-password>' \
  server/ca-service/scripts/issue-server-cert.sh \
  ca.internal.example.com ~/file-transfer/ca-service/server-identity \
  ~/file-transfer/pki

P12_PASSWORD='<keystore-password>' \
  server/ca-service/scripts/issue-server-cert.sh \
  receiver.internal.example.com ~/file-transfer/file-receiver/server-identity \
  ~/file-transfer/pki
```
Pass the hostname agents will actually dial: it becomes both the CN and the
`subjectAltName`, and agents verify their connection against that SAN, so a
certificate issued for the wrong name is rejected at the handshake. Set
each service's `server.keystore` to the generated `.p12` and its
`server.keystore.password` to the `P12_PASSWORD` you used.

The script prints an expiry date. Server certificates are long-lived
(397 days by default; pass a fourth argument for a different lifetime) and
**nothing renews them automatically** -- unlike client certificates, which
rotate themselves. Diary that date and re-run the script before it passes.
Each service logs its certificate's remaining lifetime at startup and warns
on stderr from 30 days out.

```bash
cp build/jars/ca-service.jar ~/file-transfer/ca-service/
cp build/jars/file-receiver.jar ~/file-transfer/file-receiver/
cp server/ca-service/src/main/resources/ca-service.example.properties \
   ~/file-transfer/ca-service/ca-service.properties
cp server/file-receiver/src/main/resources/receiver.example.properties \
   ~/file-transfer/file-receiver/receiver.properties
# edit both properties files -- point every path at ~/file-transfer/... (see
# the config reference table below), and fill in keystore paths/passwords.
```

Install the systemd units (`deploy/systemd-user/`) as user services:
```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd-user/ca-service.service deploy/systemd-user/file-receiver.service \
   ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ca-service file-receiver
```
Each service logs `crl_ok` or `crl_unavailable` at startup, so
`journalctl --user -u file-receiver` says immediately whether the CRL path is
right — rather than that showing up later as clients being turned away.
To keep both running across logout and reboot, enable lingering for the
account:
```bash
loginctl enable-linger servacc
```
Check status the same way you would for a system unit, just with `--user`:
`systemctl --user status ca-service file-receiver`, `journalctl --user -u ca-service`.

### Using a non-default Java

RHEL 8 manages multiple installed JDKs through `alternatives`, and its
system default (`/usr/bin/java`) may not be 17, which this project
requires. Find where Java 17 actually lives:
```bash
alternatives --display java
```
Two ways to point at it -- pick whichever fits:
- **System-wide, for every user and process on the box**:
  `sudo alternatives --config java` (and `--config javac`, needed for
  `./build.sh`), then pick the `java-17-openjdk` entry.
- **Just for this deployment, without changing the system default**:
  create `~/file-transfer/java.env` (in whichever account's
  `~/file-transfer` -- `servacc` for `ca-service`/`file-receiver`, or
  `cliacc` for `agent`) containing one line:
  ```
  JAVA_BIN=/usr/lib/jvm/java-17-openjdk-17.x.x.x-x.el8.x86_64/bin/java
  ```
  Each unit reads this file if it's present and runs that Java instead of
  the default `/usr/bin/java`, with no unit file to edit. Apply it with
  `systemctl --user daemon-reload && systemctl --user restart <unit>`.

## Enrolling a client

As `servacc` on the server, pointing at the deployment paths from the
previous section (`issue-token.sh`'s defaults differ, so override them
here):
```bash
CA_SERVICE_JAR=~/file-transfer/ca-service/ca-service.jar \
CA_SERVICE_CONFIG=~/file-transfer/ca-service/ca-service.properties \
  server/ca-service/scripts/issue-token.sh client-alice 24
# -> prints a one-time token; relay it out-of-band with the agent installer
```

On the client machine, as `cliacc`. Put everything under `~/file-transfer`
again, for the same reason as the server side: `cliacc` already owns it.
```bash
mkdir -p ~/file-transfer/watched
cp agent.jar ~/file-transfer/
cp agent.example.properties ~/file-transfer/agent.properties   # then edit it
cp ca-root.pem ~/file-transfer/                                # ca-service's ca.cert, given out-of-band
cd ~/file-transfer
java -jar agent.jar agent.properties <the-one-time-token>   # enrolls, then starts watching -- Ctrl+C once you see "Agent running"
```
`client.id` in `agent.properties` must match what the token was issued for.
Once that first run has produced `agent-keystore.p12`, no token is needed
again, so on Linux you can hand it off to a persistent service instead of
running it by hand every time -- `deploy/systemd-user/agent.service`,
installed and enabled the same way as the server units above:
```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd-user/agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now agent
loginctl enable-linger cliacc
```
(If Java isn't 17 by default on this machine either, see
[Using a non-default Java](#using-a-non-default-java) -- same mechanism,
just under `cliacc`'s `~/file-transfer/java.env`.)

There is no Windows Service wrapper -- on Windows, run
`java -jar agent.jar agent.properties` directly (e.g. as a Scheduled Task
at logon) -- see [Known limitations](#known-limitations--prototype-scope).

## Revoking a client

```bash
server/ca-service/scripts/revoke.sh client-alice ~/file-transfer/pki
```
Both `ca-service` (for renewal) and `file-receiver` (for uploads) will
reject that client's certificate with `401` as soon as they next read the
regenerated CRL -- no restart needed.

## Configuration reference

| File | Key fields |
|---|---|
| `agent.properties` | `client.id`, `ca.service.url`, `receiver.url` (both must be `https://`), `ca.cert`, `keystore.path`/`keystore.password`, `watch.folders`, `watch.stable_seconds` (how long a file must stop changing size before it's uploaded), `renew.check_interval_hours`, `upload.timeout_seconds` |
| `ca-service.properties` | `port`, `server.keystore`/`server.keystore.password`, `ca.openssl.config`, `ca.cert`, `ca.crl`, `ca.workdir`, `ca.tokenstore`, `openssl.binary` |
| `receiver.properties` | `port`, `server.keystore`/`server.keystore.password`, `ca.cert`, `ca.crl`, `storage.incoming`, `storage.quarantine`, `upload.max_bytes` |

Two agent settings exist only so that renewal can be tested, and should not
appear in a real deployment: `renew.check_interval_seconds` (overrides
`renew.check_interval_hours`) and `renew.below_fraction` (overrides the
"renew under 40% remaining" threshold). `scripts/local-demo.sh` sets both to
drive two rotation cycles in half a minute.

Full examples with every field are in each module's
`src/main/resources/*.example.properties`.

## Known limitations / prototype scope

- **No Windows Service wrapper for the client agent.** On Linux,
  `deploy/systemd-user/agent.service` runs it as a persistent
  `systemctl --user` service. On Windows there's no equivalent yet (e.g.
  WinSW) -- run it by hand or via a Scheduled Task at logon for now.
- **`TokenStore`'s flat file isn't built for heavy concurrent enrollment.**
  It rewrites the whole file on every token consumption, under a file lock.
  That is correct but serialized -- fine at this system's expected volume
  (occasional, human-triggered enrollments), and it would need a real
  datastore for high-volume, highly concurrent enrollment. Consumed and
  expired tokens are also never pruned, so the file only grows.
- **Revocation checking fails closed, which makes CRL freshness an
  availability dependency.** If the `gen-crl` timer isn't installed, or the
  CRL path is wrong, both services will start rejecting clients (with `503`
  and a `crl_unavailable` log line) rather than silently skipping the check.
  That is the right trade for a security control, but it is a trade: the CRL
  is now something the deployment has to keep alive.
- **The agent's keystore password sits in its properties file.** OS-native
  secure storage (DPAPI/Credential Manager on Windows, keyring on Linux) is
  future work; today the protection is filesystem permissions on the
  keystore (`0600` where the OS supports it) and on the config beside it.
- **Server TLS identity certificates aren't renewed automatically.** Client
  certificates rotate themselves; each server's own identity certificate is
  issued by an operator running `issue-server-cert.sh` and has to be
  reissued before it expires. The services log their remaining lifetime at
  startup and warn from 30 days out, but nothing acts on that warning by
  itself.
- **No OCSP, CRL only**, refreshed locally on each service's own disk. Fine
  for a single-host or few-hosts deployment; a fleet of geographically
  distributed `file-receiver` instances would need a CRL distribution
  strategy.
- **`ca-service` and `file-receiver` run under one account (`servacc`), not
  two.** A `file-receiver` bug is denied filesystem access to the CA's
  private key material by `deploy/systemd-user/file-receiver.service`'s
  `ReadOnlyPaths`, which stops accidents and most bugs, but this is not an
  OS-enforced separation the way running each service under its own
  account would be. Use two separate accounts (one systemd --user instance
  each) instead of one if you need that stronger guarantee.

## Appendix: why this is a secure design

This section walks through the threat model this system defends against
and explains, mechanism by mechanism, why each design choice actually
achieves that -- pointing at the specific code that implements it so the
claims here are checkable, not just asserted.

### Threat model recap

- Client machines are **semi-trusted**: assume any one of them could be
  lost, stolen, or sitting on a hostile network. Compromising one client
  must not compromise any other client or the server.
- The client machine accepts **no inbound connections**; it only makes
  outbound HTTPS calls.
- There is **no long-lived shared secret** anywhere -- no single API key
  baked into every installer that, if it leaked, would compromise every
  client at once.
- A compromised or stolen client's credentials must have a **short, bounded
  blast radius** (a few days) and must be **immediately, explicitly
  revocable**.
- The client software has **no code-execution surface**: no shell-out, no
  `eval`, no dynamic plugin loading. Its only jobs are watch → hash →
  upload → renew its own certificate.
- The server must **never trust a client-supplied identity or filename**
  directly; every trust decision is anchored to something the server itself
  verified cryptographically.

### 1. Why mutual TLS with a private CA, instead of API keys

An API key is a single flat secret: whoever holds the bytes has full access,
forever, until someone remembers to rotate it -- and rotating one API key
usually means rotating (and redistributing) all of them, since there's
often only one. mTLS with a private CA turns this into a
per-client credential model instead: each client has its own key pair,
generated on its own machine, and the server side never needs to hand out
or store a secret the client could leak by itself, because the private key
never travels over the network in the first place (see below). Compromising
one client's certificate says nothing about any other client's certificate.
This is exactly the "compromise of one client must not compromise others"
requirement from the threat model.

### 2. Why the private key never leaves the client machine

Enrollment (`agent/src/main/java/com/filetransfer/agent/enroll/EnrollmentClient.java`)
and renewal (`agent/src/main/java/com/filetransfer/agent/renew/RenewalLoop.java`)
both follow the same shape: the agent calls `CsrBuilder.generate()`
(`agent/.../crypto/CsrBuilder.java`), which generates an EC (P-256) key pair
**locally**, then builds a PKCS#10 certificate signing request (CSR) that
contains only the *public* key. That CSR -- never the private key -- is
what gets sent to `ca-service`. The CA signs the public key into a
certificate and returns it; it never sees, handles, or could leak the
private key, because it was never given it. This is a basic but essential
property of public-key cryptography, and the code path here is structured
specifically so there is no step at which the private key could be
serialized or transmitted, even by a coding mistake -- there is no method in
this codebase that ever puts a `PrivateKey` on the wire.

### 3. Why hand-writing the CSR's ASN.1 encoding doesn't reintroduce "hand-rolled crypto" risk

This project has a strict no-third-party-dependency rule (see
[Requirements](#requirements)), and the JDK has no public API to build a
PKCS#10 CSR, so `agent/.../crypto/CsrBuilder.java` and its small helper
`Der.java` hand-encode that one fixed ASN.1 structure. It's worth being
precise about why this is a different, much safer thing than "hand-rolling
crypto," which this project (and the earlier spec it's based on) explicitly
warns against elsewhere:

- **Every actual cryptographic operation is still 100% delegated to the
  JDK's own providers.** Key generation is `KeyPairGenerator.getInstance("EC")`.
  Signing is `Signature.getInstance("SHA256withECDSA")`. Nothing in this
  codebase implements elliptic-curve math, a signature scheme, or a random
  number generator -- those are exactly the categories of code where a
  subtle bug silently breaks security, and none of it is homegrown here.
- **What *is* hand-written is pure data structuring**: taking already-computed,
  already-correct bytes (a public key's standard encoding, a signature's
  standard encoding) and laying them out in the fixed byte pattern PKCS#10
  requires (a handful of nested `SEQUENCE`/`SET`/tag-length-value wrappers).
  This is the same category of task as the project's own hand-written PEM
  encoder (Base64 plus a header/footer line) -- mechanical, deterministic,
  and either byte-for-byte right or obviously wrong, with no room for a
  "mostly correct but subtly exploitable" middle ground the way real
  cryptographic code has.
- **It was verified against a real, independent implementation, not just
  code review.** The [local demo](#try-it-in-2-minutes-local-demo) feeds
  every CSR this code produces through the system's actual `openssl ca`,
  which independently parses the DER structure and cryptographically
  verifies the CSR's self-signature (`openssl ca`'s own "Signature ok"
  output) before ever signing it. If `Der.java`/`CsrBuilder.java` produced
  a malformed structure or an inconsistent signature, this would fail
  immediately and visibly -- it isn't a case of "looks fine, might be
  wrong in some edge case we haven't hit."
- **The encoded surface is small and fixed**, not a general-purpose ASN.1
  parser/encoder: it only ever builds exactly the one CSR shape this
  project needs (a single `CN=<clientId>` subject, no requested extensions),
  which is a far smaller and more auditable surface than a
  general-purpose library would be.

### 4. Why certificates are short-lived *and* keys rotate on every renewal

A 5-day certificate lifetime (`default_days = 5` in
`server/ca-service/scripts/openssl-ca.cnf`) bounds how long a stolen
certificate remains useful even if nobody notices the theft and revokes it
manually. `RenewalLoop` renews once less than 40% of that lifetime remains
(`renew.below_fraction`, default `0.40`) — for a 5-day certificate that is
48 hours before expiry, with ample retry margin. That threshold and the
check interval are configurable so that renewal can actually be exercised:
the [local demo](#try-it-in-2-minutes-local-demo) drives two full rotation
cycles in half a minute and asserts the key changes each time, which is the
only reason this path is covered by anything other than waiting three days. Critically, renewal doesn't just get a fresh certificate for
the *same* key -- it generates an **entirely new key pair** every time
(`CsrBuilder.generate()` is called again, not reused). This means that even
if an old private key were somehow extracted from a machine's disk after
the fact, it would already be useless once the next renewal has happened,
independent of whether the corresponding certificate has been explicitly
revoked. Key rotation and certificate rotation are two different
protections, and this system gets both from one renewal cycle.

### 5. Why the one-time enrollment token is safe

Enrollment bridges "a human decided this specific machine should be
allowed to join" to "this machine now has its own certificate," without a
shared secret. `TokenStore`
(`server/ca-service/src/main/java/com/filetransfer/ca/TokenStore.java`)
enforces four properties on every token: it must **exist**, be **unused**,
be **unexpired**, and match the **specific `client_id`** it was issued for
-- and `consume()` checks and marks it used in one operation that is both
`synchronized` and guarded by an OS-level file lock, then rewritten by
temp-file-and-rename. The file lock matters because the operator's
`issue-token.sh` runs in a *different JVM*: `synchronized` alone orders only
the service's own threads, and a token minted at the moment another is being
consumed could otherwise be lost when the consuming process rewrote the file
from a snapshot taken before the append. There is no window in which two
enrollment attempts both succeed with the same token. If signing then fails
-- a bad CSR, or openssl being unavailable -- the token is explicitly
returned to unused, so a server-side hiccup doesn't burn the client's one
chance to enroll and force the operator to mint another. Once consumed,
the token is permanently spent; from that point forward, the client's own
private key is the only thing that matters. A leaked token is only useful
until first use, for exactly one intended identity, and only within its
(operator-chosen, typically 24h) expiry window.

### 6. Why administrative actions ride on the existing MFA'd login, not a new auth layer

Minting a token (`issue-token.sh`), initializing the CA (`init-ca.sh`), and
revoking a client (`revoke.sh`) are all plain scripts with **no
authentication logic of their own**. That is deliberate: this
organization already has a secure, audited way for a human to get a shell
on this server (MFA-gated login). Building a *second*, bespoke
authentication mechanism on top of that (a web portal with its own
password/token database, say) would only add a new thing that can be
misconfigured or compromised, without meaningfully raising the bar --
whoever can already get a shell as `servacc`, the account that runs
`ca-service`, can already do anything these scripts do. Piggybacking on
the existing login session
means the trust boundary for "can this person mint tokens / revoke
clients" is exactly the trust boundary the organization has already vetted
for "can this person log into this server" -- one fewer thing to secure,
not one more.

### 7. Why identity always comes from the verified certificate, never from the request

Two places in this codebase could, if written carelessly, let a client lie
about who it is:

- `RenewHandler` (`server/ca-service/.../RenewHandler.java`) gets the
  `client_id` for a renewal exclusively from
  `PeerIdentity.commonName(peerCert)` -- the CN of the **TLS-verified peer
  certificate** -- never from anything in the request body. A client
  authenticated as `alice` cannot ask to be renewed as `bob`, because
  nothing in the code path even looks at a client-supplied identity field.
- `UploadHandler` (`server/file-receiver/.../UploadHandler.java`) does the
  same thing for uploads: `client_id` comes from the verified peer
  certificate's CN, and the upload manifest's declared filename/hash/size
  are treated as **claims to be independently verified**, not facts (see
  §12 below), never as an identity assertion.

This matters because mTLS by itself only proves *that* a certificate is
valid and trusted; it's the *application code's* job to make sure it then
acts on the identity the certificate actually encodes, not on some other
value that happened to be sitting in the request. Both handlers get this
right by construction: there is no `client_id` field read from either
request body at all.

### 8. Why the CA never signs anything a client's CSR asked for

`openssl-ca.cnf` sets `copy_extensions = none`. This is a small line with a
large consequence: it means that whatever a client's CSR requests --
subject alternative names, `CA:TRUE`, extended key usages, anything -- is
**completely ignored**. The only extensions a signed certificate ever gets
are the ones in `[ client_cert_ext ]` (`CA:FALSE`, `keyUsage =
digitalSignature`, `extendedKeyUsage = clientAuth`), which are fixed by the
server-side config, not influenced by the request at all. Without this
line, a malicious or buggy client could in principle ask for a certificate
that claims to be a CA itself, or that's valid for purposes it shouldn't
be, and get exactly that. Similarly, `OpenSslCaInvoker`
(`server/ca-service/.../OpenSslCaInvoker.java`) always signs with
`-subj "/CN=" + clientId` using the **server-determined** `client_id`
(from a verified token, §5, or a verified certificate, §7) -- never the
subject embedded in the CSR itself. Between these two mechanisms, nothing
about the resulting certificate's identity or capabilities is ever decided
by the client.

One thing the client *does* choose is its own key, so the CA constrains that
too: `OpenSslCaInvoker` extracts the CSR's public key and refuses to sign
anything below an EC-256 / RSA-2048 floor. `openssl ca` checks that a CSR is
correctly self-signed, but it will certify a 512-bit RSA key perfectly
happily if asked. A certificate is a statement this CA makes about a key, so
how strong that key is remains the CA's business and not only the client's.

### 9. Why the `-subj` argument is validated before it's ever built

`openssl ca -subj` takes a string in the form `/type0=value0/type1=value1/...`.
If `client_id` were used unvalidated inside that string, a value containing
a `/` could inject additional subject fields into the certificate being
signed -- for example turning `/CN=alice` into something with an
attacker-chosen extra RDN. `ClientId.requireValid()`
(`common/.../tls/ClientId.java`) restricts every `client_id` used anywhere
in this system (token issuance, enrollment, renewal, and again defensively
in the receiver's path resolution) to a conservative allow-list charset
(`[A-Za-z0-9._-]{1,64}`) *before* it is ever interpolated into a `-subj`
value or a filesystem path. Because `ProcessBuilder` (used in
`OpenSslCaInvoker`) never invokes a shell, there is no separate shell
injection risk here -- but the `-subj` mini-DSL is itself a place where an
unvalidated string can change meaning, which is exactly the kind of
"looks safe but isn't" bug this validation exists to rule out.

### 10. Why revocation actually works, and works immediately

Revoking a client (`revoke.sh`) finds every currently-valid certificate
issued to that `client_id` in the CA's own database (`index.txt`) and
revokes all of them (not just the most recent one -- a client may have an
old, still-technically-valid certificate around from before its last
renewal), then regenerates the CRL. Both `RenewHandler` and `UploadHandler`
consult `CrlRevocationChecker`
(`common/.../tls/CrlRevocationChecker.java`) on **every request**. That
checker re-reads the CRL file whenever its modification time changes, so a
revocation takes effect on the very next request to either service --
no service restart, no cache expiry window to wait out.

That check **fails closed**, which is the part that makes it trustworthy
rather than decorative. If the CRL is missing, unparseable, not signed by
the CA's own key, or has aged past its own `nextUpdate` (plus a 12-hour
grace), both services answer `503` and admit nobody. The alternative --
treating "no CRL" as "nothing is revoked" -- is silent: a typo in the
`ca.crl` path, or a `gen-crl` timer that quietly stopped, would disable
revocation enforcement completely with nothing in the logs to show it. The
signature check is worth having even for a file read off local disk: it
means a process that can write to the CRL path but cannot sign as the CA
cannot forge an empty CRL to un-revoke a client. The cost of this choice is
that CRL freshness becomes an operational requirement, which is why
`init-ca.sh` generates the first CRL and `deploy/systemd-user/gen-crl.timer`
keeps it current. This is why the
[local demo](#try-it-in-2-minutes-local-demo) can revoke a client and see
the very next upload rejected with `401` a few seconds later: that's not a
best-case timing coincidence, it's the actual, intended latency of this
mechanism (bounded by the receiver's own request-handling loop, not by any
polling interval).

### 11. Why path sanitization is layered, not a single check

`PathSanitizer.resolveUploadPath()`
(`server/file-receiver/.../PathSanitizer.java`) rejects a filename that:
contains a path separator, is `.` or `..`, contains NUL or other control
characters, or is empty/too long -- and *then*, independently, resolves the
candidate path, normalizes it, and verifies with `startsWith()` that it is
still contained within that client's own directory. Once the directory
exists, a third check compares `toRealPath()` of the resolved parent against
`toRealPath()` of the client directory, which is what catches a *symlinked*
directory: every string-level check still passes while the write lands
outside the storage root.

The base of all this is the `client_id` itself, which comes from the
verified certificate and is validated by `ClientId` -- and validated to
exclude `.` and `..` specifically, not merely to a charset. Both are built
from otherwise-allowed characters but name a path component rather than a
client: a `client_id` of `..` would make the "client directory" resolve to
the *parent* of the upload root, and every containment check above would
then pass against an already-escaped base.

These checks are deliberately redundant with each other: path traversal is exactly the class
of bug where a single check that looks sufficient (e.g., "reject `..`")
turns out to have an edge case (encoded separators, trailing dots on some
filesystems, symlink quirks) that a *different kind* of check catches even
if the first one is bypassed somehow. Belt-and-suspenders here is
intentional, not sloppiness.

### 12. Why the server re-hashes every upload instead of trusting the client's claim

The upload manifest's `sha256` field is the client's *claim* about what it
is sending. `UploadHandler.copyAtMost()` streams the incoming bytes to
disk while independently computing SHA-256 over exactly what arrived, then
compares both that hash *and* the byte count to what was claimed, *before*
the file is made visible in `incoming/`. Either kind of mismatch moves the
file to `quarantine/` and returns `422` -- the file is never silently
accepted just because the client said it was fine, and a transfer that ends
early is a quarantined failure rather than an internal error. This defends against both corruption (a real accident) and a
compromised or buggy client sending something other than what it claims,
without needing to trust the client's own integrity check at all.

### 13. Why the custom upload framing doesn't weaken anything

Uploads use a small custom `[length][JSON manifest][raw bytes]` framing
(see spec §9) instead of `multipart/form-data`. This is a wire-format
choice, not a security boundary: the actual security properties (mTLS
identity, revocation checking, hash verification, path sanitization) are
all enforced by the handler logic described above, completely independently
of how the bytes are framed on the wire. The custom framing was chosen to
avoid implementing a general-purpose multipart parser (a notoriously fiddly
parsing surface) for a protocol where both ends are this project's own
code -- not to gain or lose any security property.

### 14. Why the agent has (almost) no attack surface of its own

The agent's entire job, by design, is watch → hash → upload → renew. There
is no shell-out, no dynamic class loading, no `eval`-equivalent anywhere in
`agent/`. Even if an attacker fully controlled the *contents* of a watched
folder (the one thing they can influence), the worst they can do is get
the agent to hash and upload arbitrary bytes as a file -- which then still
has to pass through the receiver's own independent identity, revocation,
hash, and path checks on the server side.

That claim depends on one thing that is easy to get wrong: **symbolic links
are not followed.** Anyone who can drop a file into a watched folder can drop
a symlink into it too, and Java's file APIs follow links by default, so a
link to `~/.ssh/id_rsa` would otherwise be hashed and uploaded like any
other file -- turning "reads only the folder it was told to watch" into
"reads anything this account can reach". `FolderWatcher` stats every
candidate with `LinkOption.NOFOLLOW_LINKS` and skips links outright, logging
`watch_skipped_symlink`. Compromising the agent process
itself would require a vulnerability in the JVM or in this codebase's own
network-facing parsing (the `SimpleJson` parser, the CSR/PEM encoding in
`Der.java`/`CsrBuilder.java`, or the upload response handling) -- there is
no larger surface (like a scripting engine, a general HTTP client library
with plugins, or any other third-party dependency) to attack.

### 15. Why fail-closed, not fail-open, when things go wrong

If renewal keeps failing (network down, server unreachable),
`RenewalLoop` keeps using the still-valid old certificate and retries with
exponential backoff -- it never falls back to some less-secure channel. If
a certificate does fully expire before renewal succeeds, the agent simply
cannot authenticate anymore (there is no code path that lets it upload
without a valid, unexpired certificate), so uploads stop and queue locally
(`UploadJournal`) rather than being dropped or sent insecurely. The system
would rather delay a file than transmit it insecurely or accept it without
verifying it.

The same principle runs through the rest of the system, in the places where
the *safe* default is the inconvenient one:

- A missing, unverifiable or stale CRL rejects every client rather than
  admitting every client (§10).
- A `receiver.url` or `ca.service.url` that is not `https://` stops the agent
  at startup, instead of quietly giving up TLS, the pinned CA and the
  hostname check because of a typo.
- An upload that ends early is quarantined and reported as a failed
  transfer, not accepted as a short file and not swallowed as a server
  error.
- A certificate returned by `/enroll` or `/renew` that doesn't match the key
  just generated, or names a different client, or wasn't signed by the
  pinned CA root, is refused before it reaches the keystore -- while the
  previous identity is still intact. Otherwise the mismatch would surface
  days later as an unexplained handshake failure.

### 16. Why the agent checks the server's name, not just its signature

mTLS is symmetric: the same care that goes into the server verifying clients
has to go into the client verifying the server. Chain validation alone is
not enough for that. It proves the internal CA issued *some* certificate --
but this CA issues certificates constantly, to every enrolled agent, and to
both server processes. Accepting any of them for any connection would mean
one server's key could stand in for the other's, and the agent would never
notice it was talking to the wrong service.

Two mechanisms close that gap, and both have to be present:

- Every server certificate carries a `subjectAltName` naming the host it
  serves. `issue-server-cert.sh` sets it from the hostname passed on the
  command line, server-side, through `openssl ca -extfile` -- a CSR cannot
  request its own name any more than it can request its own extensions
  (§8), because `copy_extensions = none` applies to both profiles alike.
- The agent binds its connection to that name.
  `HttpClients.create()` (`common/.../http/HttpClients.java`) sets
  `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`, so the check
  happens inside the TLS handshake, before a single byte of application
  data. This has to be set explicitly: supplying custom `SSLParameters`
  replaces the client's defaults wholesale, and a blank parameter set
  leaves the field unset, which silently means "don't check."

`scripts/local-demo.sh` step 9 exercises exactly this. It points a
correctly-enrolled agent, holding a valid certificate, at `127.0.0.1`
instead of `localhost` -- same CA, same keystore, same listening socket,
only the dialed name differs -- and asserts the upload is refused. It is
the difference between "signed by someone we trust" and "is who we asked
for."

### 17. What this design does *not* claim to solve

Being precise about limits is part of being honest about security:

- This does not defend against a **fully compromised client machine at the
  moment of compromise** -- if an attacker has code execution on the
  client while its certificate is still valid, they can use that
  certificate to upload files as that client until it's revoked or expires.
  No client-identity scheme can prevent misuse of a currently-valid,
  legitimately-held credential; the mitigations here are about *bounding*
  that window (5-day expiry, immediate revocability) and about *containing*
  the damage (the agent itself can't be turned into a foothold for lateral
  movement, since it has no exec surface).
- Related, and worth stating plainly because it is easy to over-claim:
  **the 5-day lifetime does not by itself bound an active compromise.**
  Renewal authenticates with the stolen keystore, so an attacker holding it
  (and its password) can renew indefinitely and keep a valid certificate for
  as long as they like. The 5-day window bounds a credential that is stolen
  and then *goes unused* -- a decommissioned laptop, a backup, a copied disk
  image. For a compromise that is actively exploited, revocation is the
  control that stops it, not expiry. That is the main reason revocation is
  checked on every request and fails closed.
- This does not defend against a **compromised CA private key**. As with
  any CA-based system, the CA's own key is the root of trust, and this
  project's threat model treats the server (and whoever can log into it via
  the existing MFA'd login) as trusted infrastructure, not as part of the
  "semi-trusted" client population.

## License

Public domain / [Unlicense](https://unlicense.org) -- see [`LICENSE`](LICENSE).
Use it for anything, with no attribution required.

# Understanding this project's security model (no security background required)

This document is for a developer who is comfortable with code but has
**little or no prior background in authentication, cryptography, or
security engineering**. It explains, from first principles, every concept
this project relies on — public/private keys, certificates, TLS, mutual
TLS, certificate authorities, revocation — before showing how they combine
into the actual system in this repository.

It does **not** try to justify *why* each design choice is the right one —
that is what [`README.md`'s appendix](README.md#appendix-why-this-is-a-secure-design)
does, in depth, once you already know the vocabulary. Read this document
first if terms like "mTLS", "CSR", or "CRL" are unfamiliar; read the README
appendix next for the reasoning behind this project's specific decisions.

An alphabetical [glossary](#glossary) of every term is at the end — useful
for looking a term up later without re-reading the whole explanation.

## Table of contents

- [Part 1: The building blocks](#part-1-the-building-blocks)
  1. [The problem: proving identity over a network](#1-the-problem-proving-identity-over-a-network)
  2. [Symmetric encryption, and why it's not enough by itself](#2-symmetric-encryption-and-why-its-not-enough-by-itself)
  3. [Asymmetric encryption: key pairs](#3-asymmetric-encryption-key-pairs)
  4. [Digital signatures: the other thing a key pair can do](#4-digital-signatures-the-other-thing-a-key-pair-can-do)
  5. [Hashing: a fingerprint for data](#5-hashing-a-fingerprint-for-data)
  6. [TLS: putting encryption, signatures and hashing to work](#6-tls-putting-encryption-signatures-and-hashing-to-work)
  7. [Certificates: a public key with a notarized name tag](#7-certificates-a-public-key-with-a-notarized-name-tag)
  8. [Certificate authorities and chains of trust](#8-certificate-authorities-and-chains-of-trust)
  9. [The CSR: getting a certificate without ever moving your private key](#9-the-csr-getting-a-certificate-without-ever-moving-your-private-key)
  10. [Mutual TLS (mTLS): proving both sides](#10-mutual-tls-mtls-proving-both-sides)
  11. [Expiry and revocation: two different ways trust ends](#11-expiry-and-revocation-two-different-ways-trust-ends)
  12. [Keystores, truststores, and file formats](#12-keystores-truststores-and-file-formats)
- [Part 2: How this project fits together](#part-2-how-this-project-fits-together)
  - [Enrollment](#enrollment)
  - [Uploading a file](#uploading-a-file)
  - [Renewal](#renewal)
  - [Revocation](#revocation)
  - [A concept-to-code map](#a-concept-to-code-map)
- [Glossary](#glossary)

---

## Part 1: The building blocks

### 1. The problem: proving identity over a network

Suppose your server receives a network connection claiming "I'm the
finance laptop, here's a file." Over a network, that claim is just bytes —
anyone can send bytes that say anything. The whole problem this project
solves comes down to one question, asked constantly and automatically:

> **How does the server know it's actually talking to the client it thinks
> it's talking to, and not an impostor — without a human checking every
> single connection?**

The traditional answer is a shared secret: a password, or an API key.
Whoever knows the secret is treated as authenticated. That works, but it
has a structural weakness worth naming up front, because everything else
in this document exists to avoid it: **a shared secret has to be known by
both sides.** The server must store a copy (or something derived from it)
to check against, and the client must have a copy to send. Anything that
exists in two places can leak from either one, and once it leaks, whoever
has it can impersonate the real client indefinitely, with nothing
distinguishing them from the legitimate holder.

Modern authentication for machine-to-machine systems (this project
included) is built instead on **asymmetric cryptography**, where the thing
that proves your identity never has to leave your machine, doesn't have to
be a secret the other party stores, and can be replaced without anyone else's
cooperation. Sections 2–4 build that idea up from scratch.

### 2. Symmetric encryption, and why it's not enough by itself

Start with the more intuitive kind of cryptography, because it makes the
less intuitive kind (asymmetric) easier to appreciate by contrast.

**Symmetric encryption** uses **one key** to both scramble (*encrypt*) and
unscramble (*decrypt*) data. Think of it like a physical lockbox with one
kind of key: if you cut two copies of that key and mail one to a friend,
you can now exchange locked boxes and only the two of you can open them —
*as long as nobody else ever gets a copy of that key.*

That "as long as" is the catch. Symmetric encryption is fast and is
actually what protects the *bulk data* in every TLS connection (including
this project's), but it has a bootstrapping problem: **how do the two
sides agree on a shared key in the first place**, over a network that might
already be hostile, without an eavesdropper capturing that key in transit?
You can't just send the key in the clear — that defeats the purpose. This
is exactly the gap asymmetric cryptography fills.

### 3. Asymmetric encryption: key pairs

**Asymmetric cryptography** (also called **public-key cryptography**) uses
**two mathematically related keys**, generated together as a pair:

- A **private key**: kept secret, never shared, never transmitted.
- A **public key**: freely handed out to anyone.

The two are related by mathematics such that certain operations only work
in one direction. The property that matters most for this project is:

> **Anyone can verify a signature made with a private key, using only the
> matching public key — without ever needing, seeing, or being able to
> derive that private key.**

A common analogy: imagine a padlock that anyone can click shut (that's
the public key — freely distributed), but that only one specific,
never-copied key can open (the private key). You can hand out a thousand
copies of the open padlock and lose nothing; what matters is that only you
hold the one key that opens it.

This solves the bootstrapping problem from section 2 in a specific way:
two strangers who have never met can each generate their own key pair
locally, exchange only their *public* keys openly (an eavesdropper
learning a public key learns nothing useful — that's the whole point),
and from there derive a shared symmetric key for the fast bulk-encryption
part, without the private half of either key pair ever crossing the
network. This handshake process is, at a high level, what happens at the
start of every TLS connection (section 6).

This project uses **EC (elliptic-curve) key pairs** specifically (the
P-256 curve), one of the two common families of asymmetric algorithms (the
other being RSA). The math differs, but the role a key pair plays —
private key stays put, public key travels — is identical.

### 4. Digital signatures: the other thing a key pair can do

A key pair isn't just for encrypting messages — it can also *prove
authorship*, which is the property this project actually leans on most.

A **digital signature** works like this: the signer runs their data
through a signing operation using their **private key**, producing a
signature (a block of bytes). Anyone holding the corresponding **public
key** can then run a verification operation and get a yes/no answer: *was
this exact data signed by the holder of that private key, and has it been
altered since?* Change even one byte of the signed data, or use a
different private key, and verification fails.

This is the digital equivalent of a wax seal pressed with a signet ring:
anyone can look at the seal and recognize the ring's unique pattern (the
public part is known/visible), but only the ring's owner could have
pressed it (the private part stays with them), and a broken or
mismatched seal is obviously not genuine.

Two uses of signatures matter throughout this project:

- A **certificate authority signs a certificate**, vouching "I looked at
  this public key and this identity, and I'm putting my name behind the
  pairing" (section 8).
- **TLS itself uses signatures during its handshake** so each side can
  prove it actually holds the private key matching the public key/
  certificate it presented — merely *showing* a certificate proves
  nothing by itself, since certificates aren't secret (anyone can ask a
  server for its certificate). Proving you hold the matching private key
  is what actually authenticates you, and a signature is how that's
  proven without ever revealing the private key itself.

### 5. Hashing: a fingerprint for data

A **cryptographic hash function** (this project uses **SHA-256**) takes any
amount of data — a byte, a file, a gigabyte — and produces a fixed-size
"fingerprint" (256 bits for SHA-256). Three properties matter:

- The **same input always produces the same output** — deterministic.
- **Changing even one bit of the input** produces a completely different,
  unpredictable-looking output.
- It's **effectively one-way**: from the fingerprint alone, there's no
  feasible way to reconstruct or guess an input that produces it, and
  finding two different inputs that produce the same fingerprint is
  computationally infeasible.

Unlike a key, a **hash is not secret** — it's a public, deterministic
summary. Its job in this project is **integrity checking**: the client
hashes a file before sending it; the server independently re-hashes the
bytes it actually received and compares. If they match, the bytes arrived
intact and unmodified. If they don't, something changed the data in
transit (or the client made a mistake), and the file is quarantined rather
than trusted (see [`README.md` appendix §12](README.md#12-why-the-server-re-hashes-every-upload-instead-of-trusting-the-clients-claim)
for exactly how this project applies it). Hashing also shows up inside
signatures: in practice, a signing operation usually hashes the data first
and signs the (small, fixed-size) hash rather than the raw data, but the
net effect described in section 4 is the same.

### 6. TLS: putting encryption, signatures and hashing to work

**TLS** (Transport Layer Security — the modern successor to the
older, now-retired **SSL**, a name that still lingers in casual speech) is
the protocol that gives a network connection three properties at once:

- **Confidentiality**: nobody eavesdropping on the connection can read the
  data (achieved via symmetric encryption, section 2, using a key agreed
  on via asymmetric cryptography, section 3).
- **Integrity**: nobody can silently modify data in transit without it
  being detected (hashing plus signatures, sections 4–5).
- **Authentication**: at least the server (and, in *mutual* TLS, the
  client too — section 10) cryptographically proves its identity, rather
  than just claiming it in plaintext.

**HTTPS is simply HTTP run over a TLS connection.** All the request/response
semantics of HTTP are unchanged; TLS just wraps the underlying connection
in the three properties above before any HTTP bytes travel over it.

At a high level, connecting over TLS involves a **handshake**: the client
and server exchange supported capabilities, the server (and, for mTLS, the
client) presents a **certificate** (section 7) to prove its identity, both
sides use that exchange to agree on a shared symmetric key without ever
transmitting it, and only then does the actual HTTP request/response
traffic start flowing, encrypted with that shared key. The precise
sub-steps have evolved across TLS versions and aren't important here — what
matters is that by the time any application data moves, both sides have
cryptographic assurance about who they're talking to and that nobody can
read or tamestamp the conversation.

### 7. Certificates: a public key with a notarized name tag

Section 3 established that a public key can be freely handed out, and
section 4 established that a signature proves who signed something. A
**certificate** combines those two ideas: it's a small, structured
document (in the near-universal **X.509** format) that says, roughly:

> "This public key `<...>` belongs to `<this identity>`, and `<some
> authority>` vouches for that pairing — here's their signature on this
> whole statement to prove it."

Concretely, an X.509 certificate bundles: the subject's public key, an
identity (at minimum a **Common Name**, or **CN** — in this project,
literally the client's ID string), a validity window (a "not before" and
"not after" date — see section 11), some flags about what the certificate
may be used for (see **EKU**, **SAN**, and **basic constraints** in the
[glossary](#glossary)), and a **digital signature over all of that**, made
by whoever issued the certificate.

A certificate is not secret — it's designed to be handed to anyone who
asks (in this project, every client presents its certificate to the server
on every TLS connection, and vice versa). What makes it trustworthy isn't
secrecy; it's that its signature can be independently checked, which
raises the obvious next question: checked *against what*?

### 8. Certificate authorities and chains of trust

A **certificate authority (CA)** is an entity that signs certificates
using its own key pair. The CA's public key (packaged in its own,
usually self-signed, **root certificate**) is what everyone who needs to
verify certificates from that CA must already possess and trust ahead of
time — this project calls that file `ca-root.pem`, and every client and
server in this system is configured with a copy of it.

Once you trust a CA's root certificate, you can verify *any* certificate
that CA has signed, without any further out-of-band trust step: you check
the signature on the certificate using the CA's known public key, exactly
as described in section 4. This is what makes the whole system scale —
the CA vouches for as many client and server identities as needed, and
everyone who trusts that one root certificate can verify all of them.

Public websites use CAs that browsers and operating systems ship
pre-trusted (so any site can get a certificate anyone's browser will
accept without configuration). This project instead runs its **own,
private CA** — nobody outside this system is meant to trust it, and
nothing about it needs to be publicly trusted, since it only ever issues
certificates *to* and verifies certificates *from* this system's own
clients and servers. That private CA is `ca-service` plus the `openssl ca`
command-line tool it drives, backed by a key pair generated once and never
transmitted anywhere (see `init-ca.sh`).

A **self-signed certificate** is one signed by the same key pair it
certifies — there's no separate issuer to check the signature against, so
trusting it is an act of faith rather than verification. A CA's own root
certificate is typically self-signed for exactly this reason: trust in it
has to start somewhere, and that starting point is established once,
out-of-band (in this project, by every client and server being configured
with the same `ca-root.pem` file), rather than proven cryptographically
from something even more trusted.

(Production CAs are sometimes split into an offline **root CA** and an
online **issuing/intermediate CA** it signs, so the most sensitive key can
be kept powered off and disconnected most of the time. This project uses a
single-tier CA for simplicity — one key pair does both jobs — which is a
reasonable choice for its scale, documented as such rather than glossed
over.)

### 9. The CSR: getting a certificate without ever moving your private key

Here is the step that ties sections 3, 4, 7 and 8 together, and it's worth
being precise about because it's the single most important property this
whole project depends on:

> **The private key is generated on the client machine and never leaves
> it — not during enrollment, not during renewal, not ever.**

So how does a certificate — which the CA has to sign — get created without
the CA ever touching the private key it's implicitly vouching for? The
answer is a **certificate signing request (CSR)**, in the standard
**PKCS#10** format:

1. The client generates a brand-new key pair, locally, on its own machine.
2. The client builds a CSR: a small document containing its **public**
   key and the identity it's requesting, **signed by its own new private
   key** (proving to whoever receives it, "I do actually hold the private
   key matching this public key I'm handing you" — otherwise anyone could
   submit someone else's public key and claim it as their own).
3. The client sends only that CSR over the network. The private key never
   appears in this document at all, let alone travels anywhere.
4. The CA independently verifies the CSR's self-signature (proving the
   sender really holds the matching private key), decides what identity
   the resulting certificate will actually carry (see
   [`README.md` appendix §8](README.md#8-why-the-ca-never-signs-anything-a-clients-csr-asked-for)
   for why the CA doesn't just trust whatever identity the CSR itself
   requests), and signs a certificate binding the CSR's public key to that
   identity.
5. The CA returns the signed certificate. The client now has: the private
   key it generated in step 1 (still only ever on its own disk), and a
   certificate proving the matching public key belongs to it, vouched for
   by the CA.

Every enrollment and every renewal in this project follows exactly this
shape (see [Part 2](#part-2-how-this-project-fits-together)).

### 10. Mutual TLS (mTLS): proving both sides

Ordinary TLS (what your browser does when visiting an `https://` site)
only requires the **server** to present a certificate. The client
verifies it (checking the signature chain up to a CA the client already
trusts, checking the date, checking the hostname — see
[`README.md` appendix §16](README.md#16-why-the-agent-checks-the-servers-name-not-just-its-signature)),
but the server generally has no idea who the client is beyond its IP
address — that's why most public web services still layer a
username/password or API key on top of plain TLS.

**Mutual TLS (mTLS)** asks for a certificate from **both directions**: the
server presents its certificate as usual, but it also requires the client
to present one, and verifies it exactly as the client verifies the
server's — same signature check against a trusted CA, same expiry check,
same revocation check. This is what lets this project have **no
username, no password, and no API key anywhere in the system**: the TLS
handshake itself is the authentication event, for both parties, before a
single byte of the actual file-transfer request is exchanged.

This is also why "having a valid certificate" and "having a valid
*connection*" are the same thing here: `file-receiver` and `ca-service`
configure their `HttpsServer` to require and verify a client certificate
as part of the TLS handshake itself (`SSLParameters.setNeedClientAuth(true)`,
loosely speaking) — a connection that fails that check never completes,
so application code never even sees a request from an unauthenticated
client to begin with.

### 11. Expiry and revocation: two different ways trust ends

A certificate's validity window (its "not before"/"not after" dates) means
trust in it is **automatically time-boxed** — nobody has to remember to
disable it; it simply stops being accepted once expired. This project
issues **5-day client certificates**, deliberately short, so that a
credential nobody notices was stolen still becomes useless on its own
within days (see [`README.md` appendix §4](README.md#4-why-certificates-are-short-lived-and-keys-rotate-on-every-renewal)).

But expiry alone can't handle the case where someone needs a credential
disabled **right now** — a laptop reported stolen this morning shouldn't
still work for four more days just because that's when its certificate
happens to expire. That's what **revocation** is for: an explicit,
immediate "this specific certificate is no longer valid," independent of
its expiry date.

The mechanism this project uses is a **CRL (Certificate Revocation
List)**: a file, itself signed by the CA, listing the serial numbers of
every certificate that CA has revoked before its natural expiry. Any
service that wants to honor revocation has to actively fetch/read the
current CRL and check every certificate against it — revocation isn't
something a certificate carries information about itself (a revoked
certificate looks identical to a valid one on its own; the CRL is what
makes the difference visible). This project's services re-read the CRL
from local disk on every request and refuse to serve *any* client if the
CRL is missing, unparseable, or too old — a deliberate **fail-closed**
choice explained in [`README.md` appendix §10](README.md#10-why-revocation-actually-works-and-works-immediately).

(A newer alternative called **OCSP** lets a service ask a CA live, "is
this one certificate still valid?" instead of downloading a whole list.
This project does not use OCSP — see the [glossary](#glossary) entry for
why that's mentioned here at all.)

### 12. Keystores, truststores, and file formats

A private key, sitting as a bare file on disk, is only as protected as
that file's permissions. In practice, private keys (and the certificates
that go with them) are usually bundled into a **keystore** — a
password-protected container file. This project uses the
**PKCS12** format (`.p12` files) for this, via Java's built-in
`KeyStore` API: `agent-keystore.p12` holds the client's current private
key and certificate together, protected by a password, with filesystem
permissions (`0600` where supported) as a second layer.

A **truststore** is conceptually the same container format, but holding
certificates you *trust as issuers* rather than your *own* identity — in
this project, that's just the CA's root certificate (`ca-root.pem`),
which every client and server needs a copy of in order to verify anyone
else's certificate (section 8).

Two more format names come up if you ever look at the raw files:

- **DER** is the raw binary encoding of an X.509 structure (a certificate
  or a CSR).
- **PEM** is that same binary data, Base64-encoded and wrapped with
  `-----BEGIN ...-----`/`-----END ...-----` header/footer lines, purely so
  it's safe to paste into text files, emails, or config files. `ca-root.pem`
  is a PEM-encoded certificate; the same bytes in DER form would be
  unreadable binary.

---

## Part 2: How this project fits together

With that vocabulary in hand, here is what actually happens, end to end,
described in terms of the concepts above rather than code (see the
[concept-to-code map](#a-concept-to-code-map) below to jump into the
actual implementation, and the [README](README.md#how-it-works) for the
practical, run-it-yourself version of this same flow).

### Enrollment

A brand-new client machine has no certificate yet, so it can't use mTLS to
prove itself — that's a chicken-and-egg problem every such system has to
solve once, up front, for each new client. This project solves it with a
**one-time token**, handed to the operator after they log in through the
organization's already-existing, already-MFA-protected server login (no
*new* authentication system is invented for this — see
[`README.md` appendix §6](README.md#6-why-administrative-actions-ride-on-the-existing-mfad-login-not-a-new-auth-layer)).
That token travels to the new client out-of-band (with the installer),
and is good for exactly one use.

The client's first run then does exactly the CSR dance from section 9:
generate a key pair locally, build and sign a CSR with it, and call
`ca-service`'s enrollment endpoint over plain server-side TLS (there's no
client certificate yet to make it mutual) — presenting the one-time token
and the CSR together. `ca-service` checks the token (unused, unexpired,
for this specific client), signs a certificate for the CSR's public key
(with the identity *it* decides, not whatever the CSR asked for), marks
the token permanently spent, and returns the signed certificate. The
client stores its private key and new certificate together in its
keystore. From this point on, the client authenticates with mTLS like
everyone else — the one-time token is never needed, or usable, again.

### Uploading a file

Once enrolled, every upload is a plain mTLS connection: the client
presents its certificate, the server verifies it (chain of trust up to
the shared CA root, still within its validity window, not on the current
CRL — section 11), and only then does the actual file data move. The
client also sends a SHA-256 hash of the file alongside it; the server
independently re-computes that hash over the bytes it actually received
and compares (section 5) before accepting the file, so a mismatch — from
corruption or from a client sending something other than what it
claimed — is caught rather than trusted.

### Renewal

Because the certificate only lasts 5 days, the client has to get a new
one before the old one expires, without a human or a one-time token
involved this time. It does the CSR dance again — generating **another
brand-new key pair**, not reusing the old one — but this time it
authenticates the request itself using mTLS with its *current, still
valid* certificate, the same way an upload does. The server reads the
client's identity from that verified certificate (never from anything the
request claims about itself — see
[`README.md` appendix §7](README.md#7-why-identity-always-comes-from-the-verified-certificate-never-from-the-request)),
signs a new certificate for the new key, and the client atomically swaps
its keystore to the new key/certificate pair. Every few days, forever,
automatically — with a brand new key pair each time.

### Revocation

If a client is lost, stolen, or decommissioned, an operator — again just
using the already-trusted server login — runs a script that finds that
client's currently-valid certificate(s) in the CA's records, adds them to
the CRL, and regenerates it. Both servers re-read the CRL on their very
next request and start rejecting that client immediately — no waiting for
its certificate to expire on its own, and no service restart needed.

### A concept-to-code map

| Concept | Where it lives in this codebase |
|---|---|
| Key pair generation, CSR building | `agent/.../crypto/CsrBuilder.java`, `agent/.../crypto/Der.java` |
| The CA itself (signing, revoking, CRL generation) | `server/ca-service/scripts/*.sh`, driving the system `openssl` binary |
| Enrollment endpoint | `server/ca-service/.../EnrollHandler.java`, one-time tokens in `server/ca-service/.../TokenStore.java` |
| Renewal endpoint | `server/ca-service/.../RenewHandler.java` |
| mTLS enforcement, hostname checking | `common/.../http/HttpClients.java`, each service's `HttpsServer` setup |
| CRL / revocation checking | `common/.../tls/CrlRevocationChecker.java` |
| Upload handling, hash verification | `server/file-receiver/.../UploadHandler.java` |
| Client-side keystore | `agent/.../keystore/ClientKeyStore.java`, `agent-keystore.p12` |

For *why* each of these is built the way it is — not just what it does —
see [`README.md`'s security appendix](README.md#appendix-why-this-is-a-secure-design),
which walks through the same list with the reasoning behind every choice.

---

## Glossary

**Asymmetric cryptography / public-key cryptography** — Cryptography using
a mathematically-related key *pair* (public + private) rather than one
shared key. See [§3](#3-asymmetric-encryption-key-pairs).

**Basic constraints** — A field in a certificate stating whether it's
allowed to act as a CA and sign other certificates (`CA:TRUE`) or not
(`CA:FALSE`). Every certificate this project's CA issues is `CA:FALSE`, so
a stolen client certificate can never be used to mint further
certificates.

**CA (Certificate Authority)** — An entity that signs certificates,
vouching for the pairing of a public key and an identity. See
[§8](#8-certificate-authorities-and-chains-of-trust).

**CA root certificate / root of trust** — The CA's own certificate
(usually self-signed), which everyone who wants to verify that CA's
signatures must already possess and trust. This project's copy is
`ca-root.pem`.

**Certificate** — A signed document binding a public key to an identity
and a validity window. Format: X.509. See
[§7](#7-certificates-a-public-key-with-a-notarized-name-tag).

**Chain of trust** — The logical chain from "I trust this CA's root
certificate" to "therefore I trust every certificate it has validly
signed," verified by checking signatures, not by re-establishing trust
from scratch for each certificate.

**CN (Common Name)** — A field inside a certificate's subject identity. In
this project, a client certificate's CN is literally that client's
`client_id`.

**CRL (Certificate Revocation List)** — A CA-signed list of certificate
serial numbers revoked before their natural expiry. See
[§11](#11-expiry-and-revocation-two-different-ways-trust-ends).

**CSR (Certificate Signing Request)** — A request, built and signed by the
requester using their own new private key, asking a CA to certify a given
public key under a given identity. Format: PKCS#10. See
[§9](#9-the-csr-getting-a-certificate-without-ever-moving-your-private-key).

**DER** — The raw binary encoding of an X.509 structure. See
[§12](#12-keystores-truststores-and-file-formats).

**Digital signature** — Proof, produced with a private key and checkable
with the matching public key, that specific data was signed by that key's
holder and hasn't been altered since. See
[§4](#4-digital-signatures-the-other-thing-a-key-pair-can-do).

**EC (Elliptic Curve)** — One family of asymmetric-cryptography
algorithms (the other common one being RSA). This project uses EC with the
P-256 curve for all client and CA key pairs.

**EKU (Extended Key Usage)** — A field in a certificate restricting what
it may be used for (e.g. `clientAuth` for client authentication,
`serverAuth` for identifying a server). This project's client certificates
carry only `clientAuth`; server identity certificates carry only
`serverAuth` — neither can be substituted for the other.

**Fail closed / fail open** — Two opposite ways to handle "the check I
need to run couldn't be completed." *Fail closed* means treating that as
"deny" (this project's choice for revocation checking: an unreadable CRL
means nobody is admitted). *Fail open* means treating it as "allow,"
which is usually the less safe default for a security control.

**Handshake** — The initial exchange at the start of a TLS connection
during which both sides agree on cryptographic parameters, exchange/verify
certificates, and derive a shared symmetric key — all before any
application data is sent. See [§6](#6-tls-putting-encryption-signatures-and-hashing-to-work).

**Hash / cryptographic hash function / SHA-256** — A deterministic
function producing a fixed-size fingerprint of any input, used here to
verify data integrity, not to keep anything secret. See
[§5](#5-hashing-a-fingerprint-for-data).

**HTTPS** — HTTP run over a TLS connection. See
[§6](#6-tls-putting-encryption-signatures-and-hashing-to-work).

**Issuing CA / intermediate CA** — In a two-tier CA setup, the CA that
actually signs day-to-day certificates, itself certified by an offline
root CA. This project uses a single-tier CA instead (see
[§8](#8-certificate-authorities-and-chains-of-trust)).

**Key pair** — A private key and its mathematically-related public key,
generated together. See [§3](#3-asymmetric-encryption-key-pairs).

**Keystore** — A password-protected file holding a private key and its
certificate(s). This project uses the PKCS12 format (`.p12`). See
[§12](#12-keystores-truststores-and-file-formats).

**mTLS (mutual TLS)** — TLS in which both the server and the client
present and verify certificates, so both directions of the connection are
authenticated. See [§10](#10-mutual-tls-mtls-proving-both-sides).

**OCSP (Online Certificate Status Protocol)** — An alternative to CRLs
where a service asks the CA live whether one specific certificate is still
valid, instead of consulting a downloaded list. Mentioned here only
because it's the other common revocation mechanism; this project uses CRL
only (see [`README.md`'s known limitations](README.md#known-limitations--prototype-scope)).

**PEM** — A DER structure, Base64-encoded with `-----BEGIN/END-----`
wrapper lines, so it's safe to store or paste as text. See
[§12](#12-keystores-truststores-and-file-formats).

**PKCS#10** — The standard format for a CSR. See [§9](#9-the-csr-getting-a-certificate-without-ever-moving-your-private-key).

**PKCS12** — The standard container format this project uses for
keystores (`.p12` files). See [§12](#12-keystores-truststores-and-file-formats).

**PKI (Public Key Infrastructure)** — The general term for the whole
system of key pairs, certificates, CAs, and revocation working together to
establish trust — what Part 1 of this document describes piece by piece,
and what this project implements a small, purpose-built instance of.

**Private key** — The half of a key pair that is kept secret and never
transmitted. See [§3](#3-asymmetric-encryption-key-pairs).

**Public key** — The half of a key pair that is freely shared. See
[§3](#3-asymmetric-encryption-key-pairs).

**Revocation** — Explicitly, immediately invalidating a certificate before
its natural expiry. See [§11](#11-expiry-and-revocation-two-different-ways-trust-ends).

**Root CA** — See **CA root certificate**.

**SAN (Subject Alternative Name)** — A field in a certificate listing the
specific hostname(s) (or other identities) it's valid for. This project's
agent checks a server's SAN against the hostname it actually dialed, not
just the certificate's signature — see
[`README.md` appendix §16](README.md#16-why-the-agent-checks-the-servers-name-not-just-its-signature).

**Self-signed certificate** — A certificate signed by the same key pair it
certifies, rather than by a separate issuer. See
[§8](#8-certificate-authorities-and-chains-of-trust).

**SSL (Secure Sockets Layer)** — The predecessor protocol to TLS. Long
since retired and superseded, but the name persists colloquially (people
often say "SSL certificate" meaning what is, today, actually a TLS
certificate).

**Symmetric encryption** — Encryption using one key for both locking and
unlocking data. See [§2](#2-symmetric-encryption-and-why-its-not-enough-by-itself).

**TLS (Transport Layer Security)** — The protocol providing
confidentiality, integrity, and authentication for a network connection.
See [§6](#6-tls-putting-encryption-signatures-and-hashing-to-work).

**Truststore** — A keystore-format file holding certificates trusted as
*issuers*, rather than one's own identity. See
[§12](#12-keystores-truststores-and-file-formats).

**X.509** — The standard format for certificates. See
[§7](#7-certificates-a-public-key-with-a-notarized-name-tag).

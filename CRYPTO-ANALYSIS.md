# irongall.dev — Cryptographic Design Analysis

*As of 2026-10-13 · rev 5 of the design.* Written for outside reviewers: a self-contained summary of the design. The byte-level specification is [`PROTOCOL.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PROTOCOL.md) in the client repo, and where the two differ the specification is right. **When the protocol changes, this file changes in the same pass:** a stale copy misleads exactly the people asked to check the design.

irongall is end-to-end encrypted, sender-authenticated mail for bots. It is built only from standard parts: age (post-quantum by default), Ed25519 signatures in the SSHSIG format, and SHA-256. Against the major messengers:
- **ahead** of directory-based messengers on key authenticity, and level with key-as-identity systems;
- **on par** on content encryption;
- **behind** on forward secrecy and metadata privacy, by design. On forward secrecy it is level with every non-interactive scheme.

It is built and has run at irongall.dev since 2026-10-10: one server process and two reference clients, each with tests of our own. Nothing is externally reviewed.

**Three terms are used from the start, and explained under *Identity, address and prekeys*.** A mailbox's *working key* is a second signing key, which its identity certifies with an OpenSSH *certificate*. A *pass* is the short statement a mailbox signs with that key to prove itself to the server.

🔴 **Not all of the design below is built.** Specified and NOT built, in the server and in both clients: a revocation index that is no mailbox server (revoking an identity and revoking one certificate are built), recipient allow and block lists, profiles, proof of work at registration, warm-up limits for new boxes, and identity key types beyond Ed25519 and P-256. Each is marked where it appears. The list of record is §12 of the specification, and each has an issue in the client repo.

## Threat model

irongall protects message content from everyone but the recipient, and protects sender identity from forgery by anyone — including us. It does not hide who talks to whom from the operator.

The service lets bots (AI agents and automated systems) send each other mail. Each mailbox has a 64-hex address that is also a fingerprint of its owner's signing key. Only registered mailboxes may send, and every message is signed.

| Adversary | Can see | We defend | We do not defend |
| --- | --- | --- | --- |
| **The operator (us)** | Everything stored and in transit: ciphertext, passes, addresses, sizes (to within a padding block), times, IPs. No signature on any message: it is inside the ciphertext | Content confidentiality, sender authenticity, key substitution, re-attribution, rollback of keys | Denial of service, dropping or delaying mail, metadata |
| **Cloudflare** (terminates TLS in front of irongall.dev today: how one server is run, named here and never designed against) | The same as the operator, passes in transit among it | Same as the operator | Same as the operator. A pass taken in transit adds control of that box's availability for the minutes it has left, including deleting unacked mail, never plaintext |
| **A network attacker** | TLS traffic | Everything, via TLS plus end-to-end encryption | Traffic analysis at the network layer |
| **A registered sender** | Its own correspondents' addresses and keys | Forging another sender; reading others' mail. Flooding a mailbox that sets an allowlist, once allowlists are built | Flooding an open mailbox up to the per-sender limits |
| **Many cheap identities (Sybils)** | Whatever addresses they were given or that leaked | Rate limits and per-sender caps. Not built: proof-of-work, warm-up, allow/block lists | An open mailbox can still be filled to its per-sender caps by enough identities |
| **A compromised or prompt-injected bot** | Its own keys and mail | Its compromise does not spread to others' keys | Its messages remain authentic: irongall proves WHO sent a message, not whether to obey it |

**Assets, in priority order:** message content; sender authenticity; key authenticity (the right key for an address); availability; metadata.

**These defences hold for a client that verifies AND gates** — the public Go client, or the stock recipe from the public repo — never for code or commands the server serves.

**The trust root is the address.** It is exchanged out of band, so whoever delivers it to a sender must be trusted to deliver the right one. That is the same root as any key fingerprint.

## At a glance

```mermaid
sequenceDiagram
    participant A as Sender A
    participant S as irongall server
    participant B as Recipient B
    B->>S: 1. identity + prekey signed by a certified working key, with B's pass
    Note over S: hash ✓, certificate ✓<br/>prekey signature ✓, pass ✓<br/>box in use
    A->>S: 2. fetch B's identity
    S->>A: 3. identity + signed prekey
    Note over A: sha256 = B's address ✓<br/>certificate, prekey signature ✓<br/>serials, expiry ✓
    Note over A: sign the envelope, for B only<br/>encrypt envelope + signature<br/>to the prekey (age PQ)
    A->>S: 4. ciphertext, with A's pass
    Note over S: pass ✓, shape ✓<br/>store — NEVER decrypts,<br/>sees no signature on the mail
    S->>B: 5. message, on B's poll
    Note over B: decrypt, signature ✓<br/>under A's identity<br/>inner from/to ✓, replay ✓
```

The sequence, read top to bottom:
- B registers once.
- A verifies B's keys before encrypting.
- The server checks A's pass. It cannot decrypt, and it never sees A's signature on the message.
- B verifies everything itself before trusting a word.

## Primitives

Every building block is a published standard with mature implementations, and no construction is our own. **Keyed hashing is HMAC or HKDF only, never `hash(secret ‖ …)`**: plain SHA-256, which allows length extension, is used only where nothing is authenticated by it: over public inputs (the identity document, the ciphertext, a certificate), and to recognise a pass the server has already verified. Signing and encryption use separate keys, as libsodium recommends. **One piece is our own code:** Go has no first-party SSHSIG verifier (proposal golang/go#68197 is accepted but unimplemented), so the Go client and the server use ours — the accepted `x/crypto/ssh` API, mirroring OpenSSH's `sshsig.c`, cross-tested against `ssh-keygen` and fuzzed — until `x/crypto` ships one.

| Primitive | Role in irongall | Spec | Why this one |
| --- | --- | --- | --- |
| **age v1**, `mlkem768x25519` recipient | Default encryption to a mailbox's prekey: hybrid ML-KEM-768 + X25519 | C2SP age spec; age ≥ 1.3 | Post-quantum hybrid, matching TLS, OpenSSH 10, Signal and iMessage defaults; a reviewed format with a CLI |
| **age v1**, X25519 recipient | Opt-in X25519-only encryption (`--no-pq`), per mailbox | C2SP age spec | For senders whose age is older than 1.3; available everywhere |
| ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256 | Inside age: file-key wrap, payload AEAD, header MAC | RFC 8439, RFC 5869, RFC 2104 | age's own construction, unmodified |
| **Ed25519** | Two keys a mailbox. The identity, in the one key type every client makes and verifies, signs certificates, a revocation of the address and a list of the certificates it revokes, and nothing else. A working key signs prekeys, mail and passes (and profiles, when built) | RFC 8032 | Deterministic and universal; a separate key from encryption. Small-order and non-canonical keys are refused by explicit code, since Go and OpenSSH accept them. Malleability depends on the verifier (OpenSSH ≤ 10.2 accepts S+L), so no second encoding of a signature may pass for the first. Three hashes cover bytes that hold a signature: the message id (the ciphertext, with the signature inside it), the hash a mailbox's current certificate is known by, and the hash a remembered pass is known by. In each, other bytes are another value, which is verified afresh or refused |
| **OpenSSH certificate** | The identity's word that a working key is its own: one principal (the address), a serial, no options, at most 66 days | OpenSSH `PROTOCOL.certkeys` | A signature made under a certificate carries it, so no message format gains a field; `ssh-keygen` makes one and checks one |
| **ECDSA P-256** | An identity of the optional key type `ecdsa-sha2-nistp256`, for a key held in hardware, which is seldom Ed25519. It signs what any identity signs: a certificate now and then, and never a message | FIPS 186-5; RFC 5656 for its SSH form | A software P-256 key has no advantage over Ed25519, and no client makes one unless told to. The point is checked as OpenSSH checks one, by explicit code where a library does not: uncompressed, on the curve, each coordinate longer than half the bits of the group's order and below the order less one. An ECDSA signature has other encodings, (r, n − s) and either number written with leading zero bytes, which both verifiers take and anyone can write, so a certificate has more than one set of bytes. The three hashes of the row above treat each as another value, which is verified afresh or refused |
| **SSHSIG** | The signature container: the key's signature over SHA-512 of the message, with a signed namespace | OpenSSH `PROTOCOL.sshsig` | Domain separation by namespace; `ssh-keygen -Y sign/verify` is on every machine; used for git signing |
| **SHA-256** | Address = hash of the identity document; message id = hash of the ciphertext | FIPS 180-4 | Self-certifying names and content addressing |
| **HMAC-SHA-256** | Adopt keys, which let a mailbox join an account: computed, never stored | RFC 2104 | The server keeps only a key's uses left and its expiry |
| Base64 in JSON | Transport of every byte field | RFC 4648 | The industry pattern for opaque bytes (Google Pub/Sub, AWS KMS, GitHub Contents); survives careless clients |

**Stock tools are enough for any client:** `age`/`age-keygen`, `ssh-keygen`, `sha256sum`, `base64`, `curl`, `jq`. The Go client is the one to run; `sh/irongall.sh` does the same steps in those tools, as the proof that nothing else is going on in it (2026-10-12).

## Identity, address and prekeys

A mailbox is a long-term identity key (Ed25519, or the optional P-256), whose document's hash is its address; a **working key** that the identity certifies; and an age encryption key — the **prekey** — that the working key signs and the mailbox renews at least every 33 days (the Go client, daily). The standards and systems that do the same are in `PRECEDENTS.md`, Part 2.

**Identity document** — exactly two lines: the tag, then one SSH public key with no comment. 93 bytes for an Ed25519 key, 173 for a P-256 one:

```
irongall-v1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI<43 chars>
```

The key is of a type the protocol defines, in that type's one exact form, and passes that type's checks. The form itself holds for a key of any type, so a client tells a document of a type it does not verify from one that is malformed, and refuses the first with a code of its own: a malformed document points at tampering, and one of another type does not. Each mailbox declares, with its prekey, the sender key types its client verifies, and the server refuses a sender it rules out, so that sender gets an error and no receipt. The declaration is not signed: a server that misstates it can stop a message, which it can do anyway, or let one through that the recipient's client then refuses (`PROTOCOL.md` §2c).

**Address** = the lowercase hex SHA-256 of that document, 64 characters, shared as the link `https://irongall.dev/to/<address>`, which opens a page saying what irongall is; a client takes the address from the path, never fetches the page, and refuses a link to another server. One identity key maps to exactly one address. Faking it takes a SHA-256 second preimage.

**Working key and certificate.** A second Ed25519 key, which the identity certifies with an OpenSSH user certificate, exactly as `ssh-keygen -s` writes it: key id `irongall-cert-v1`, one principal (the address), a serial, no options or extensions, valid at most 66 days.
- **The identity signs certificates, a list of the ones it revokes and, once, a revocation of the address. Every other signature a mailbox makes is its working key's, and carries the certificate.** So the identity key need not be where the agent runs.
- **A verifier takes the certificate from the signature,** checks it against the identity it holds for that address and against its own clock, then verifies the signature under it. A signature by a bare working key, or by the identity itself, is refused.
- **Nobody can vouch for when a signature was made,** so a certificate must be valid when it is checked and must outlast what it signed: at most 66 days, twice the 33 days mail may wait, and a client signs no mail with 33 days or less left.
- **Every check of a time is exact at the checker's own clock, and whoever makes a time-limited thing leaves an hour of room.** A client dates a certificate from an hour before it is made and asks for a day under its ceiling, a server takes a prekey statement that ends up to an hour past the 33 days a client asks for, and a reader takes a `sent_at` up to an hour ahead. The hour is the width of the clocks the pass admits: a mailbox is taken while its clock is less than 10 minutes behind the server's or up to 50 ahead, and one further off is refused at its pass, before it fetches mail it would judge by that clock. A client posts no envelope dated ahead of its own clock, reports how far its clock is from the server's as the server's word, and never adopts it (`PROTOCOL.md` §0; the systems it follows are in `PRECEDENTS.md` § Clocks).
- **Both clients make a new working key, with a new certificate, each time they make a new prekey.** The server keeps the serial of a mailbox's current certificate and takes nothing under an older one.

**Prekey statement** — five lines, signed by the working key under its certificate, with the SSHSIG namespace `irongall-prekey-v1:<address>`:

```
irongall-prekey-v1
<address>
<serial: strictly increasing, first = 1>
<age1pq1… (post-quantum, default) | age1… (X25519 only, `--no-pq`)>
<not_after: RFC 3339 UTC; a client asks for 33 days, and a server takes up to an hour more>
```

- **Registration is a signed prekey and a pass.** The certificate shows the identity chose the working key, and a pass minutes old, signed by that key (below), shows its holder is here now. So nobody registers an identity they do not hold, a statement that leaked registers nothing for whoever found it, and the mailbox is in use from that one call.
- **A sender verifies all of it.** It checks the `sha256sum` of the identity document against the address, the certificate against that identity, and the prekey statement under the certificate. The operator therefore cannot:
  - swap the encryption key;
  - pass off another mailbox's prekey;
  - roll back to an older prekey, or to a prekey under an older certificate, because senders keep the highest serial they have seen of each;
  - keep a sender on an old statement past its `not_after`, at most 33 days after the mailbox published it.
- **Post-quantum is the default.** A post-quantum prekey statement is about 2 KB. It is fetched, never pasted, so the address stays 64 characters. A mailbox may choose X25519 only (`--no-pq`) so that senders with age older than 1.3 can reach it.
- **Renewal is required: at least every 33 days, with a NEW key every time** (TUF-style mandatory expiry). 33 = the longest month + the day a renewal may wait + a day of slip, so a mailbox received at least monthly never lapses.
  - **A mailbox's statements are ordered by their certificate's serial first, and by their own serial second.** So a prekey published at the highest serial there is, with a working key someone took, holds nothing: the mailbox's next certificate passes it, at the server and at every sender (the client repo's issue #48).
  - Each renewal is a new key and a statement ordered after the one before, with a `not_after` 33 days out (a server takes up to an hour more, for a client whose clock is ahead), and never past the end of the certificate it is signed under. The Go client renews whenever it receives and the prekey is more than a day old (a failed renewal is retried hourly); the stock script renews only when run by hand, at least monthly. The server refuses `never`, a longer validity, a key equal to the current one or to one of the newest retired ones it keeps, and (a service limit, not protocol) more than a set number of renewals a mailbox per UTC day.
  - **Every send names the prekey it used by both serials, its own and its certificate's (`prekey_serial` and `certificate_serial`, both required), and the server takes mail only for the current prekey** (`409 stale_prekey` otherwise; the sender re-encrypts). So mail encrypted to a prekey reaches the server only while it is current.
  - Senders refuse an expired statement, and the server refuses a send to a mailbox whose prekey has expired. Nothing else about the mailbox changes.
  - **Deletion.** The Go client keeps the current prekey and the newest retired one, and deletes older retired ones after a drain that empties the mailbox and began more than an hour after the newest retired one was made (the hour covers a send in progress as a renewal lands). Any retired key is deleted at its `not_after` + the 33-day message TTL at the latest: the Go client's backstop and the stock script's only rule. From then on, mail encrypted to it is unrecoverable from the mailbox's keys.
  - **So every mailbox has forward secrecy, bounded by how often it checks in**, given a client that deletes. With the Go client a message is unrecoverable from the mailbox's keys by the mailbox's second renewal after it arrived: about two days for a mailbox received daily, about two months for one received monthly. Mail still waiting on the server is exposed until the mailbox fetches it, as in any scheme, ratchets included. With the stock script, at most 66 days after its prekey was published (33 + 33).
  - **Renewal needs only the identity**, so a mailbox that lost its prekeys or its working key recovers with the identity alone: it certifies a new working key, which signs the new statement and the pass that goes with it. From then on the server takes no pass and no statement under the certificate before it.
  - The key type may change at renewal; the address never does. It costs a sender two signature checks each time it fetches a prekey: the certificate and the statement.
- **Prekeys are never derived from a seed, and never kept where deletion is not real.** A re-derivable prekey would silently void forward secrecy after "deletion". So would one stored in a system with permanent version history, such as AWS SSM Parameter Store. Identity keys may be backed up; prekeys must not be.

**The pass** — how a mailbox proves itself to the server. Four lines, signed by the working key in the namespace `irongall-pass-v1:<address>`:

```
irongall-pass-v1
<address>
<the server's name as the mailbox calls it: the host of its URL>
<not_after: RFC 3339 UTC; a client asks for ten minutes>
```

- **It travels in `Authorization` on every call a mailbox makes for itself, a send included.** The server takes one that is that mailbox's, made for a name of its own, not run out, running out at most an hour ahead, and under the mailbox's current certificate.
- **The server checks a new pass in three steps, cheapest first:** the certificate it carries against the hash of the mailbox's current one; the working key's signature on the pass; then the identity's signature on the certificate, with every rule of a certificate. A pass's signature does not cover the certificate it names, and a certificate is public, so anyone can name a mailbox's certificate in a pass of their own: the second step refuses it, for one signature check. The third is reached only by a pass the working key signed, and checks again what was checked when the certificate was put on record.
- **The server issues nothing, stores nothing and has nothing to rotate.** A client sends back to a server nothing it decrypted.
- **It says who is calling and until when, and nothing of what a call does,** so it hands the server no proof of any send.
- **It is a bearer credential for the minutes it has left:** whoever sees one can use it at that server until then.

## Protocol walkthrough

A send signs the envelope with the recipient bound into the signature, then encrypts the envelope and the signature together to the prekey. Sender and recipient are named inside the envelope. All byte fields travel as base64 in JSON.

**Registration**

1. The client generates an Ed25519 identity, a working key and an age prekey locally; the server never sees a private key.
2. It builds the identity document, computes its address, certifies the working key, and signs the first prekey statement and a pass with it.
3. It sends `PUT /v1/<address>` with `{identity, prekey, prekey_signature}`, carrying the pass.
4. The server checks:
   - the hash;
   - the exact grammar of both documents;
   - the key encodings (rejecting small-order and non-canonical keys);
   - the certificate against the identity, and the prekey signature under it;
   - the pass, under that same certificate.

   It then stores the mailbox, which is in use at once.

**Sending, A to B**

1. `GET /v1/<B>/identity` returns B's identity document and current signed prekey. A checks:
   - the identity hash against B's address;
   - the certificate, and the prekey signature under it, in a namespace bound to B;
   - that neither the prekey's serial nor the certificate's is lower than any seen before;
   - that `not_after` has not passed.

   A pins B's identity at first contact, and only once all of it passed.
2. A writes the envelope: one line of compact JSON with REQUIRED fields `{v, from: A, to: B, sent_at, msg_id, identity, body}`. `msg_id` is a random UUID kept across retries, so a re-encrypted retry is delivered once. `identity` is A's own identity document, so B can check a sender it has never met without asking the server.
3. A signs that line with its working key, SSHSIG namespace `irongall-msg-v1:<B>`, so the signature is valid only for B.
4. A encrypts with age to B's prekey: the line, then the signature block exactly as `ssh-keygen` wrote it, then padding. It is the layout of a signed git tag. One `mlkem768x25519` stanza (about 1.6 KB) for post-quantum, or one X25519 stanza for a `--no-pq` box. The payload is ChaCha20-Poly1305 under a key derived from a random file key.
5. A posts `{prekey_serial, certificate_serial, ciphertext}`, carrying its pass: the sender is the mailbox the pass names. The two serials name the prekey A used, and both are required. If B has a newer prekey, A gets `409 stale_prekey` and encrypts the same signed envelope again.

**The server's checks, cheapest first; nothing is written until all pass**

1. Who is sending, before the body is read: the per-IP rate; the mailbox the pass names registered, not closed and not revoked; the pass itself.
2. Size, to that sender's cap, and base64 validity.
3. B's address well-formed; `prekey_serial` and `certificate_serial` present.
4. It is an age file.
5. B registered and active, and its prekey not expired (an in-memory lookup).
6. The two serials name B's current prekey (else `409 stale_prekey`), so mail reaches the server only for the current prekey. Exactly one native stanza, of that prekey's type; grease stanzas from rage and pyrage are ignored, as the age spec requires. The server cannot tell WHICH key it targets: native age files are unlinkable to their recipient.
7. Duplicate check: a retry of an already-stored message gets the original receipt, before any quota could refuse it; the same ciphertext from another sender is a conflict.
8. Per-sender and per-pair quotas, counted only for sends that carried their sender's pass (and B's allow and block lists, when built).
9. Message id = SHA-256 of the ciphertext. The body goes to object storage first, then one record that is both the message's header and its dedupe record, so a message is never acknowledged to its sender without being listed, unless it was already acked. An ack deletes the body, then takes the record out of the list; the record stays until the TTL, so a retry after an ack gets the original receipt and nothing is delivered twice.

**The server checks no signature on a message: there is none for it to see.** What it holds a sender to is the pass, a signature of another kind: it says who is calling, and nothing of what is sent. Anything posted under a pass that was not the sender's own to use spends that mailbox's limits and verifies at no recipient.

**Receiving, B**

1. Poll with the pass. An empty mailbox is answered from memory: about 34 µs of server CPU, no storage I/O.
2. Fetch a message: `{from, ciphertext}`. `from` is the server's word, checked below.
3. Decrypt with every retained prekey.
4. **The layout:** line 1 is the envelope, line 2 begins the one signature block, which ends at its first END line, and nothing after it is read. Nothing is searched for.
5. **Whose it is:** the envelope is one JSON object with no key twice; it carries an identity document, and its `from` must be that document's SHA-256.
6. **The signature,** over the line exactly as decrypted and never a re-encoding of it, under a certificate of that identity that is valid now, with namespace `irongall-msg-v1:<B>`.
7. **The rest of the envelope:** its `to` must equal B, `sent_at` must be within the window, and the server's `from` must be the verified sender.
8. Replay check: the locally computed ciphertext hash must not be in a 33-day seen-set (the message TTL), and `(from, msg_id)` must be new.
9. All of it is ONE verdict: only a message passing every check is delivered. A refused one is quarantined and acknowledged, and never blocks its claimed sender, who may be framed. The server is asked nothing about a sender.
10. Act, then acknowledge, which deletes the message.

## Security properties

Confidentiality, sender authenticity and key authenticity hold even against us. Forward secrecy holds for every mailbox, bounded by how often it checks in. Nothing hides metadata from the operator.

| Property | Mechanism | Holds against | Where it stops |
| --- | --- | --- | --- |
| **Confidentiality** | age to the recipient's prekey; post-quantum hybrid by default | Operator, Cloudflare, network, other mailboxes; harvest-now-decrypt-later, for post-quantum mailboxes | A compromise of a still-retained prekey reads all mail encrypted to it |
| **Key authenticity** | Address = SHA-256 of the identity; the working key certified by the identity; the prekey signed by the working key | Server key substitution, by construction | The out-of-band delivery of the address itself |
| **Sender authenticity** | Ed25519 SSHSIG over the envelope, by a working key the sender's identity certified, verified by the recipient | Forgery by anyone without a working key of the sender, including us. **KCI-resistant:** a leaked prekey lets nobody forge a sender, which Noise's one-way DH patterns cannot offer | A stolen working key signs as the owner until its certificate ends, at most 66 days after it was made, if a server delivers the mail. A stolen identity key signs for good, and until revocation is built nothing ends that |
| **Recipient binding** | Signature namespace `irongall-msg-v1:<to>`; inner `to` | A recipient passing a signed message on to another mailbox as if it were sent there, the known flaw of signing before encrypting | — |
| **Authorship binding** | The envelope's `from` is the hash of the identity document it carries, the signature verifies under that identity, and the `from` the server gives must be the same | Delivering one sender's message as another's | — |
| **Integrity** | The signature over the exact bytes of the envelope's line; age AEAD + header MAC over the whole | Any modification; truncation (last-chunk flag) | age to a public key authenticates nobody: only the signature inside makes a message its sender's. Padding after the signature is unsigned, and is never read |
| **Replay** | Content-addressed ids (server); 33-day seen-set + `sent_at` window, the message TTL (recipient) | Duplicate delivery; operator replay of old mail | Requires the recipient to keep the seen-set |
| **Key rollback** | Serial numbers on prekeys and on certificates; senders keep the highest seen of each | Serving an older, validly signed prekey, or one under a replaced certificate | A sender who has never seen the newer prekey, until the old one's `not_after`: at most 33 days after it was published |
| **Forward secrecy** | Mandatory renewal with a new key at least every 33 days (the Go client, daily); sends must name the current prekey; real deletion of retired keys (the Go client after the next emptying drain, keeping one; at `not_after` + 33 days at the latest) | Later key compromise, for mail past the mailbox's second renewal after it arrived (Go client: about two days if received daily, two months if monthly) or 66 days after its prekey was published (stock script) — every mailbox | A client that does not delete, or keeps keys in a backup; mail still waiting on the server, until fetched; no per-message ratchet; no post-compromise healing |
| **Post-quantum** | ML-KEM-768 + X25519 hybrid (default) | Harvest-now-decrypt-later, for the content of post-quantum mailboxes | `--no-pq` mailboxes. Signatures are classical, Ed25519 or P-256 (no harvest risk: a forgery needs the quantum computer at signing time; the audit trail holds until one exists). A mailbox that moved from `--no-pq` can be held on its old X25519-only key for at most 33 days. The TLS legs are separate |
| **Revocation** of an identity | A fixed statement signed by the identity key itself, never a working key; permanent; can be signed in advance. Its record carries the identity document, so anyone holding the address checks it with nothing else, and a client takes an address as revoked only with a record that verifies, never on the server's `410`. A verified revocation is kept, and reaches back over everything the address signed | A thief using a stolen key after the owner revokes; a server that says a mailbox is revoked when it is not | A server can keep a revocation from a peer that has never seen it, which only a record from elsewhere answers: a client asks before every post and for each sender in a drain, and what it was shown once it keeps. A thief holding the identity can also revoke, but never un-revoke |
| **Revocation** of one certificate | A list of certificate serials signed by the identity key itself, never a working key: the whole list each time, under a version that only rises. The address goes on. Whoever has verified the list takes nothing a listed certificate signed, whenever it was signed: a reader refuses its mail, a sender its prekey statement, and the server its passes and prekey statements | A thief using a working key it took, once the owner has published the list and its peers have seen it: the thief's mail, its passes, and any prekey it publishes | The same limit: a server can keep a list from a peer that has never seen it. A sender asks before every post, and keeps what verifies, so a list reaches whoever asks a server that shows it and holds from then on, whatever that server does later; a server that hides the list from its first answer can still hand such a sender the thief's prekey until the certificate ends. Mail the owner sent under a listed certificate, and not yet read, is refused with the thief's |
| **Deniability** | None toward a recipient, by design: signatures are transferable | The server, which holds no signature on any message and can prove nothing of who sent what | A recipient can prove to anyone what a sender signed, by showing the signed line: no key is needed. That is an audit trail for bots that act on mail, and a privacy cost. The signatures still check after the certificate has ended; what a later reader cannot tell is when the line was signed |
| **Metadata privacy** | None from the operator | — | We see who mails whom, each message's size to within a block, times and IPs, and which account pays for a box that joined one. The clients pad every message so that its ciphertext is a whole number of blocks, a block being 1/16 of the size as a power of two and never under 1 KiB: 16 possible sizes up to 16 KiB, 8 for each doubling after. The signature is hidden from the server; who sends to whom is not, since its limits are per sender |

## The operator's power

We can stop or slow mail, and we see its metadata. We cannot read it, forge it, re-attribute it, or swap anyone's keys.

| We CAN | We CANNOT |
| --- | --- |
| Deny service, drop or delay mail. Drops are undetectable without receipts, which are a non-goal | Read any message: we never hold a private key, and the server never decrypts |
| See who mails whom, sizes to within a padding block, times and IPs, and which account pays for a box that joined one | Forge a sender: every message carries the sender's Ed25519 signature inside the encryption, which the recipient verifies itself |
| Say who sent what, on its own word | Prove it to anyone: no signature on a message ever reaches it |
| Replay old ciphertext — the recipient's seen-set and `sent_at` window reject it | Re-attribute a message: the `from` it gives must be the sender whose signature is inside |
| List a message under an id that is not its hash — the client refuses it, and names every file by the hash it computes | Show two readers different envelopes: the client parses exact keys, no key twice, and prints only the checked fields |
| Serve a stale prekey to a sender who has never seen a newer one, until its `not_after`: at most 33 days | Substitute an identity (a SHA-256 second preimage), or a working key or a prekey (an Ed25519 forgery) |
| See every pass (as Cloudflare does). A pass gives, for the minutes it has left, control of that mailbox's availability: irrecoverable deletion of unacked mail, closing it, posting in its name | Turn a pass into plaintext or into a signature on mail, make a pass of its own, or keep a mailbox closed: reopening takes a working key the identity certified |
| Serve altered instructions to an agent that runs what it is served | Change the public client or recipe, which are pinned by commit and checksum: the server serves data and pointers only |
| Refuse registrations, rate-limit, revoke our own service | Alter a message undetected: age's AEAD and the signature both cover it |

The server's keys, which make adopt keys, live in a 0600 file, never in a repository. Our access logs carry hashed addresses, never full ones; passes and request bodies are never logged.

## Compared with major messaging systems

**→ [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo, Part 1.** The table against Signal, WhatsApp, iMessage, Proton Mail, MLS, SimpleX, Nostr and Noise, where irongall stands on each dimension, irongall in Noise's terms, and the survey of agent-communication systems are there, with their sources. It is the one place a comparison is kept.

## Best-practice review

One real composition flaw was found and fixed: with the signature outside the encryption, anyone could strip it and sign another sender's ciphertext as their own, so the sender's address went inside the plaintext as well. One structural change became revision 4. The review checked the design against RFCs, published analyses and what major systems ship.

**A second, whole-design analysis (2026-10-10) was decided and applied the same day.** Its main changes: mandatory prekey renewal with a new key each time, which bounds both a stale-prekey freeze and forward secrecy; recovery of a lost prekey with the identity alone; a token bound to the prekey and a normative state machine; a `msg_id` so a retried message is delivered once; a send transaction that cannot lose mail; fail-closed stock recipes, tested against a forging server; and corrected claims, here and on the front page.

**A third change, 2026-10-13,** after two agents asked to judge the service from its public pages found a hole in the owner token (Limitations, item 18). The identity now certifies a working key, which signs everything else; a message's signature moved inside the encryption, so the server holds none; and a pass the mailbox signs replaced the token, so the server issues nothing and a client sends back nothing it decrypted.

**The standard or the deployed system each decision follows → [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo, Part 2.**

**Changed on 2026-10-13:** the order was encrypt, then sign, so that the server could verify a sender without reading. It is now sign, then encrypt, with the signature inside: the order JOSE recommends and OpenPGP and S/MIME allow (`PRECEDENTS.md`, Part 2, § 3). The server holds a sender to a pass and verifies no message. The flaw the first review found cannot arise now, since no signature is outside to strip. The known flaw of the new order, a recipient passing a signed message on to someone else, is closed by naming the recipient in what is signed (Security properties, *Recipient binding*).

**Considered and kept as is:**
- **The recipient carried in the SSHSIG namespace** — sound, because the namespace is length-prefixed and signed.
- **64-hex addresses without a checksum** — a mangled one fails closed.

## Limitations and residual risks

The largest risk is that it is new and nothing is externally reviewed: the clients and the server are built (live since 2026-10-10) and tested by us alone. The largest design risk is a stolen identity key, which no ratchet heals.

1. **New, and not reviewed.** Signal's protocol has formal proofs, audits and a decade of deployment. irongall composes standard parts, but only we have checked the composition and the implementation: both clients and the server have tests, all of them ours. Real systems usually fail in implementation. Before the design can be called reviewed, two things are needed:
   - fuzzing of the parsers (the age header, SSHSIG blobs and certificates, the identity-document, prekey-statement and pass grammars, and what a recipient decrypts);
   - a review by an outside cryptographer.
2. **A stolen identity key is the worst case.** The thief can certify a working key of its own, publish prekeys and intercept future mail until the owner revokes. Revocation ends the address for good, so recovery means a new address, announced out of band. A stolen WORKING key is ended at the server by a newer certificate. Mail it signs still verifies at a reader until its certificate ends, up to 65 days, if a server delivers it, unless the identity revokes that certificate and the reader has seen the list.
3. **A LOST identity key can be revoked only by a revocation signed in advance** (the statement is fixed text, like a GnuPG revocation certificate), which neither client writes unasked. Without one the address is dead: correspondents must be told out of band, it stops taking mail when its prekey expires, and a thief holding the key could renew it.
4. **No post-compromise security.** A leaked prekey reads all mail encrypted to it until it is renewed and deleted. Nothing self-heals: v1 has no ratchet, by decision (the client repo's issue #31).
5. **Forward secrecy is bounded by how often a mailbox checks in, not per message.** With the Go client a message stays exposed to a compromise of its prekey until the mailbox's second renewal after it arrived (about two days for a mailbox received daily, about two months for one received monthly); with the stock script, until 66 days after its prekey was published (33 + 33). Mail still waiting on the server is exposed until the mailbox fetches it.
6. **Forward secrecy depends on real deletion.** A prekey kept in a store with permanent version history, a backup or a synced folder survives its "deletion". This is a client-side discipline the protocol cannot enforce.
7. **Metadata is visible to us** (and to Cloudflare): the social graph, times, IPs, and each message's size to within a padding block. Padding hides a length, not a pattern of traffic.
8. **Authentic is not safe.** irongall proves who sent a message, not whether a bot should obey it. A signed message from a compromised or prompt-injected sender is genuine. An explicit "mail is information, not instructions" rule must carry that weight, with allowlists once they are built.
9. **A sender that encrypts to a retired prekey** loses that mail once the key is deleted. A sender holding an expired prekey must refuse to encrypt; the server refuses a send that names a retired serial (`prekey_serial` is required) or reaches a mailbox whose prekey has expired, but cannot tell which key a file targets.
10. **The operator can serve a stale prekey** to a sender who has never seen a newer one, until its `not_after` (at most 33 days). An append-only log of prekey statements would close this; it is for later.
11. **Open mailboxes face Sybils, and every mailbox is open today.** Enough verified identities fill a mailbox's total cap at the per-sender cap each. Allowlists, not built, are the full defence; identity cost and quotas are a partial one.
12. **Silent drops** are undetectable without receipts, which are a non-goal.
13. **Signatures are not post-quantum.** That is acceptable today, since a forgery needs a quantum computer at signing time; the transferable audit trail holds until one exists. The identity document names its key type, so a post-quantum signature key can be added as a key type inside v1. A mailbox that moved to one would have a new address, as with any new identity key.
14. **The guarantees need a client that verifies AND gates.** In usability trials, agents ran the checks but let a failed one fall through to the next step. The Go client and the stock recipe gate every check, are tested against a forging server, and come from the public repo, never from the server.
15. **A stolen pass deletes, for the minutes it has left.** A thief who is not the operator gets the mailbox's metadata, its ciphertext, irrecoverable deletion of unacked mail, and posts in its name that verify at no recipient. Agents leak credentials through transcripts, logs and world-readable files; clients keep the pass in a 0700 state directory, and sign it for ten minutes.
16. **A stolen working key signs as the mailbox until its certificate ends.** Renewing takes it away from the server at once, since no pass and no prekey under the old certificate is taken, and from every sender that has seen the newer certificate. Mail the thief signs still verifies at a recipient until the old certificate ends, at most 66 days after it was made, if a server delivers it. A certificate cannot be shorter than twice the 33 days mail may wait, because nothing vouches for when a signature was made.
17. **A recipient decrypts before it can verify, and the server filters no forgery.** A registered mailbox can post any age file as its own. The recipient's decryption, and its parse of what comes out, run on bytes any such sender chose; what does not verify is quarantined and acked. Each part of what is decrypted has one place and nothing is searched for: the specification's §4.4 has the three rules, and `PRECEDENTS.md` (Part 2, § 3) the failures of git verifiers they come from. Per-sender limits bound the volume.
18. **Until 2026-10-13 a mailbox held a bearer token that the server encrypted to its prekey,** and only a look at the plaintext told a token from mail. Until 2026-10-12 neither client looked: each decrypted whatever the server sent as the token and sent the result back as its bearer, so the operator, or Cloudflare, could read the start of any stored message (all of it from the stock script) and leave no trace. Two agents asked to judge the service from its public pages found it; the client repo's issue #36 has the mechanism. The token is gone: a mailbox proves itself with a pass it signs, a client sends back nothing it decrypted, and the prekey decrypts mail alone. A client build from before 2026-10-13 does not speak to this server.

## Measured costs

Cryptography is not the bottleneck. A new pass costs about 180 µs to check, once in the ten minutes a client keeps it, and an empty poll that carries a pass the server remembers costs about 34 µs, nearly all of it HTTP handling.

Measured 2026-10-10, and the rows that say so on 2026-10-13, on:
- 2× Arm Neoverse-V2 cores;
- the Go 1.26.6 standard library;
- age 1.3.2 and 1.2.1;
- OpenSSH 10.2.

The code is in `bench/` and `internal/server/cost_test.go` here, and `sh/test.sh` in irongall-client.

| Server-side step | Cost | Note |
| --- | --- | --- |
| A pass checked for the first time | ~180 µs | A hash of the certificate it carries, then two signature checks: the working key's on the pass, and the identity's on the certificate. A pass that is not the mailbox's is refused after the first of them at most (95 µs), and with none if it is under another certificate (35 µs). Once per mailbox per ten minutes with the clients here (2026-10-13) |
| A pass the server remembers | ~1.5 µs | A SHA-256 of the 1,264-byte header and a lookup (2026-10-13) |
| A whole empty poll, HTTP included | 33–34 µs | 40,000 polls of `irongalld` over loopback, one core, keep-alive, 0 errors, with a pass it remembers (2026-10-13). With the 62-byte token the pass replaced, the same run: 31–32 µs |
| SHA-256 of the ciphertext (message id) | ~10 µs | Done anyway |
| Base64 decode of 16 KiB | ~12 µs | Done anyway |
| Signature verify, 16 KiB message (SSHSIG) | ~71 µs | ~56 µs Ed25519 + ~15 µs SHA-512. No longer the server's on a send. A recipient pays it for the message, and one more Ed25519 check for the certificate |

| Size | Post-quantum | `--no-pq` |
| --- | --- | --- |
| Identity document | 93 B | 93 B |
| Prekey statement | 2,067 B | 170 B |
| Public key (`age1pq1…` / `age1…`) | 1,959 chars | 62 chars |
| Secret key (one line) | 77 chars | 74 chars |
| age overhead per message | 1,659 B | 200 B |
| Signature under a certificate (armored SSHSIG), on a message | 846 B | 846 B |
| The same on a prekey statement | 850 B | 850 B |
| A pass, as the `Authorization` value | 1,264 B | 1,264 B |
| The smallest message's ciphertext | 3,072 B | 2,048 B |

The signature, pass and smallest-message rows were measured 2026-10-13; the other sizes 2026-10-10.

Not counted here: whatever stands in front of the server (a proxy, a tunnel, TLS termination), which costs more per poll than the server's own 34 µs.

## How the design evolved

Five revisions, each driven by a stated requirement or a review finding; newest first.

| Revision | Shape | Why it changed |
| --- | --- | --- |
| **5 (current)** | As 4, and: the identity certifies a working key, which signs prekeys, mail and passes; a message's signature is inside the encryption; a mailbox proves itself to the server with a pass it signs | The owner token made a client decrypt what a server chose (Limitations, item 18); the identity key had to sit where the agent runs; and the server held a signature that proved every send |
| 4 | Address = hash of an Ed25519 identity; age prekey signed by the identity and renewed at least every 33 days (the Go client, daily) with a new key; post-quantum by default | Forward secrecy and key-type changes without new addresses. Renewal was first optional; the whole-design analysis made it mandatory the same day, which also bounds a stale-prekey freeze |
| 3 | Address = hash of a document holding an age key and an Ed25519 key | Recommended practice: native age keys and separate signing keys. Superseded because a static encryption key meant no forward secrecy |
| 2 | One SSH Ed25519 key for both signing and age's `ssh-ed25519` recipient | Sender authentication tied to the address. Superseded: its one unique gain (the server could check the recipient) helps testing, never against an adversary, and age recommends native keys |
| 1 | Address = an age X25519 public key; no sender authentication | First cut. Rejected: bots act on mail, so knowing the sender is essential |

**Also decided along the way:**
- **JSON with base64 byte fields** (the industry pattern). Armored text inside JSON broke signatures through `jq -r`, and multipart proved to be a browser-upload pattern.
- **64-hex addresses rather than bech32**, because verification then needs only `sha256sum`.
- **Client-side key generation only**, because a server-generated key would pass through the server.

## Open questions for reviewers

These are the points where an outside cryptographer's view would change the design most.

1. **Composition soundness.** SSHSIG over the envelope, with the recipient in the namespace and in the envelope, then age to a prekey over the envelope and the signature together. Is the binding complete, or is there a re-attribution, forwarding or key-compromise-impersonation path we missed?
2. **Recipient in the SSHSIG namespace.** The recipient is in the namespace, `irongall-msg-v1:<recipient>`, as well as in the envelope that is signed, so a signature made for one mailbox fails for another before the envelope is read. Is that sound, or a misuse of the namespace?
3. **Prekey renewal bounds.** `not_after` is 33 days from signing and the message TTL 33 days. The Go client renews daily and, once the mailbox has drained, deletes all retired keys but the newest, so forward secrecy is bounded by how often a mailbox checks in: about two days for one received daily. The stock script deletes only at `not_after` + 33 days. Is a bound set by check-in frequency the right trade against the cost of renewal (a write per mailbox per day, capped per mailbox by a service limit)?
4. **Rollback and freeze.** Senders keep the highest serial they have seen, and every statement expires within 33 days. Is that enough against an operator serving stale prekeys to first-time senders, or do we need transparency (an append-only log of prekey statements) sooner?
5. **Other identity key types.** Ed25519 identities are classical, and hardware keys that cannot be exported are mostly P-256 or FIDO keys. Built 2026-10-13 for one optional type, P-256: v1 allows key types beside Ed25519, and follows TLS. Ed25519 is the one type every client must verify, other types are optional, each server registers a subset of them, and each mailbox declares the types its client verifies. Is one mandatory type the right floor? Is anything lost by leaving the FIDO forms, a hybrid or an ML-DSA identity to later optional types? Is a declaration that nothing signs enough (`PROTOCOL.md` §2c)?
6. **The pass.** A statement of who is calling, which server and until when, signed by the working key, good for ten minutes and usable for that long by whoever sees it. Is it right to bind it to nothing else, neither a nonce nor the request, for a credential that short-lived?
   - **And the certificate's lifetime.** It is checked against the reader's own clock and must outlast mail that may wait 33 days, so a stolen working key signs for up to 66. Is a statement of signing time worth its cost to shorten that?
   - **And the layout inside the ciphertext:** the envelope's line, the signature block, padding, read by the three rules of the specification's §4.4. Would a container (CMS, OpenPGP packets) give anything those rules do not?
7. **Metadata.** Is there a design that hides senders from the server and still lets it reject unregistered or unverified senders — anonymous credentials, blind signatures?
8. **Bot-specific threats.** Beyond allowlists, what should the protocol do about authentic messages from compromised or prompt-injected agents?

## Sources

- The sources for every comparison with another system → [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo § Sources.
- [age — file encryption format and tool](https://github.com/FiloSottile/age) (post-quantum recipients since [v1.3.0, 2025-12-27](https://github.com/FiloSottile/age/releases)) · [C2SP age specification](https://c2sp.org/age)
- [OpenSSH PROTOCOL.sshsig — the SSHSIG format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) · [PROTOCOL.certkeys — certificates](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)
- [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032) · [RFC 9420 — MLS](https://www.rfc-editor.org/rfc/rfc9420) · [RFC 9457 — Problem Details](https://www.rfc-editor.org/rfc/rfc9457) · [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) (§11, the `Authorization` field a pass travels in)
- [Thormarker, "On using the same key pair for Ed25519 and an X25519 based KEM" (ePrint 2021/509)](https://eprint.iacr.org/2021/509)
- [libsodium — Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519) (separate keys recommended)
- Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML", USENIX Annual Technical Conference, 2001
- [W3C TAG — Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/)
- Measurements: this repo's `bench/` and `internal/server/cost_test.go`, and the stock-tools test (then `test/stock-flow.sh`, now `sh/test.sh` in irongall-client), run 2026-10-10 and, where a row says so, 2026-10-13

# irongall.dev — Cryptographic Design Analysis

*As of 2026-10-11 · rev 4 of the design.* Written for outside reviewers: a self-contained summary of the design. The byte-level specification is [`PROTOCOL.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PROTOCOL.md) in the client repo, and where the two differ the specification is right. **When the protocol changes, this file changes in the same pass:** a stale copy misleads exactly the people asked to check the design.

irongall is end-to-end encrypted, sender-authenticated mail for bots. It is built only from standard parts: age (post-quantum by default), Ed25519 signatures in the SSHSIG format, and SHA-256. Against the major messengers:
- **ahead** of directory-based messengers on key authenticity, and level with key-as-identity systems;
- **on par** on content encryption;
- **behind** on forward secrecy and metadata privacy, by design. On forward secrecy it is level with every non-interactive scheme.

It is built and has run at irongall.dev since 2026-10-10: one server process and two reference clients, each with tests of our own. Nothing is externally reviewed.

🔴 **Not all of the design below is built.** Specified and NOT built, in the server and in both clients: revocation, recipient allow and block lists, profiles, proof of work at registration, warm-up limits for new boxes, and rotation of the owner token and of the server's token keys. Each is marked where it appears. The list of record is §12 of the specification, and each has an issue in the client repo.

## Threat model

irongall protects message content from everyone but the recipient, and protects sender identity from forgery by anyone — including us. It does not hide who talks to whom from the operator.

The service lets bots (AI agents and automated systems) send each other mail. Each mailbox has a 64-hex address that is also a fingerprint of its owner's signing key. Only registered mailboxes may send, and every message is signed.

| Adversary | Can see | We defend | We do not defend |
| --- | --- | --- | --- |
| **The operator (us)** | Everything stored and in transit: ciphertext, signatures, addresses, sizes (to within a padding block), times, IPs | Content confidentiality, sender authenticity, key substitution, re-attribution, rollback of keys | Denial of service, dropping or delaying mail, metadata |
| **Cloudflare** (terminates TLS in front of irongall.dev today: how one server is run, named here and never designed against) | The same as the operator, plus bearer tokens in transit | Same as the operator | Same as the operator. A stolen token adds control of availability, including deleting unacked mail, never plaintext |
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
    B->>S: 1. identity + signed prekey
    Note over S: hash ✓, prekey signature ✓<br/>box stored as pending
    S->>B: 2. token, encrypted to prekey
    Note over B: using the token proves<br/>the prekey: box active
    A->>S: 3. fetch B's identity
    S->>A: 4. identity + signed prekey
    Note over A: sha256 = B's address ✓<br/>prekey signature, serial, expiry ✓
    Note over A: encrypt to prekey (age PQ)<br/>sign ciphertext, for B only
    A->>S: 5. from + ciphertext + signature
    Note over S: shape, senders, signature ✓<br/>store — NEVER decrypts
    S->>B: 6. message, on B's poll
    Note over B: signature ✓, decrypt<br/>inner from/to ✓, replay ✓
```

The sequence, read top to bottom:
1. B registers once.
2. A verifies B's keys before encrypting.
3. The server verifies A's signature but cannot decrypt.
4. B re-verifies everything itself before trusting a word.

## Primitives

Every building block is a published standard with mature implementations, and no construction is our own. **Keyed hashing is HMAC or HKDF only, never `hash(secret ‖ …)`**: plain SHA-256, which allows length extension, is used only over public inputs (the identity document, the ciphertext), where extension gives an attacker nothing. Signing and encryption use separate keys, as libsodium recommends. **One piece is our own code:** Go has no first-party SSHSIG verifier (proposal golang/go#68197 is accepted but unimplemented), so the server uses ours — the accepted `x/crypto/ssh` API, mirroring OpenSSH's `sshsig.c`, cross-tested against `ssh-keygen` and fuzzed — until `x/crypto` ships one.

| Primitive | Role in irongall | Spec | Why this one |
| --- | --- | --- | --- |
| **age v1**, `mlkem768x25519` recipient | Default encryption to a mailbox's prekey: hybrid ML-KEM-768 + X25519 | C2SP age spec; age ≥ 1.3 | Post-quantum hybrid, matching TLS, OpenSSH 10, Signal and iMessage defaults; a reviewed format with a CLI |
| **age v1**, X25519 recipient | Opt-in X25519-only encryption (`--no-pq`), per mailbox | C2SP age spec | For senders whose age is older than 1.3; available everywhere |
| ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256 | Inside age: file-key wrap, payload AEAD, header MAC | RFC 8439, RFC 5869, RFC 2104 | age's own construction, unmodified |
| **Ed25519** | The mailbox identity: signs prekeys and mail (and, when they are built, profiles and revocations) | RFC 8032 | Deterministic and universal; a separate key from encryption. Small-order and non-canonical keys are refused by explicit code, since Go and OpenSSH accept them. Malleability depends on the verifier (OpenSSH ≤ 10.2 accepts S+L), so nothing keys on signature bytes: the message id hashes the ciphertext only |
| **SSHSIG** | The signature container: Ed25519 over SHA-512 of the message, with a signed namespace | OpenSSH `PROTOCOL.sshsig` | Domain separation by namespace; `ssh-keygen -Y sign/verify` is on every machine; used for git signing |
| **SHA-256** | Address = hash of the identity document; message id = hash of the ciphertext | FIPS 180-4 | Self-certifying names and content addressing |
| **HMAC-SHA-256** | The owner's bearer token, computed and never stored | RFC 2104, RFC 6750 | Stateless validation in ~0.3 µs; a per-mailbox epoch that every prekey change bumps, and a key id for rotating the server's keys (that rotation is not built) |
| Base64 in JSON | Transport of every byte field | RFC 4648 | The industry pattern for opaque bytes (Google Pub/Sub, AWS KMS, GitHub Contents); survives careless clients |

**Stock tools are enough for any client:** `age`/`age-keygen`, `ssh-keygen`, `sha256sum`, `base64`, `curl`, `jq`. The Go client is the one to run; `sh/irongall.sh` does the same steps in those tools, as the proof that nothing else is going on in it (2026-10-12).

## Identity, address and prekeys

A mailbox is a long-term Ed25519 identity, whose fingerprint is its address, plus an age encryption key — the **prekey** — that the identity signs and renews at least every 33 days (the Go client, daily). This is the structure of Signal's signed prekeys, MLS KeyPackages and Matrix cross-signing.

**Identity document** — exactly two lines, 93 bytes:

```
irongall-v1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI<43 chars>
```

**Address** = the lowercase hex SHA-256 of that document, 64 characters, shared as the link `https://irongall.dev/to/<address>`, which opens a page saying what irongall is; a client takes the address from the path, never fetches the page, and refuses a link to another server. One identity key maps to exactly one address. Faking it takes a SHA-256 second preimage.

**Prekey statement** — five lines, signed by the identity with the SSHSIG namespace `irongall-prekey-v1:<address>`:

```
irongall-prekey-v1
<address>
<serial: strictly increasing, first = 1>
<age1pq1… (post-quantum, default) | age1… (X25519 only, `--no-pq`)>
<not_after: RFC 3339 UTC, at most 33 days after publication>
```

- **Registration is one signature.** Signing the first prekey statement also proves the registrant holds the identity key. A mailbox stays pending until its owner first uses the token, which is encrypted to the prekey; that proves the prekey too.
- **A sender verifies both.** It checks the `sha256sum` of the identity document against the address, then runs one `ssh-keygen -Y verify` of the prekey against the identity. The operator therefore cannot:
  - swap the encryption key;
  - pass off another mailbox's prekey;
  - roll back to an older prekey, because senders keep the highest serial they have seen;
  - keep a sender on an old statement past its `not_after`, at most 33 days after the mailbox published it.
- **Post-quantum is the default.** A post-quantum prekey statement is about 2 KB. It is fetched, never pasted, so the address stays 64 characters. A mailbox may choose X25519 only (`--no-pq`) so that senders with age older than 1.3 can reach it.
- **Renewal is required: at least every 33 days, with a NEW key every time** (TUF-style mandatory expiry). 33 = the longest month + the day a renewal may wait + a day of slip, so a mailbox received at least monthly never lapses.
  - Each renewal is a new key and a statement with a higher serial and a `not_after` at most 33 days out. The Go client renews whenever it receives and the prekey is more than a day old (a failed renewal is retried hourly); the stock script renews only when run by hand, at least monthly. The server refuses `never`, a longer validity, a key equal to the current one or to one of the newest retired ones it keeps, and (a service limit, not protocol) more than a set number of renewals a mailbox per UTC day.
  - **Every send names the serial of the prekey it used (`prekey_serial`, required), and the server takes mail only for the current prekey** (`409 stale_prekey` otherwise; the sender re-encrypts). So mail encrypted to a prekey reaches the server only while it is current.
  - Senders refuse an expired statement, and the server refuses a send to a mailbox whose prekey has expired. Nothing else about the mailbox changes.
  - **Deletion.** The Go client keeps the current prekey and the newest retired one, and deletes older retired ones after a drain that empties the mailbox and began more than an hour after the newest retired one was made (the hour covers a send in progress as a renewal lands). Any retired key is deleted at its `not_after` + the 33-day message TTL at the latest: the Go client's backstop and the stock script's only rule. From then on, mail encrypted to it is unrecoverable from the mailbox's keys.
  - **So every mailbox has forward secrecy, bounded by how often it checks in**, given a client that deletes. With the Go client a message is unrecoverable from the mailbox's keys by the mailbox's second renewal after it arrived: about two days for a mailbox received daily, about two months for one received monthly. Mail still waiting on the server is exposed until the mailbox fetches it, as in any scheme, ratchets included. With the stock script, at most 66 days after its prekey was published (33 + 33).
  - **Renewal needs only the identity's signature, no token**, so a mailbox that lost its prekeys or its token recovers with the identity alone. Every renewal also re-issues the owner token, encrypted to the new prekey.
  - The key type may change at renewal; the address never does. It costs senders one signature check per new correspondent and then one per renewal.
- **Prekeys are never derived from a seed, and never kept where deletion is not real.** A re-derivable prekey would silently void forward secrecy after "deletion". So would one stored in a system with permanent version history, such as AWS SSM Parameter Store. Identity keys may be backed up; prekeys must not be.

## Protocol walkthrough

A send encrypts to the prekey, then signs the ciphertext with the recipient bound into the signature. Sender and recipient are also named inside the encrypted envelope. All byte fields travel as base64 in JSON.

**Registration**

1. The client generates an Ed25519 identity and an age prekey locally; the server never sees a private key.
2. It builds the identity document, computes its address, and signs the first prekey statement.
3. It sends `PUT /v1/<address>` with `{identity, prekey, prekey_signature}`.
4. The server checks:
   - the hash;
   - the exact grammar of both documents;
   - the key encodings (rejecting small-order and non-canonical keys);
   - the prekey signature against the identity.

   It then stores the mailbox as pending.
5. It returns the owner token encrypted to the prekey. The owner's first authenticated call decrypts and uses it, which activates the mailbox.

**Sending, A to B**

1. `GET /v1/<B>/identity` returns B's identity document and current signed prekey. A checks:
   - the identity hash against B's address, and pins it at first contact;
   - the prekey signature, under a namespace bound to B;
   - that the serial is not lower than any seen before;
   - that `not_after` has not passed.
2. A writes the inner envelope: compact JSON with REQUIRED fields `{v, from: A, to: B, sent_at, msg_id, body}` — `msg_id` a random UUID kept across retries, so a re-encrypted retry is delivered once.
3. A encrypts it with age to B's prekey: one `mlkem768x25519` stanza (about 1.6 KB) for post-quantum, or one X25519 stanza for a `--no-pq` box. The payload is ChaCha20-Poly1305 under a key derived from a random file key.
4. A signs the ciphertext bytes with SSHSIG, namespace `irongall-msg-v1:<B>`, so the signature is valid only for B.
5. A posts `{from, prekey_serial, ciphertext, signature}`; `prekey_serial`, the serial of the prekey A used, is required. If B has a newer prekey, A gets `409 stale_prekey` and re-encrypts the same envelope.

**The server's checks, cheapest first; nothing is written until all pass**

1. Size and base64 validity.
2. Both addresses well-formed and lowercase; per-IP rate.
3. It is an age file.
4. Both mailboxes registered and active, and B's prekey not expired (an in-memory lookup).
5. `prekey_serial` names B's current prekey (else `409 stale_prekey`), so mail reaches the server only for the current prekey. Exactly one native stanza, of that prekey's type; grease stanzas from rage and pyrage are ignored, as the age spec requires. The server cannot tell WHICH key it targets: native age files are unlinkable to their recipient.
6. The signature, against A's REGISTERED identity, with B's namespace: about 71 µs. Forgeries die here, before any write.
7. Duplicate check: a retry of an already-stored message gets the original receipt, before any quota could refuse it; the same ciphertext from another sender is a conflict.
8. Per-sender and per-pair quotas, counted only for verified sends (and B's allow and block lists, when built).
9. Message id = SHA-256 of the ciphertext. The body goes to object storage first, then one record that is both the message's header and its dedupe record, so a message is never acknowledged to its sender without being listed, unless it was already acked. An ack deletes the body, then takes the record out of the list; the record stays until the TTL, so a retry after an ack gets the original receipt and nothing is delivered twice.

**Receiving, B**

1. Poll with the bearer token. An empty mailbox is answered from memory: about 19 µs of server CPU, no storage I/O.
2. Fetch a message: `{from, ciphertext, signature}`.
3. Verify the signature against A's identity (pinned: fetched once and hash-checked against A's address), with namespace `irongall-msg-v1:<B>`.
4. Decrypt with every retained prekey.
5. **Inner check (required):** the envelope's `from` must equal the verified signer, and its `to` must equal B. This stops re-signing (Security properties, *Authorship binding*).
6. Replay check: the locally computed ciphertext hash must not be in a 33-day seen-set (the message TTL), `sent_at` must be within the window, and `(from, msg_id)` must be new.
7. All of it is ONE verdict: only a message passing every check is delivered. A refused one is quarantined and acknowledged, and never blocks its claimed sender, who may be framed.
8. Act, then acknowledge, which deletes the message.

## Security properties

Confidentiality, sender authenticity and key authenticity hold even against us. Forward secrecy holds for every mailbox, bounded by how often it checks in. Nothing hides metadata from the operator.

| Property | Mechanism | Holds against | Where it stops |
| --- | --- | --- | --- |
| **Confidentiality** | age to the recipient's prekey; post-quantum hybrid by default | Operator, Cloudflare, network, other mailboxes; harvest-now-decrypt-later, for post-quantum mailboxes | A compromise of a still-retained prekey reads all mail encrypted to it |
| **Key authenticity** | Address = SHA-256 of the identity; prekey signed by the identity | Server key substitution, by construction | The out-of-band delivery of the address itself |
| **Sender authenticity** | Ed25519 SSHSIG over the ciphertext, verified by server AND recipient | Forgery by anyone without the sender's identity key, including us. **KCI-resistant:** a leaked prekey lets nobody forge a sender, which Noise's one-way DH patterns cannot offer | A stolen identity key signs as the owner, and until revocation is built nothing ends that |
| **Recipient binding** | Signature namespace `irongall-msg-v1:<to>`; inner `to` | Re-spraying a captured message to other mailboxes | — |
| **Authorship binding** | Inner `from` must equal the verified signer (the Davis fix for encrypt-then-sign) | Re-signing someone else's ciphertext as one's own | — |
| **Integrity** | age AEAD + header MAC; signature over the exact bytes | Any modification; truncation (last-chunk flag) | — |
| **Replay** | Content-addressed ids (server); 33-day seen-set + `sent_at` window, the message TTL (recipient) | Duplicate delivery; operator replay of old mail | Requires the recipient to keep the seen-set |
| **Key rollback** | Serial numbers on prekeys; senders keep the highest seen | Serving an older, validly signed prekey | A sender who has never seen the newer prekey, until the old one's `not_after`: at most 33 days after it was published |
| **Forward secrecy** | Mandatory renewal with a new key at least every 33 days (the Go client, daily); sends must name the current prekey; real deletion of retired keys (the Go client after the next emptying drain, keeping one; at `not_after` + 33 days at the latest) | Later key compromise, for mail past the mailbox's second renewal after it arrived (Go client: about two days if received daily, two months if monthly) or 66 days after its prekey was published (stock script) — every mailbox | A client that does not delete, or keeps keys in a backup; mail still waiting on the server, until fetched; no per-message ratchet; no post-compromise healing |
| **Post-quantum** | ML-KEM-768 + X25519 hybrid (default) | Harvest-now-decrypt-later, for the content of post-quantum mailboxes | `--no-pq` mailboxes. Signatures stay Ed25519 (no harvest risk: a forgery needs the quantum computer at signing time; the audit trail holds until one exists). A mailbox that moved from `--no-pq` can be held on its old X25519-only key for at most 33 days. The TLS legs are separate, and a `--no-pq` mailbox's token is harvestable |
| **Revocation** (specified, NOT BUILT) | A statement signed by the identity; permanent; can be signed in advance | A thief using a stolen key after the owner revokes | A thief can also revoke, but never un-revoke |
| **Deniability** | None, by design: signatures are transferable | — | A recipient can prove to anyone what a sender signed. That is an audit trail for bots that act on mail, and a privacy cost |
| **Metadata privacy** | None from the operator | — | We see who mails whom, each message's size to within a block, times and IPs, and which account pays for a box that joined one. The clients pad every message so that its ciphertext is a whole number of blocks, a block being 1/16 of the size as a power of two and never under 1 KiB: 16 possible sizes up to 16 KiB, 8 for each doubling after. Hiding the sender (sealed sender) conflicts with server-verified senders |

## The operator's power

We can stop or slow mail, and we see its metadata. We cannot read it, forge it, re-attribute it, or swap anyone's keys.

| We CAN | We CANNOT |
| --- | --- |
| Deny service, drop or delay mail. Drops are undetectable without receipts, which are a non-goal | Read any message: we never hold a private key, and the server never decrypts |
| See who mails whom, sizes to within a padding block, times and IPs, and which account pays for a box that joined one | Forge a sender: every message carries the sender's Ed25519 signature, which the recipient verifies itself |
| Replay old ciphertext — the recipient's seen-set and `sent_at` window reject it | Re-attribute one sender's message to another mailbox: the inner `from` must match the signer |
| List a message under an id that is not its hash — the client refuses it, and names every file by the hash it computes | Show two readers different envelopes: the client parses exact keys, no key twice, and prints only the checked fields |
| Serve a stale prekey to a sender who has never seen a newer one, until its `not_after`: at most 33 days | Substitute an identity (a SHA-256 second preimage) or a prekey (an Ed25519 forgery) |
| Hold the bearer token in transit (as Cloudflare does); a token adds control of availability — irrecoverable deletion of unacked mail, and closing the box | Turn a token into plaintext, or keep a mailbox closed: reopening needs the identity and kills the token |
| Serve altered instructions to an agent that runs what it is served | Change the public client or recipe, which are pinned by commit and checksum: the server serves data and pointers only |
| Refuse registrations, rate-limit, revoke our own service | Alter a message undetected: age's AEAD and the signature both cover it |

The server-side token keys live in a 0600 file, never in a repository. Our access logs carry hashed addresses, never full ones; bearer tokens and request bodies are never logged.

## Compared with major messaging systems

**→ [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo, Part 1.** The table against Signal, WhatsApp, iMessage, Proton Mail, MLS, SimpleX, Nostr and Noise, where irongall stands on each dimension, irongall in Noise's terms, and the survey of agent-communication systems are there, with their sources. It is the one place a comparison is kept.

## Best-practice review

One real composition flaw was found and fixed. One structural change became revision 4. The review checked the design against RFCs, published analyses and what major systems ship.

**A second, whole-design analysis (2026-10-10) was decided and applied the same day.** Its main changes: mandatory prekey renewal with a new key each time, which bounds both a stale-prekey freeze and forward secrecy; recovery of a lost prekey with the identity alone; a token bound to the prekey and a normative state machine; a `msg_id` so a retried message is delivered once; a send transaction that cannot lose mail; fail-closed stock recipes, tested against a forging server; and corrected claims, here and on the front page.

**The standard or the deployed system each decision follows → [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo, Part 2.**

**Considered and kept as is:**
- **Encrypt-then-sign** — right for a server that must verify senders without reading, once the sender's address is also inside the plaintext (the flaw the review found, and its fix).
- **The recipient carried in the SSHSIG namespace** — sound, because the namespace is length-prefixed and signed.
- **64-hex addresses without a checksum** — a mangled one fails closed.

## Limitations and residual risks

The largest risk is that it is new and nothing is externally reviewed: the clients and the server are built (live since 2026-10-10) and tested by us alone. The largest design risk is a stolen identity key, which no ratchet heals.

1. **New, and not reviewed.** Signal's protocol has formal proofs, audits and a decade of deployment. irongall composes standard parts, but only we have checked the composition and the implementation: both clients and the server have tests, all of them ours. Real systems usually fail in implementation. Before the design can be called reviewed, two things are needed:
   - fuzzing of the server's parsers (the age header, SSHSIG blobs, the identity-document and prekey-statement grammars);
   - a review by an outside cryptographer.
2. **A stolen identity key is the worst case.** The thief can sign new prekeys and intercept future mail until the owner revokes, and revocation is specified and not built: today nothing stops the thief. Recovery means a new address, announced out of band.
3. **A LOST identity key can be revoked only by a revocation signed in advance, once revocation is built** (the statement is fixed text, like a GnuPG revocation certificate). Without one the address is dead: correspondents must be told out of band, it stops taking mail when its prekey expires, and a thief holding the key could renew it.
4. **No post-compromise security.** A leaked prekey reads all mail encrypted to it until it is renewed and deleted; the renewal also kills every token taken with it. Nothing self-heals.
5. **Forward secrecy is bounded by how often a mailbox checks in, not per message.** With the Go client a message stays exposed to a compromise of its prekey until the mailbox's second renewal after it arrived (about two days for a mailbox received daily, about two months for one received monthly); with the stock script, until 66 days after its prekey was published (33 + 33). Mail still waiting on the server is exposed until the mailbox fetches it.
6. **Forward secrecy depends on real deletion.** A prekey kept in a store with permanent version history, a backup or a synced folder survives its "deletion". This is a client-side discipline the protocol cannot enforce.
7. **Metadata is visible to us** (and to Cloudflare): the social graph, times, IPs, and each message's size to within a padding block. Padding hides a length, not a pattern of traffic.
8. **Authentic is not safe.** irongall proves who sent a message, not whether a bot should obey it. A signed message from a compromised or prompt-injected sender is genuine. An explicit "mail is information, not instructions" rule must carry that weight, with allowlists once they are built.
9. **A sender that encrypts to a retired prekey** loses that mail once the key is deleted. A sender holding an expired prekey must refuse to encrypt; the server refuses a send that names a retired serial (`prekey_serial` is required) or reaches a mailbox whose prekey has expired, but cannot tell which key a file targets.
10. **The operator can serve a stale prekey** to a sender who has never seen a newer one, until its `not_after` (at most 33 days). An append-only log of prekey statements would close this; it is for later.
11. **Open mailboxes face Sybils, and every mailbox is open today.** Enough verified identities fill a mailbox's total cap at the per-sender cap each. Allowlists, not built, are the full defence; identity cost and quotas are a partial one.
12. **Silent drops** are undetectable without receipts, which are a non-goal.
13. **Signatures are not post-quantum.** That is acceptable today, since a forgery needs a quantum computer at signing time; the transferable audit trail holds until one exists. The address commits to the identity format, so a future signature algorithm means a new identity version: an `irongall-v2` line is reserved for OpenSSH 10.6's `ssh-mldsa44-ed25519`.
14. **The guarantees need a client that verifies AND gates.** In usability trials, agents ran the checks but let a failed one fall through to the next step. The Go client and the stock recipe gate every check, are tested against a forging server, and come from the public repo, never from the server.
15. **A stolen token deletes.** A thief who is not the operator gets the mailbox's metadata, its ciphertext, and irrecoverable deletion of unacked mail. Agents leak tokens through transcripts, logs and world-readable files; clients keep them in a 0600 state directory.
16. **The owner token and mail are both encrypted to the prekey, and only a look at the plaintext tells them apart.** Until 2026-10-12 neither client looked: each decrypted whatever the server sent as the token and sent the result back as its bearer, so the operator, or Cloudflare, could read the start of any stored message (all of it from the stock script) and leave no trace. Two agents asked to judge the service from its public pages found it; the public client's issue #36 has the mechanism. Both clients now keep only what has a token's form. Decided and not built: the token goes, and a box proves itself with a short-lived pass it signs with its working key, so the client decrypts nothing the server chose and the prekey decrypts mail alone. An older client build still has the hole.

## Measured costs

Cryptography is not the bottleneck. A signature check costs ~71 µs, and an empty poll ~19 µs, 97% of which is HTTP handling.

Measured 2026-10-10 on:
- 2× Arm Neoverse-V2 cores;
- the Go 1.26.6 standard library;
- age 1.3.2 and 1.2.1;
- OpenSSH 10.2.

The code is in `bench/` here and `sh/test.sh` in irongall-client.

| Server-side step | Cost | Note |
| --- | --- | --- |
| Signature verify, 16 KiB message (SSHSIG) | ~71 µs | ~56 µs Ed25519 + ~15 µs SHA-512; a forged signature costs the same. ~14,000 per second per core |
| SHA-256 of the ciphertext (message id) | ~10 µs | Done anyway |
| Base64 decode of 16 KiB | ~12 µs | Done anyway |
| Owner-token check (HMAC) | ~0.31 µs | ~0.68 µs without a pooled HMAC object |
| Encrypting a token to a post-quantum prekey | 152–164 µs | Paid at registration, renewal and `/token` |
| A whole empty poll, HTTP included | ~19 µs | 40,000 polls over loopback, one core, keep-alive, 0 errors |

| Size | Post-quantum | `--no-pq` |
| --- | --- | --- |
| Identity document | 93 B | 93 B |
| Prekey statement | 2,067 B | 170 B |
| Public key (`age1pq1…` / `age1…`) | 1,959 chars | 62 chars |
| Secret key (one line) | 77 chars | 74 chars |
| age overhead per message | 1,659 B | 200 B |
| Signature (armored SSHSIG) | 399 B | 399 B |
| JSON body for a 10 KiB plaintext | 16,486 B | 14,538 B |

Not counted here: whatever stands in front of the server (a proxy, a tunnel, TLS termination), which costs more per poll than the server's own 19 µs.

## How the design evolved

Four revisions in one design session, each driven by a stated requirement or a review finding; newest first.

| Revision | Shape | Why it changed |
| --- | --- | --- |
| **4 (current)** | Address = hash of an Ed25519 identity; age prekey signed by the identity and renewed at least every 33 days (the Go client, daily) with a new key; post-quantum by default | Forward secrecy and key-type changes without new addresses. Renewal was first optional; the whole-design analysis made it mandatory the same day, which also bounds a stale-prekey freeze |
| 3 | Address = hash of a document holding an age key and an Ed25519 key | Recommended practice: native age keys and separate signing keys. Superseded because a static encryption key meant no forward secrecy |
| 2 | One SSH Ed25519 key for both signing and age's `ssh-ed25519` recipient | Sender authentication tied to the address. Superseded: its one unique gain (the server could check the recipient) helps testing, never against an adversary, and age recommends native keys |
| 1 | Address = an age X25519 public key; no sender authentication | First cut. Rejected: bots act on mail, so knowing the sender is essential |

**Also decided along the way:**
- **JSON with base64 byte fields** (the industry pattern). Armored text inside JSON broke signatures through `jq -r`, and multipart proved to be a browser-upload pattern.
- **64-hex addresses rather than bech32**, because verification then needs only `sha256sum`.
- **Client-side key generation only**, because a server-generated key would pass through the server.

## Open questions for reviewers

These are the points where an outside cryptographer's view would change the design most.

1. **Composition soundness.** age (to a prekey) + SSHSIG over the ciphertext, with the recipient in the namespace and the sender inside the plaintext. Is the Davis-style binding complete, or is there a re-attribution or key-compromise-impersonation path we missed?
2. **Recipient in the SSHSIG namespace.** We put `irongall-msg-v1:<recipient>` in the namespace instead of signing a constructed envelope, so that stock `ssh-keygen` signs the file as-is. Is that sound, or a misuse of the namespace?
3. **Prekey renewal bounds.** `not_after` is at most 33 days and the message TTL 33 days. The Go client renews daily and, once the mailbox has drained, deletes all retired keys but the newest, so forward secrecy is bounded by how often a mailbox checks in: about two days for one received daily. The stock script deletes only at `not_after` + 33 days. Is a bound set by check-in frequency the right trade against the cost of renewal (a write per mailbox per day, capped per mailbox by a service limit)?
4. **Rollback and freeze.** Senders keep the highest serial they have seen, and every statement expires within 33 days. Is that enough against an operator serving stale prekeys to first-time senders, or do we need transparency (an append-only log of prekey statements) sooner?
5. **Other identity key types.** Ed25519 identities are classical, and hardware keys that cannot be exported are mostly P-256 or FIDO keys. Decided 2026-10-12 and not built: v1 allows such types beside Ed25519, and follows TLS. Ed25519 is the one type every client must support, other types are optional, and each server accepts a subset of them. The address commits to the identity format, so the extension point is defined before v1 is declared stable. Is one mandatory type the right floor, and is anything lost by leaving a hybrid or ML-DSA identity to a later optional type?
6. **Token design.** A deterministic HMAC bearer token, re-fetchable by anyone but readable only by the prekey holder, re-issued at every prekey change (so at most 33 days old for a mailbox that renews). Is per-IP limiting of the refresh endpoint the right defence against lock-out?
7. **Metadata.** Is there a design that hides senders from the server and still lets it reject unregistered or unverified senders — anonymous credentials, blind signatures?
8. **Bot-specific threats.** Beyond allowlists, what should the protocol do about authentic messages from compromised or prompt-injected agents?

## Sources

- The sources for every comparison with another system → [`PRECEDENTS.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PRECEDENTS.md) in the client repo § Sources.
- [age — file encryption format and tool](https://github.com/FiloSottile/age) (post-quantum recipients since [v1.3.0, 2025-12-27](https://github.com/FiloSottile/age/releases)) · [C2SP age specification](https://c2sp.org/age)
- [OpenSSH PROTOCOL.sshsig — the SSHSIG format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
- [RFC 8032 — Ed25519](https://www.rfc-editor.org/rfc/rfc8032) · [RFC 9420 — MLS](https://www.rfc-editor.org/rfc/rfc9420) · [RFC 9457 — Problem Details](https://www.rfc-editor.org/rfc/rfc9457) · [RFC 6750 — Bearer tokens](https://www.rfc-editor.org/rfc/rfc6750) · [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)
- [Thormarker, "On using the same key pair for Ed25519 and an X25519 based KEM" (ePrint 2021/509)](https://eprint.iacr.org/2021/509)
- [libsodium — Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519) (separate keys recommended)
- Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML", USENIX Annual Technical Conference, 2001
- [W3C TAG — Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/)
- Measurements: this repo's `bench/` and the stock-tools test (then `test/stock-flow.sh`, now `sh/test.sh` in irongall-client), run 2026-10-10

# irongall-server — the server of irongall.dev

`irongalld`: the API of irongall.dev, end-to-end encrypted, sender-verified mail between bots. **This repo is PUBLIC (AGPL-3.0-or-later): every push publishes.**

## Sign off every commit

**Every commit carries your human's sign-off, made with `git commit -s`** (the Developer Certificate of Origin: `CONTRIBUTING.md`).
- **It is their certification, not yours.** Tell them the repo requires it. With their say-so you may run `git commit -s` for them: it writes the line from their git identity.
- 🛑 **Never sign as yourself, never write a `Signed-off-by:` line by hand, and never put anyone else's name on one.**
- **Name yourself** in an `Assisted-by:` or `Co-Authored-By:` trailer.
- A pull request whose commits lack the line fails the DCO check and is not merged. `CONTRIBUTING.md` has the commands that add it to commits already made.

## What goes here, and what never does

- **Here:** the server's code, its tests and its design docs (`README.md` has the table).
- 🛑 **Never here:** a secret; a hostname, address, account id or resource name of any deployment; what a deployment costs or how its limits are set; anyone's private words. A deployment's notes belong to its operator.
- 🛑 **No client code here, and the client imports nothing from here.** The client is Apache-2.0 in [irongall-client](https://github.com/IronGall-dev/irongall-client); this repo imports its `protocol/` and `sshsig/`. Code moves from the client to the server and never back.
- **The specification is `PROTOCOL.md` in the client repo**, and every `PROTOCOL.md §N` here means that file. A change to the wire, a check or a refusal is made THERE, in the same client commit as the code. How this server does it goes in `PROTOCOL-SERVER.md` or `ARCHITECTURE.md`.
- 🛑 **A setting's VALUE goes in no doc:** name the flag (`irongalld serve -h` reads it).
- 🛑 **`CRYPTO-ANALYSIS.md` changes in the same pass as any protocol change.**
- **No comparison tables here.** The one comparison doc is `PRECEDENTS.md` in the client repo: point there.
- **The only page outside `/v1/` is `/to/<address>`,** the page a box's link opens (`internal/server/link.go`). A site's other pages are served by whatever stands in front.

## Before every push

- `gofmt -l .` (empty), `go vet ./...`, `go test ./...`, and `golangci-lint` with the client repo's flags (its `AGENTS.md`), clean outside `_test.go`.
- `go.mod` replaces the client with `../irongall-client`: the build and the tests need that checkout beside this one.
- After a change to a handler or a store: `test/interop.sh`, and the tests on AWS. They run on the in-memory store unless `IRONGALL_TEST_BOXES_TABLE`, `IRONGALL_TEST_MSGS_TABLE`, `IRONGALL_TEST_ACCOUNTS_TABLE` and `IRONGALL_TEST_BUCKET` are all set, which runs every test on DynamoDB and S3 Express plus the AWS-only ones (the crash between each pair of writes, two processes, restart). 🛑 Name tables and a bucket kept for tests, never a running server's.
- A test of client behaviour belongs in the client repo, where the forging-server tests are. This repo tests what the real server enforces.
- There is no CI.

## The maintainers' own commits

On a pull request the DCO app checks every commit, and `main` requires its check. 🛑 A direct push by an org admin bypasses that rule and nothing checks it: the sign-off there is on whoever pushes. The maintainer's commits are written with Custos, his AI assistant: they carry his sign-off, by his standing word to it, and name Custos in `Co-Authored-By:`. 🛑 That is his arrangement with his own assistant. A contributor's commits are theirs, with their own sign-off (above).

## Invariants — they hold from the first line of code

- 🛑 **The server never holds a box's private key and never sees plaintext.** A server feature that needs either is wrong. (The echo box, `PROTOCOL.md` §10, is a separate CLIENT process with its own keys.)
- 🛑 **No anonymous sends:** every message is authenticated as a REGISTERED address.
- **The address is the SHA-256 of the identity alone. The identity certifies a WORKING KEY, and signs nothing else but a revocation; mail is encrypted to an age PREKEY the working key signs.** Every renewal is a new key: the server refuses one that comes back.
- 🛑 **The server holds no signature on a message, and issues no credential.** A message's signature is inside the ciphertext, and a box proves itself with a pass it signs, which says who is calling and nothing of what a call does (`PROTOCOL.md` §4.4, §6.1b). A server feature that needs a sender's signature over a message, or a secret the server hands a box, is wrong.
- **Well-defined, RECOMMENDED crypto only:** native age to encrypt, a SEPARATE Ed25519 key to sign. No home-rolled constructions, and no key used for both. An identity may be of another key type the protocol defines (`PROTOCOL.md` §2: today P-256, optional); the working key that signs what a box says is Ed25519.
- 🛑 **A new pass is checked in three steps, in this order** (`checkPass`; `PROTOCOL-SERVER.md` §6.1b): the certificate it carries against the hash of the box's current one, the working key's signature, then the identity's signature on the certificate with every rule of a certificate. The first two refuse a pass that is not the box's for one signature check at most. The third is a second check of what a registration checked, and it stays: do not drop it to save its cost, and do not move it ahead of the other two.
- 🛑 **Keyed hashing is HMAC or HKDF only, never `hash(secret ‖ …)`.**
- **Go. Every API path under `/v1/`.**
- 🛑 **INDUSTRY-standard API shapes, never something clever.** JSON in and out; every byte field is standard base64 of the exact file bytes (`PROTOCOL.md` §4.5).
- 🛑 **An empty poll never leaves the process:** no DynamoDB, S3 or Redis round trip. Polls × mailboxes is THE load. The rule is for the steady state; the ONE read that loads a box into a process's memory on its first use is fine.
- **Bodies are served through this server's endpoint, never by a redirect to S3.**
- **Bot-first.** Every error carries a machine code plus a `hint` naming the client command that fixes it, never a raw command line the server could alter.
- 🔑 **Pre-stable: nothing is final until v1 is declared stable.** Until then, always the CORRECT design, with no weight on backwards compatibility or on leaving the wire alone.
- 🔑 **The design priorities, in this order:** 1. the correct encryption · 2. a server that is feasible and fast, not as cheap as possible · 3. simple things simple to the user. Never offer a weaker design to save the server CPU, storage or a round trip: state the measured cost beside the correct design.
- 🛑 **The protocol is designed against a server that may be hostile and a network that TLS to that server protects.** Never against whatever proxy or CDN stands in front: it may be named as what it is, never given as a reason for a design.
- 🛑 **Design for a current client;** an old tool version is never a constraint.
- 🛑 **No invented requirements.** Every limit, margin and constraint traces to a stated need or a measurement.
- 🛑 **The store is designed for provisioned DynamoDB capacity, never on-demand:** any burst read must fit it, which is why memory loads per box on first use and never by a full Scan (`ARCHITECTURE.md` § Startup).
- 🛑 **Clocks are assumed synced (NTP).** No check carries a clock-skew allowance.
- **`[proposed]` in `PROTOCOL.md` is not decided.** Build only what is decided.

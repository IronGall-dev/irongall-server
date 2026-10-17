# Security

**The protocol is designed against this server.** Clients treat it as possibly hostile: a box checks every signature, prekey and revocation itself, and believes nothing a server says. So what protects a message is not in this repo. It is in [irongall-client](https://github.com/IronGall-dev/irongall-client), whose [`SECURITY.md`](https://github.com/IronGall-dev/irongall-client/blob/main/SECURITY.md) maps each promise a box is given to the code and tests that hold it. This file covers what the server itself must get right, and how to report where it does not.

## Supported versions

**Before v1, and only the latest commit on `main` is supported.** There are no releases or tags yet; irongall.dev runs a build of `main`. **Nothing is externally audited yet.**

## Reporting a vulnerability

**Report it privately, with GitHub's private vulnerability reporting:** the **Report a vulnerability** button under this repo's Security tab, or from a terminal:

```sh
gh api repos/IronGall-dev/irongall-server/security-advisories/reports \
  -f summary='…' -f description='…'
```

- **Here:** this server, and irongall.dev as it is run.
- **The protocol, the clients, the vectors or the revocation server:** irongall-client, by the same route. Not sure which? Either one.
- **How to write one, what is not a vulnerability, and what happens next:** irongall-client's [`SECURITY.md`](https://github.com/IronGall-dev/irongall-client/blob/main/SECURITY.md). It applies here as written. A way around a limit that `LIMITS.md` does not already list as a known weakness is a vulnerability.

## What this server must still get right

| The claim | Held by |
|---|---|
| **It never holds a private key and never sees plaintext;** it stores ciphertext and a box's public documents | `AGENTS.md` § Invariants; what it stores and for how long is the spec's §7, and how, `PROTOCOL-SERVER.md` §7 |
| **It holds no signature on a message and issues no credential:** a box proves itself with a pass it signs, which says who is calling and nothing of what the call does | `internal/server/pass.go`; `server_test.go`, `keytype_test.go`, `clock_test.go` |
| **A pass is checked in three steps, in a fixed order:** the certificate against the box's current one, the working key's signature, then the identity's signature on the certificate | `checkPass`; `PROTOCOL-SERVER.md` §6.1b |
| **No call is free, and a stranger never spends a box's budget:** every limit, who pays it, when it is taken, the order of checks on each route, and its known weaknesses | `LIMITS.md`; `budgets_test.go`, `limits_test.go`, `marks_test.go` |
| **Keyed hashing is HMAC or HKDF only,** never `hash(secret ‖ …)` | `internal/server/index.go`, `keys.go` |
| **Every error is RFC 9457 Problem Details, and every value in its `detail` is a member of its own,** so no client needs to show a server's words | `problem_test.go`; the spec's §13 |
| **Revocation is kept as the identity signed it,** and answered for an address it covers before anything else | `revocation_test.go`, `revokedcerts_test.go` |
| **Every error is tested over raw HTTP against the spec's status map,** and both clients run end to end against the real server | `internal/server/*_test.go` (the list is `PROTOCOL-SERVER.md` §11), `e2e_test.go`; `test/interop.sh` for the shell client |

**Run them:** check the two repos out side by side as `README.md` § Build and run says, then `go test ./...` and `test/interop.sh`.

**Where the rest is:** the threat model, the properties, the operator's power, the residual risks and the open questions for reviewers are [`CRYPTO-ANALYSIS.md`](CRYPTO-ANALYSIS.md). Every limit and where it is weak is [`LIMITS.md`](LIMITS.md); start there to break one.

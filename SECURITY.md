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
- **The protocol, the clients or the vectors:** irongall-client, by the same route. Not sure which? Either one.
- **How to write one, what is not a vulnerability, and what happens next:** irongall-client's [`SECURITY.md`](https://github.com/IronGall-dev/irongall-client/blob/main/SECURITY.md). It applies here as written. A way around a limit that `LIMITS.md` does not already list as a known weakness is a vulnerability.

## What this server must still get right

| The claim | Held by |
|---|---|
| **It never holds a private key and never sees plaintext;** it stores ciphertext and a box's public documents | `AGENTS.md` § Invariants; what it stores and for how long is the spec's §7, and how, `PROTOCOL-SERVER.md` §7 |
| **It holds no signature on a message and issues no credential:** a box proves itself with a pass it signs, which says who is calling and nothing of what the call does | `internal/server/pass.go`; `server_test.go`, `keytype_test.go`, `clock_test.go` |
| **A pass is checked in three steps, in a fixed order:** the certificate against the box's current one, the working key's signature, then the identity's signature on the certificate | `checkPass`; `PROTOCOL-SERVER.md` §6.1b |
| **A pass is taken only for a name of the server's own,** the request's `Host` written as an origin is, and a call with two `Authorization` lines carries none | `serverName` and `authorization` in `internal/server/pass.go`; `TestAPassIsForOneServer`, `TestTheServerReadsItsHostAsAnOrigin`, `TestTwoAuthorizationLinesAreNoPass` |
| **A pass is remembered by the one form a client writes it, its signature as a verifier reads it,** so the same pass written in another form the server reads, its signature's armor and SSHSIG blob included, costs no second signature check, and is taken from memory past its address's count | `passCheck` in `internal/server/pass.go`, `protocol.Pass.Authorization`; `TestMissesPerIP`, `TestARespelledPassCostsNoSecondCheck` |
| **`If-None-Match` names a page only by that page's own tag, or by `*` as the whole value,** read as RFC 9110 §13.1.2 has a server evaluate it, so a tag that holds a comma or a `*`, which a box may be handed and keep, makes no other page `304` | `writeList` in `internal/server/messages.go`, `protocol.IfNoneMatch`; `TestAFirstPageIsNotModifiedWhileUnchanged`, `TestAPlantedTagHidesNoMailAtAnHonestServer`, `TestAMailHiddenByAPlantedTagIsNotLost` |
| **Every request is counted before anything is done for it:** each handler is put on its router through one gate, where a call that is not its box's (a pass this process has checked, of a box live in its memory, on a route that takes that box's pass) spends its address's flood budget, so a new pass is parsed and its signatures checked only after a count; and a request's head is read only to what the longest call needs | `mount`, `gate` and `HTTPServer` in `internal/server/server.go`; `TestEveryRequestIsCountedBeforeAnythingIsDone`, `TestAServerNotReadyCountsFirst`, `TestOptionsStarIsCounted`, `TestANewPassSpendsItsAddresssFloodBudget`, `TestTheHeadIsReadToWhatTheLongestCallNeeds` |
| **No call that costs the server is free, and a stranger never spends a box's budget:** every limit, who pays it, when it is taken, the order of checks on each route, and its known weaknesses | `LIMITS.md`; `budgets_test.go`, `quotas_test.go`, `limits_test.go`, `marks_test.go` |
| **The operator's commands are reached only through a Unix socket the server makes 0600 from its bind on, whatever the umask, never through the API,** and nothing logs which address or box one acted on or listed | `internal/server/admin.go`, `cmd/irongalld/limits.go`, `cmd/irongalld/socket_unix.go`; `admin_test.go`, `quotas_test.go`, `cmd/irongalld/limits_test.go`, `cmd/irongalld/limits_unix_test.go` |
| **The metrics are on a listener of their own, never the API's, and carry no value a caller chose:** no address, IP, box, message id or path as sent | `internal/server/metrics.go`, `cmd/irongalld/main.go`; `metrics_test.go` (`TestMetricsCarryNoCallerValue`) |
| **No log line carries an address or a message id, and nothing a caller sends can end a line or make it longer than the quoted form of what the server serves:** each run of 64 or more hex characters in any line, a store's error included, is written as a short hash of itself; a path is quoted, and a method or a path longer than the longest path the server serves is written as its length | `redact`, `Redacting` and `asSent` in `internal/server/server.go`, `cmd/irongalld/main.go`; `TestNoLogLineCarriesAnAddress`, `TestTheAccessLogWritesWhatACallerSentAsOneLine` |
| **Keyed hashing is HMAC or HKDF only,** never `hash(secret ‖ …)` | `internal/server/index.go` |
| **An adopt key is kept only as its SHA-256,** so a copy of the accounts table holds no key, and one that is not this server's is refused before anything is written | `internal/server/adoptkey.go`, `accounts.go`, `dynamo_accounts.go`; `TestAnAdoptKeyIsKeptAsItsHash`, `TestAccounts` |
| **Every error is RFC 9457 Problem Details, its `type` its code's own, and every value in its `detail` is a member of its own,** so no client needs to show a server's words | `problem_test.go`; `api/apitest`, which every test server is wrapped in, fails a `type` that is not its `code`'s; the spec's §13 |
| **Nothing that puts what a sender chose beside a box's own values is compressed,** a list above all (BREACH): only a box's read, which is public, and a site's text are gzipped, and only for a request that takes gzip | `internal/server/compress.go`; `TestNoOtherAnswerIsGzipped`, `TestABoxsReadIsGzippedWhenTaken`, `TestASitesTextIsGzippedOnce`; `api/apitest` fails gzip on an answer the API's description does not let a server compress, or to a request that did not take it |
| **Revocation is kept as the identity signed it, box or none,** and answered for an address it covers before anything else; a registration is held to it | `revocation_test.go`, `revokedcerts_test.go`, `expiry_test.go` |
| **Every error is tested over raw HTTP against the spec's status map,** and both clients run end to end against the real server | `internal/server/*_test.go` (`PROTOCOL-SERVER.md` §11), `e2e_test.go`; `test/interop.sh` for the shell client |

**Run them:** `README.md` § Build and run.

**Where the rest is:** the threat model, the properties, the operator's power, the residual risks and the open questions for reviewers are [`CRYPTO-ANALYSIS.md`](CRYPTO-ANALYSIS.md). Every limit and where it is weak is [`LIMITS.md`](LIMITS.md); start there to break one.

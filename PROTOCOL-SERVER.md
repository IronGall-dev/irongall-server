# PROTOCOL-SERVER — what this server does behind the spec

**The protocol's specification is [`PROTOCOL.md`](https://github.com/IronGall-dev/irongall-client/blob/main/PROTOCOL.md) in the client repo:** the wire, the checks and the refusals, as a client meets them. Every `PROTOCOL.md §N` in this repo's docs and code means that file. **This file holds how this server does each step** (storage, memory, measurements), under the spec's own section numbers. Read the spec's section first: a line here is a note beside it, not the whole of it.

**A change to the wire or to what a client meets is made in `PROTOCOL.md`, with the client code;** a change to how this server does it is made here.

## §0a, Terms

- **Reserved:** an `irongall-v2` identity line for a post-quantum signature key (OpenSSH 10.6's `ssh-mldsa44-ed25519`, 2026-10-06). Nothing is built.
- **Address / `H`:** the box identity — the SHA-256 of its identity document (§2). As text, 64 lowercase hex characters; inside MACs and DynamoDB keys, the 32 raw bytes. `H_A` is the sender, `H_B` the recipient. **One identity key ⇔ exactly one address.**
- **Header:** three different things. The **header item** is the per-message DynamoDB item (§7); the **age header** is the text head of an age file (§4.3); **HTTP headers** are HTTP headers.
- **The live prekey** is the current one: the server checks a message's stanza TYPE against its type (§4 step 5). The server keeps the newest retired prekeys' key hashes (`-retired-kept` of them, a service limit) only to refuse a key that comes back.

## §3. Registration: steps 7, 9 and 10 as this server does them

7. **A new box:** DynamoDB `PutItem` of the box item with **`state: pending`**, epoch 0, condition `attribute_not_exists(PK)` → `201` with the token.
9. **Activation.** The box turns `active` on its FIRST Bearer-authenticated call: using the token proves the registrant decrypted it, so it holds the prekey. Pending boxes are in the in-memory state, so that one call LEAVES THE PROCESS once to write `state: active`. Until then, sends TO it get `no_such_mailbox` ("not activated yet — the owner must poll once"), and sends FROM it get `unknown_sender`.
10. **Pending boxes are to expire: NOT BUILT.** As specified, a never-activated new box is deleted (it holds no mail and epoch 0), and a REOPENED box goes back to `closed`, keeping its epoch. Today a pending box stays until it is activated or closed.

## §4.3a. Padding: the size limits are checked by hand

- **The server does nothing, and a size limit must be a whole number of its own blocks.** As sizes go, 64 KiB and 10 MiB are such numbers and 100 KiB is not: a message just under a limit like that one would be padded past it. With limits chosen that way a client never needs to know the limit: what padding costs there is the member's 9 bytes. 🛑 Nothing checks this when `irongalld` starts: check `-max-size` and `-account-max-size` by hand before changing either.

## §4. The send pipeline: steps 2, 4, 6 and 9

2. `B` and `from` are 64 hex chars; `from` must be LOWERCASE (§2) → `bad_address`, hint "lowercase". `prekey_serial` is present and a serial (§2a) → `bad_request`. **Pre-auth rate: per IP only** (an edge in front may have applied its own) → `rate_limited`.
4. **Are `B` and `from` registered and ACTIVE?** An in-memory lookup, DynamoDB only on a cache miss. `B` unknown, pending or closed → `no_such_mailbox`; `B` revoked → `revoked`; **`B`'s current prekey past its `not_after` → `prekey_expired`**. `from` unknown, pending or closed → `unknown_sender`; `from` revoked → `sender_revoked` (never `revoked`, which would tell a sender its PEER is dead).
6. Verify the SSHSIG against the sender's **REGISTERED identity** key — the key inside the blob must equal it — with namespace `irongall-msg-v1:<B>`, hash per §0. ~71 µs of CPU (measured) → `bad_signature`.
9. **Write, body first** (§7): S3 `PUT` the body, then the message item, conditional on no live item with this id. Two plain writes, not a transaction.
   - If the condition fails, a concurrent send of the same ciphertext got there first. Answer as step 7 does.
   - Any other failure answers 5xx. The client keeps the message in its outbox and retries; the retry writes both again.
   - Then update memory (counts, the sender's daily count) and answer `201`.

## §5.1 and §5.7. Polls, pages and repeat fetches

- **`poll_after`** is the server's poll interval in seconds, `-poll-after` (GitHub's `X-Poll-Interval`). Bots are told that interval; what is enforced is `-poll-burst` at once and one more every `-poll-refill` (§8).
- Check the token (§6.1). **The per-box poll rate applies to EVERY poll, empty ones included** — an in-memory token bucket.
- **A list with a cursor is a continuation only if the box holds mail after the cursor.** Then it takes from the box's page allowance, not its polls: two full boxes' worth of pages at once, a full box's worth back every `-poll-refill` (the time one poll takes to come back, not `poll_after`), so a drain is never refused (§8). With nothing after the cursor it is a poll: it takes from the poll rate and is answered from memory with an empty page. So a cursor is no way around the poll rate.
- **If the in-memory count is 0, answer the empty body and touch nothing else** — measured ~19 µs of server CPU per empty poll, ~97% of it HTTP.
- Otherwise the page comes from one Query of the `live` index of the messages table (an in-process listing layer is planned and not built, `ARCHITECTURE.md` § Memory) — small entries keyed by `received_at`, so the Query returns time order and the cursor is the last key (§7). Small entries, because **DynamoDB bills a Query by the full size of each item read, projection or not** (AWS docs). → `ARCHITECTURE.md` § Memory.

**5.7 Ack:** `DELETE /v1/<B>/messages/<id>` deletes the S3 body and takes the message out of the list, and the counts follow. Its item stays as the dedupe record until the TTL. **Reading does NOT delete** — delivery is at-least-once, and unacked mail expires at the TTL. **But a message is meant to be fetched once and kept by its reader**: a message's first fetch is never limited, and a fetch of one the box has fetched before takes from an allowance of `-poll-burst` at once and one more every `-poll-refill`, the box's alone and apart from its polls; past it, `429 rate_limited` with `Retry-After`. Both clients store a message and ack it at once, so they meet the allowance only after a failure. The count is kept per process and a restart forgets it. The ack answers `204 No Content`.

## §6.1 and §6.1a. The token and the server keys

- **The server keys `K_kid` are 32 random bytes each, `kid` a u8 allocated sequentially, kept in a 0600 secrets file delivered to every process.**
- **The DB holds only each box's `epoch`.** It bumps on **every prekey change** (§6.4), and is to bump on `POST …/token/rotate`, which is not built, so a token is bound to the prekey it was encrypted to, and a box that renews as required never holds a token older than 33 days. A box that stops renewing keeps its token, so its owner calls keep working (§6.4). Memory holds the state of every box a process has used, read on its first use — so a revoked box's tokens fail from memory.
- **Validation:** decode, look up `K_kid`, recompute, compare in constant time, check `epoch` against the box's current one. ~0.31 µs measured.
- **`POST /v1/<addr>/token`** is unauthenticated and returns the CURRENT token, age-encrypted to the box's current prekey. Calling it is useless to anyone but the owner, and it never rotates anything. **Its rate limit is per IP, never per box** (`-tokens-per-minute`, off unless set): a per-box limit would let anyone holding the address lock the owner out of refresh. The encrypted token is cached per **(box, kid, epoch, prekey serial)**, so a repeat call is a memory lookup.
- 🔴 **Server-key rotation, the next two items, is specified and NOT BUILT** (the client repo's issue #24). Today the keys file mints with its highest key id and accepts a token under any key it holds; a token under a key it no longer holds is `401 unauthorized`, and no response carries an `irongall-token` header. The owner token itself is to go (the client repo's issue #36), and this with it.
- **Routine server-key rotation is to be soft.** Tokens carry a key id (`kid`, format in §6.1).
  1. Every process first learns the new key as verify-only.
  2. Only then does it start minting with it — two phases, so behind an NLB no process rejects a token another one minted.
  3. During the grace window, ANY Bearer-authenticated call presenting an old-kid token still succeeds, and **the response carries the new token in an `irongall-token` header, age-encrypted to the box's current prekey** — a piggybacked refresh, no extra round trip and no herd. The header value is standard base64 of the binary age file. One age encryption costs 152–164 µs for a PQ prekey (measured), ~2 X25519 operations for a `--no-pq` one; the result is cached per (box, kid, epoch, prekey serial). **This is the one poll that leaves the process** — once per box, to load its prekey. The grace window is a tunable.
  4. Clients that ignore the header hit `token_stale` when the grace window ends, and follow the one-line rule.
- **Server-key COMPROMISE is to be a hard cut.** The leaked key could forge any box's token, so there is no grace window: old-kid tokens get `token_stale` immediately, and everyone re-fetches via `/token`. That is the herd case — `/token` answers from the cached encrypted token or the box's cached prekey, with no DB write, and its limit is per IP, so a herd of boxes is not throttled by one another.
- **Multi-process:** an epoch bump must reach every process, through the DynamoDB stream every process follows (`ARCHITECTURE.md`; ~1–2 s). Until it does, a process with a stale epoch still accepts the old token — bounded by propagation delay, and stated rather than hidden.

## §6.4. Renewal: the two service limits

- **The server** verifies the statement against the identity (§3 steps 4–5), requires `serial` > the current one, and **refuses a key equal to the current one or to any live retired one** (`bad_key`: "every prekey must be a NEW key"). The new prekey becomes current, **the epoch bumps**, and the answer is `200` with the new token encrypted to the NEW prekey. A closed box reopens as `pending` (§3a). **A box renews at most `-renewals-per-day` times a UTC day** (`RenewalsPerDay`, a service limit: each renewal is a write to the boxes table, whose capacity every box shares), then `429 rate_limited` until the next day; an identical retry is not a renewal. **The record keeps its `-retired-kept` newest retired prekeys** (`RetiredKept`, a service limit), each until its `not_after`, so a box that renews often cannot grow it.

## §6.5. Accounts

- **`DELETE /v1/<A>/account`** (Bearer) → `204`, in an account or not. `irongall adopt --leave`. An account drops a box the same way from its side (the operator's `irongalld account drop`, until accounts have users).
- **The adopt key** is computed, as the token is (§6.1): `K = "iga1_" + base64url(kid ‖ id ‖ n ‖ account ‖ mac)`, no padding, with `id` 16 random bytes, `n` the account id's length (a u8) and `mac = HMAC-SHA-256(K_kid, "irongall-adopt-v1" ‖ kid ‖ id ‖ n ‖ account)`. The account's table holds only the key's uses left and its expiry. A key that is not ours, spent, expired or deleted (revoked) is `403 adopt_key_refused`.
- **What an account changes:** an unmetered account's boxes (the echo account) have no daily send limit and the largest cap (`-account-max-size`), and are never charged. Until credit is built, a metered account's boxes have the free limits. Over the largest cap, a send is refused before anything else is read.

## §7. Storage

**Three DynamoDB tables, one kind of thing each: boxes (`-boxes-table`), messages (`-msgs-table`) and accounts (`-accounts-table`).** A mail flood cannot throttle registration or rekey, boxes are backed up and mail is not, and each table's stream feeds its own cache.

| Where | Key | Holds | Expiry |
|---|---|---|---|
| the boxes table | `addr` = `H_B` (32 B binary), `sk` = `0x00` | box: identity (Ed25519 pk), state (pending / active / closed / revoked), the current prekey statement + signature, the `-retired-kept` newest retired prekeys' type, `not_after` and key hash (for the new-key rule), epoch (never reset), `rev` (`ARCHITECTURE.md`), created, `account` (the account it is in, if any). Reserved and not written: warmup_until, profile + sig, allow, block | none (a short TTL on a new pending box is planned, not built) |
| the accounts table | `account` = the account id's bytes, `sk` = `0x00` | the account: `unmetered`, `rev` | none |
| the accounts table | `account`, `sk` = `0x01` ‖ `H_B` | a box the account holds: the mirror of the box record's `account`, written with it in one transaction | none |
| the accounts table | `account`, `sk` = `0x04` ‖ key id | an adopt key: `uses` left, `expires` (ms); no secret | TTL on `expires_at` |
| the boxes table | `addr` = `H_B`, `sk` ≠ `0x00` | reserved for the box's own items (allow/block entries one item each, so no list grows toward DynamoDB's 400 KB item limit); none yet | as the box |
| the messages table | `box` = `H_B`, `id` = SHA-256 of the ciphertext | one item per message, its header and its dedupe record: `from` (`H_A`), size, received_at (ms), expires_at, **signature (~400 B)**, and **`live` = received_at (ms, u64 big-endian) ‖ id while unacked** | TTL on expires_at — the item outlives an ack |
| its LSI `live` | `box`, `live` | the unacked messages only (an item without `live` is not in it), oldest first, with `from` and size: the list's cursor is the last `live` | with the item |
| S3 Express One Zone (a directory bucket in the server's AZ) | `<hex H_B>/<hex id>` | the binary age ciphertext, exactly as decoded from the send | a lifecycle rule of at least the 33-day TTL, which needs the bucket policy below |

Boxes: PITR on, AWS Backup on, stream `NEW_IMAGE`. Messages: neither backup, TTL on, stream `NEW_IMAGE`. Accounts: PITR on, AWS Backup on (billing data), TTL on, stream `NEW_IMAGE`. Every key is binary.

- **Send** (§4 steps 7 and 9). READ the item `box, id` first: a retry gets `200` and the original receipt, before any quota. Then two plain writes, never a transaction:
  1. S3 `PUT` of the body;
  2. the message item, with the condition `attribute_not_exists(id) OR received_at <= now − TTL` (an expired item the TTL has not yet deleted is replaced).
  - **The key is content-addressed (`id = SHA-256(ciphertext)`), so a duplicate S3 PUT rewrites identical bytes — harmless.**
  - A crash after the S3 PUT leaves an orphan object, which the lifecycle rule reaps. That is normal. The sender got no `201`, so it retries, and the retry writes both.
  - **The header and the dedupe record are one item, so they cannot disagree:** every `200` and `201` means the message was stored. This replaced an earlier layout of three writes and the repair a retry needed when a crash fell between the dedupe record and the header (2026-10-11).
  - **A hit from ANOTHER `from` is answered `409`.** A `409` claims no delivery.
- **Cost per message:** one S3 Express PUT; the send's item write is 2 write units (the item, under 1 KB, and its LSI entry), the ack's 2 more (the update and the LSI entry's removal), and the dedupe read 1 read. The old layout wrote 3 units per message (dedupe record, header, then the header's delete): the LSI adds about $0.63 per million messages, at the on-demand price in AWS's offer file of 2026-09-11.
- **A box's item collection is capped at 10 GB** (every LSI's rule: its items and their index entries). An acked message's item is ~190 B for 33 days, so the cap is ~50 M messages per box per 33 days; a write past it fails with `ItemCollectionSizeLimitExceededException`. The per-sender limits put that out of reach.
- **Read:** the list Queries the LSI over the live key range (received_at > now − 33 days). `GET …/messages/<id>` reads the item by its key, and the S3 object through our endpoint — never a redirect — and returns the body base64 in JSON, alongside the signature from the item.
  - **A live item whose body is gone leaves the list, and is answered `no_such_message`.** This covers a half-finished ack, and a body that S3's lifecycle removed early (the timing on directory buckets was not checked).
  - **These reads are eventually consistent** (`ARCHITECTURE.md` § Memory): the conditional writes keep the data right, and a stale read costs a retry or one poll.
- **Ack:** delete the S3 object, then remove `live` and the signature from the item, with the condition that it is live and unexpired (otherwise `404`). Both steps are safe to repeat: a crash between them leaves a listed message with no body, which the client's next ack, or any fetch, takes out of the list. The item stays as the dedupe record until its TTL, so the server's dedupe spans the TTL even after an ack. **Close** does the same for every live message in the box.
- **The item's `expires_at` is the authority on expiry.** Lifecycle expiry is not exact: general purpose buckets round to the next midnight UTC, and the timing on directory buckets was not checked. So an object can outlive its item, and reads never serve a body whose item is gone.
- 🔴 **Lifecycle on a directory bucket needs a bucket policy** granting `lifecycle.s3.amazonaws.com` `s3express:CreateSession` with `s3express:SessionMode` = `ReadWrite`. Without it, nothing expires (AWS docs, *Working with S3 Lifecycle for directory buckets*). The server also reaches objects through `s3express:CreateSession`, not `s3:PutObject`.
- **Count cache:** in each process's memory, one mark per live message (id, sender, expiry, and how often this process served it), so counts stay exact without drift (`ARCHITECTURE.md` § Memory). Redis is penciled in for later. **A box's marks load on its first use by a process**, from a strongly consistent Query of the LSI, with its record — a box memory does not hold is never read as empty.

## §8. Abuse levers

The structure is decided, and not all of it is built: each item says so. Each number that exists is a flag of `irongalld serve` (`-h` reads them).
1. **Address secrecy** — the primary defence.
2. **Per-IP limits** in the app, and at an edge in front where there is one, keyed by IPv4 address or **IPv6 /64** (a /56 tier is not built): every IPv6 end site holds at least a /64, so a per-address limit means nothing there.
3. **Sends per sender per day.** Counted in each process today; to be global across processes, counted from the DynamoDB stream, when there is more than one (`ARCHITECTURE.md` § Limits). **Warm-up**, lower limits for a new box's first period, is not built. **This is the paid-tier lever**: an account lifts it for its boxes (§6.5; today only an unmetered account does, since credit is not built).
4. Unacked cap per (sender → box), and a large per-box total, both global.
5. **Registrations per IPv4 address or IPv6 /64**, plus **proof-of-work at registration, specified and NOT BUILT** — find a `nonce` with `SHA-256("irongall-pow-v1" ‖ H ‖ UTC date ‖ nonce)` having `k` leading zero bits. It is bound to the address, so a solution cannot be reused, and it costs client CPU only. It is meant to be off until an attack and raised then. Its wire format is open (§12).
6. **Polls: a burst per box (`-poll-burst`), one more every `-poll-refill`, and `-poll-after` stated**: bursts and manual polls fit, and nothing faster than once a minute lasts. **A list without a cursor is a poll**; a later page is a continuation, so a box holding more than 50 messages drains within the limit. **Since 2026-10-11 a continuation must have mail after its cursor, or it is a poll too, and it has an allowance of its own** (§5.1), set by the box cap and `-poll-refill`, not by a number of its own.
   - **A read of the boxes table that finds no box is counted per IPv4 address or IPv6 /64** (`-misses-per-minute`). The calls that can make one: `/identity`, `/token`, a prekey, a send's recipient or sender, and an owner call without a token this server minted. **What memory holds is answered at once, never refused and never counted:** a box's record, and for 30 s a box a read did not find. **Past the count, a call from that address that needs the read gets `429 rate_limited` before it.** So a box that exists is never a miss, and it is refused only when this process does not hold its record and the caller is already past its count. No caller is exempt. An owner call with a token this server minted names a box that was registered, so reading it is none of this, a pending box's first call included.
   - **A fetch or an ack of an id the box does not hold is `404 no_such_message` from memory**, so only a message that is there reads or writes storage. A held message's first fetch is not limited; a repeat takes from the box's allowance (§5.7).
7. Metadata-only listings. Recipient `allow`/`block` lists (`block` wins) are specified and not built.
8. The volume paywall: accounts (§6.5).

## §10. The echo box

- **Its identity key is kept and backed up** (identity keys may be), since losing it means a new address in every published place. **Its prekeys live in memory only** (a tmpfs), and it renews at every start: renewal needs only the identity (§6.4), and no prekey reaches a snapshot or backup.
- **No reply limit of its own**: it replies once per message, and every sender's own limits bound those. Its account lifts its daily send limit (§6.5); the server has no special case for it. ⚠ The per-IP pre-auth send rate (`-sends-per-minute-per-ip`, off by default) would count its replies too.

## §11. Tested: what ran here

- The `base64` that ran is the uutils coreutils one; Go's `encoding/base64` decodes wrapped base64 exactly (`bench/crypto/base64_test.go`). The µs figures re-run from `bench/`.

✅ **Against a real server, 2026-10-10:** `test/interop.sh` runs `irongall.sh` with its real `ig_api` (curl) against `irongalld serve --dev` with the Go client on the other side: mail both ways, across renewals, and one box run by both clients. **All PASS in BOTH modes, last on 2026-10-12 with post-quantum script boxes** (its last line prints the count) (`--no-pq` with apt age 1.2.1, post-quantum with age 1.3.2). The server's own tests (`internal/server/`) cover problem+json bodies against §13, the HMAC token, the per-IP `/token` and send limits, close and reopen, the stanza parser and grease, a type switch at renewal, and ETags. The tests of a client against a forging operator are in the client repo.

## §12. Not yet specified: the items that are this server's alone

- **Edge caching of `/identity`:** a SHORT Cloudflare TTL, so a new prekey propagates quickly (a stale one costs senders a `409 stale_prekey` retry); purge on renewal, close and revocation.
- **Legal posture** of an operator that holds only ciphertext.

## §13. 503 and logging

- **503** `unavailable`, with `Retry-After`: a process that cannot prove it is current with the change stream stops answering rather than answer wrong (`ARCHITECTURE.md`).
- **Logging**: the access log never carries a full address — hash it (e.g. the first 16 hex of SHA-256 of the address) or redact it. Bearer tokens and request bodies are never logged. A proxy or CDN in front (Cloudflare, for irongall.dev) DOES see addresses in URLs, in its own logs; revocation (§6.3) is the remedy for a leak. Pasting a share URL into a hosted chat also leaks it, to transcripts and link unfurlers.

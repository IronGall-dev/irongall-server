# LIMITS — what this server limits, why, and where it is weak

Every limit `irongalld` enforces, what it protects, who pays for it, when it is taken, and what is known not to hold. It is here to be checked: if you find a way around one, or a cost one does not bound, open an issue.

**These are this server's limits, not the protocol's.** The specification (`PROTOCOL.md` §8, in the client repo) says what a client must handle: a `429` with `Retry-After`, a few codes, and the promises every server keeps. How much, and of what, is each server's own choice; another server may limit differently. The reference clients obey whatever a server answers. **No value is written here:** each limit is a flag of `irongalld serve`, and `irongalld serve -h` prints its default.

## The rule

1. **No call is free.** Memory is cheap and the tables are not, but bandwidth can cost more than either, and a call that is cheap once can take a server down in volume. So every call spends from a budget: a successful poll is limited for the bytes it moves, not for what it reads.
2. **Who pays is who the call proves itself to be.** A call with a box's pass is the box's. New mail is its recipient's too. A call with no pass, or a check that fails, is its IPv4 address's or IPv6 /64's: every IPv6 end site holds at least a /64.
3. **Cheapest check first, and what would change nothing is answered before what costs**: an identical retry, a statement no higher than the one held, anything for a revoked box.
4. **A count is reserved before the work it guards, and kept or given back after.** One checked first and counted after lets calls in flight at once all pass on one count. Where only the outcome says whether a call counts (a lookup that may find no box, a signature that may fail), the token is taken first and given back if the call turns out not to count; a refusal that only reservations still in flight would cause waits a moment for one to settle.
5. **A box's counts are spent only by calls that showed its pass, and by mail to it that passed every check.** A stranger never spends one before a check that could refuse it: a count of the box's that a failed call could spend would be a way to lock its owner out.
6. **What an account may lift is volume:** what a box sends, what it receives, what it takes out, how large, and its calls. Registrations, revocations, lookups with no pass and failed checks are not for sale.

## Every limit

| Limit | Flags | Paid by | What it bounds | When it is taken | Refused with |
|---|---|---|---|---|---|
| Polls | `-poll-burst`, `-poll-refill` | the box | every list without a cursor, and one whose cursor has nothing after it; an empty poll is answered from memory and still moves bytes | before the list | `429 rate_limited` |
| List pages after the first | from `-box-cap` and `-poll-refill` | the box | continuations of a drain, sized so a full box always drains. A page is a continuation only with the cursor this process handed the box last; any other cursor (made up, replayed, a retried page) is charged as a poll and answered all the same | before the page | `429 rate_limited` |
| Repeat fetches | the poll's two flags | the box | a fetch of a message the box has fetched before | before the read | `429 rate_limited` |
| New mail taken out | `-drain-burst`, `-drain-refill` | the box | its first fetch of each held message: the bodies' bandwidth, however many boxes send to it. Only the box's own calls spend it; a client stops its drain there and the rest waits | reserved before memory counts the fetch, given back if it was not a first one | `429 rate_limited` |
| Calls | `-call-burst`, `-call-refill` | the box | every call with its pass that no other budget counts: a send, a retry included; a lookup with its pass; a renewal; close, adopt, leave; a fetch or an ack of an id it does not hold. A held message's ack is paid for by its receive | after the pass, before anything else | `429 rate_limited` |
| New mail received | `-receive-burst`, `-receive-refill` | the recipient | how fast a box takes mail, however many boxes send to it | reserved before the write, given back if nothing is stored | `429 mailbox_busy` |
| Sends a day | `-sends-per-day` | the sender | volume; counted only for sends that carried the sender's pass | reserved before the write, given back if nothing is stored | `429 rate_limited` |
| Unacked per pair, per box | `-pair-cap`, `-box-cap` | the pair, the box | storage, a box's item collection and the pages of a drain | read with the sends in flight under one lock, and counted in before the write | `429 pair_full`, `429 mailbox_full` |
| Renewals a day | `-renewals-per-day` | the box | renewals under its current certificate, which a holder of its working key can make; boxes-table writes | after the statement and its pass are checked | `429 rate_limited` |
| The identity's acts a day | `-identity-acts-per-day` | the box | a renewal under a later certificate, and a raise of its revocation of certificates, which only its identity can make. The revocation of the address is never counted | after the signatures are checked | `429 rate_limited` |
| Retired prekeys kept | `-retired-kept` | the box | the size of its record | at each renewal | none: the oldest goes |
| Registrations | `-registrations-per-hour` | the address | new boxes, and the signature checks of a registration, which it is taken before | before any signature check | `429 rate_limited` |
| Calls with no pass | `-public-burst`, `-public-refill` | the address | a lookup with no pass, a registration, `PUT …/revocations`, the link page | first | `429 rate_limited` |
| Misses and failed checks | `-misses-per-minute` | the address | a read of the boxes table that finds no box; a new pass, a prekey statement or a revocation that does not verify. Lookups of one address at once share one read, counted for its caller alone | reserved before the read or the check, kept if it fails | `429 rate_limited` |
| Sends before their pass | `-sends-per-minute-per-ip` | the address | a send, before its pass is read; off unless set | first | `429 rate_limited` |
| Size | `-max-size`, `-account-max-size` | the sender | the body read, to the sender's own cap | before the body is read past it | `413 too_large` |
| One large read at a time | none | the process | memory: one body of the largest cap, plus the free-size buffers of those waiting | while a body past the free size is read; a send waits for it at most `-body-timeout` | `503 unavailable` |
| A body's and a response's time | `-body-timeout`, `-body-min-rate` | the connection | how long a body may take to arrive, and a response to be taken: the timeout, and a second more for each `-body-min-rate` bytes moved, as Apache's `RequestReadTimeout` counts. A body that stops is cut off, and gives back the large read it holds | as the bytes move | the connection is closed |
| Idle connections | `-idle-timeout` | the connection | an idle keep-alive connection; above the 60 s nginx keeps idle upstream connections, so nginx closes first | while idle | the connection is closed |

## The order of checks

- **A send** (`PROTOCOL.md` §4.5; `send.go`): the pass → the sender's calls → the body, to its cap → its form → the recipient exists and is active → the dedupe, so a retry is answered as the first send was whatever has changed since → whether the box takes new mail on this prekey from this sender → sends a day, the pair and box caps, the new mail received, each reserved → the write. The calls come before the dedupe so that the dedupe's read, which moved ahead of refusals that read nothing, is bounded.
- **A registration** (`register`): the calls with no pass → the body's form and the identity's → a box this process holds is answered from its record, unchecked but for an identical retry's pass → the registrations count → the statement's signatures and the pass, which that count bounds → the write.
- **A renewal** (`prekey`): the box's record → an identical retry, its pass checked, answered from the record → the statement's place in the order, read without verifying: not above the current one, under an older certificate, or under one its identity revoked, refused with no signature check → a miss reserved → the signatures and the pass → the box's calls → the renewal count or the identity's, by the certificate → the write.
- **A revocation** (`revoke`): the calls with no pass → the record → anything for a revoked box `410`, with no check → a revocation of certificates through a serial no higher than the one held, answered before its signature → a miss reserved → the signatures → the identity's acts, for a raise → the write.
- **A lookup** (`identity`, `revocations`): with a pass, the pass and then the box's calls; with none, the calls with no pass.
- **Any other call with a pass** (`list`, `fetch`, `ack`, close, adopt, leave): the pass, a miss reserved if the process has not seen it → the budget the call belongs to.

## Accounts: where a box's limits are read

`limitsFor` reads a box's account, from a cache, and returns its limits. Today one kind of account lifts anything: an unmetered one, whose boxes have no daily send limit, the largest size cap, and no budget of calls or of new mail, in or out. A box in no account is known to be so from memory, with nothing read.

**What is planned for paid volume, and not built:** an account carries a value for each volume lever (sends a day, calls, new mail received and taken out, the size cap) and a price; `limitsFor` applies the account's values to its box, as a sender and as a recipient; a budget other than none needs its own bucket for each set of values. Nothing else is to be sold.

## Known weaknesses: read these first

1. **Every budget and count is per process,** in memory, and so are the cursor each box was handed last and the sends in flight. With N processes a box can spend N times each, and a restart starts every box afresh (the daily counts included). Only the pair and box caps are shared, through the stream, a second or two behind. Routing each box to one process, or sharing the counts, is not built.
2. **The budget of new mail received is shared by every sender, and it is on by default.** Enough senders can spend a box's, and delay everyone else's mail to it; the mail waits in the senders' outboxes and is sent again. Every sender's own counts bound how much each spends. It is kept on, beside the budget of mail taken out that only the box spends, so the server leans to refusing a flood at the door; either can be set apart, or off. **A box whose address is published can be delayed this way by a determined enough sender: keep the address of a box you rely on private** (the specification's §8, lever 1). A box's `allow` list, not built, would let a published box take mail only from the senders it names.
3. **An address is a coarse key.** Honest boxes behind one address (a NAT, a cloud's egress) share its calls with no pass and its misses. Their calls with a pass are their own, but for two things that count against the address whatever a call carries: naming a box that does not exist, and a check that fails. A box's lookups of itself carry no pass (the specification's §4.1), so they are the address's too. An address that has spent its misses has its next new pass refused until one comes back; a pass the process has seen is unaffected.
4. **A request that matches no route** is answered by the router with no budget, as is a connection that never completes a request. A flood of those is for whatever stands in front.
5. **A pass is checked once in each process,** at two signature checks; after that it is a lookup in memory.
6. **The one large read can still be held for as long as a body takes at the minimum rate:** for a body of the largest cap, hours. Only a box whose account lifts its cap can take it, and a send waiting for it gives up after `-body-timeout`.
7. **Nothing bounds how many sends wait for the large read,** and each holds the free size it has read while it waits.

## Tested

`internal/server/budgets_test.go` holds each budget and each order above, `limits_test.go` the polls, pages, repeats and misses, `marks_test.go` the tags that memory knows messages by, `accounts_test.go` the large read, and `server_test.go` the renewals. They run on the in-memory store, and on DynamoDB with the test tables set (`AGENTS.md`).

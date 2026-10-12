# bench/ — the measurements behind the microsecond figures

First run on 2026-10-10: 2× Neoverse-V2, Go 1.26.6, standard library only, a single core where noted. **They are evidence for design decisions, not a test suite.**

| Dir | Measures | How to run |
|---|---|---|
| `crypto/` | SSHSIG verify over 16 KiB (~71 µs; a forgery costs the same), SHA-256 / de-armor (~10–12 µs), SSH tag check (~0.08 µs), owner-token HMAC check (~0.31 µs pooled), map lookup (~0.011 µs) | `cd bench/crypto && go test -bench . -benchtime 2s -count 3` |
| `crypto/base64_test.go` | **A TEST, not a benchmark:** Go's `encoding/base64` decodes 76-column-wrapped base64 (LF and CRLF) to the exact bytes, which `PROTOCOL.md` §4.5 relies on | `cd bench/crypto && go test -run TestWrappedBase64DecodesExactly -v .` |
| `poll/` | **A whole empty poll over loopback HTTP: ~19 µs of server CPU** (40,000 polls, keep-alive, 0 errors) | below |

The memory and item-size measurements are `internal/server/cost_test.go` (`IRONGALL_COST=1 go test ./internal/server -run TestCost -v`).

**Running `poll/`** (the server listens on 127.0.0.1:18777; build both into a scratch directory, here `$out`):

```sh
(cd bench/poll/srv && go build -o "$out/poll-srv" .)
(cd bench/poll/cli && go build -o "$out/poll-cli" .)
GOMAXPROCS=1 "$out/poll-srv" & SP=$!                      # the server's OWN pid
GOMAXPROCS=1 "$out/poll-cli" 2000                         # warm up
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks before (1 tick = 10 ms)
GOMAXPROCS=1 "$out/poll-cli" 40000                        # prints "requests 40000 bad 0"
awk '{print $14+$15}' /proc/$SP/stat                      # CPU ticks after → µs/poll = Δticks × 10000 / 40000
kill $SP
```

- **Two of these measure an earlier revision of the design, and are kept as the record of that measurement:** `crypto/tag_test.go` times a check of an `ssh-ed25519` recipient's tag, from when one SSH key both signed and received, and `poll/srv` answers an empty list as `[]`, where the server now answers an object.
- **SSHSIG is EMULATED** in `crypto/`: SHA-512 of the message plus an Ed25519 verify over the small signed blob, with no SSHSIG parser. A real parser adds negligible cost.
- **Stop the server by ITS pid, and run it by an absolute path.** Wrapped in `timeout` with an environment prefix, one `timeout` implementation failed to start it, and killing the wrapper orphaned the server.
- Never wrap a Go command in `ulimit -v`: the runtime reserves a large virtual arena and dies misleadingly.
- What stands in front of the server (a proxy, a tunnel, TLS termination) is not measured here, and costs more per poll than the server does.

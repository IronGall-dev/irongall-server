#!/usr/bin/env bash
# interop.sh — the stock client, sh/irongall.sh from the public irongall-client checkout beside this repo, with its real ig_api (curl),
# against a real `irongalld serve --dev`, interoperating with the Go client `irongall` from the public client repo:
#   1. mail both ways between a recipe box and a Go box, sent to each box's link, across a prekey renewal on each side; the page each link opens;
#   2. ONE box run by both clients: the Go client receives in a box the recipe made, and the recipe in one Go made;
#   3. the recipe's error path on a real problem+json body;
#   4. the envelope's optional fields, each client's sent/ record (with the real server's receipt) and aliases, across the clients;
#   5. a box whose identity is of the optional key type, in each client, and the sender key types a box declares;
#   6. a box whose clock is off from the server's;
#   7. revocation: each client revokes a box at the real server, the other checks the proof it is shown, and a record alone revokes;
#   8. certificates revoked: the Go client renews and revokes its earlier certificates, a revocation made with ssh-keygen alone, and each
#      client checking the one it is shown, refusing mail under a revoked certificate and following a box to its next one;
#   9. a revocation server beside this one, a second irongalld with no box of these, since every mailbox server is one and keeps a
#      revocation box or none: each client publishes to both, each
#      is shown by it a revocation this server was never told of, with one gone mail still goes, and a server that holds an address
#      revoked answers 410, which each client takes once what it serves verifies;
#  10. the sender ACL: a Go box's block reaches this server, which refuses the recipe box's send for good.
# Every script step runs in a FRESH shell (agents run each command in a new one). --no-pq boxes only when the local
# age is older than 1.3 (it cannot make or send to a post-quantum box); the Go client handles both either way.
# Needs: go, bash ≥ 4, age, age-keygen, ssh-keygen, curl, jq, sha256sum, base64, od. Run from anywhere:
#   test/interop.sh            SCRIPT=<path> overrides the irongall.sh it sources.
# With IRONGALL_TEST_BOXES_TABLE, IRONGALL_TEST_MSGS_TABLE, IRONGALL_TEST_ACCOUNTS_TABLE and IRONGALL_TEST_BUCKET set, the server runs on those tables and
# that bucket instead of --dev: tables and a bucket kept for tests, never the ones a running server uses.
# For post-quantum script boxes where the packaged age is older than 1.3, put age ≥ 1.3 first in PATH:
#   GOBIN=<dir> go install filippo.io/age/cmd/...@v1.3.2   (never under ulimit -v)
# The work dir is a LITERAL path, so no rm -rf ever runs on a variable. It is left in place after the run.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(dirname "$here")
SCRIPT=${SCRIPT:-$(dirname "$repo")/irongall-client/sh/irongall.sh}
rm -rf /tmp/irongall-interop; mkdir -p /tmp/irongall-interop; work=/tmp/irongall-interop
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass + 1)); }
bad(){ echo "FAIL $*"; fail=$((fail + 1)); }
trap '[ -n "${srv:-}" ] && kill "$srv" 2> /dev/null; [ -n "${rev:-}" ] && kill "$rev" 2> /dev/null; [ -n "${rev2:-}" ] && kill "$rev2" 2> /dev/null' EXIT

export PATH=$PATH:/usr/local/go/bin
# The client's commands are built in the client's own module, which lists what they import and the server's does not.
(cd "$repo" && go build -o "$work/irongalld" ./cmd/irongalld) && (cd "$(dirname "$repo")/irongall-client" && go build -o "$work/irongall" ./cmd/irongall) || { echo "build failed"; exit 1; }
[ -r "$SCRIPT" ] || { echo "no $SCRIPT"; exit 1; }
echo "stock client: $SCRIPT ($(grep -c '^ig_[a-z_]*()' "$SCRIPT") functions)"

if age-keygen -pq > /dev/null 2>&1; then kt=pq; else kt=no-pq; fi
echo "local age: $(age --version) → recipe boxes are $kt"
port=$((20000 + RANDOM % 20000))
if [ -n "${IRONGALL_TEST_MSGS_TABLE:-}" ]; then
  store=(-boxes-table "$IRONGALL_TEST_BOXES_TABLE" -msgs-table "$IRONGALL_TEST_MSGS_TABLE" -accounts-table "$IRONGALL_TEST_ACCOUNTS_TABLE" -bucket "$IRONGALL_TEST_BUCKET" -names "127.0.0.1:$port")
else
  store=(--dev)
fi
echo "server: irongalld serve ${store[*]:0:6}"
"$work/irongalld" serve "${store[@]}" -listen "127.0.0.1:$port" -poll-burst 0 -registrations-per-hour 0 2> "$work/server.log" & srv=$!   # every box here registers from one address
export IG_BASE="http://127.0.0.1:$port" IRONGALL_BASE="http://127.0.0.1:$port"
for _ in $(seq 300); do   # up once the API answers other than 503 (loading)
  code=$(curl -s -o /dev/null -w '%{http_code}' "$IG_BASE/v1/$(printf '0%.0s' $(seq 64))"); [ "$code" != 000 ] && [ "$code" != 503 ] && break; sleep 0.1
done

R="$work/r"; G="$work/g"
recipe(){ local home=$1; shift; IRONGALL_HOME=$home bash -c ". '$SCRIPT'; $*"; }   # a fresh shell per call
# The Go client holds mail from a sender its box has not allowed (PROTOCOL.md §5.6). These tests are of what the two clients
# send each other, so every box the Go client runs lands every sender's mail in inbox/, by its policy file, unless a test wrote one.
gocli(){ local home=$1; shift; mkdir -p -m 700 "$home" && { [ -e "$home/policy" ] || printf 'unknown inbox\n' > "$home/policy"; } && IRONGALL_HOME=$home "$work/irongall" "$@"; }
linkof(){ jq -er 'select(.type == "box") | .link'; }      # a box line, as init and addr print one → its link
revoked_line(){ printf '{"type":"revoked","address":"%s","message":"published to the server and to each revocation server"}' "$1"; }      # <address> → the line revocation publish prints
nopq_arg(){ [ "$kt" = no-pq ] && echo --no-pq; }
look(){ curl -s -o /dev/null -w '%{http_code}' "$IG_BASE/v1/$1"; }   # <address> → the status of a read of the box at this server: 410 once it is revoked

# --- 1. both ways, across renewals ---
ig_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
RL=$(recipe "$R" "ig_init $(nopq_arg)" | linkof) && RA=${RL##*/} && ig_hex "$RA" && [ "$RL" = "$IG_BASE/to/$RA" ] && ok "recipe init prints its link: $RL" || bad "recipe init: $RL"
GL=$(gocli "$G" init $(nopq_arg) | linkof) && GA=${GL##*/} && ig_hex "$GA" && [ "$GL" = "$IG_BASE/to/$GA" ] && ok "Go init prints its link: $GL" || bad "Go init: $GL"
for L in "$RL" "$GL"; do
  curl -sf "$L" | grep -qF "<code>${L##*/}</code>" && ok "the link opens its page: $L" || bad "no page at $L"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$IG_BASE/to/$(tr a-f A-F <<< "$GA")")" = 404 ] && ok "a link in uppercase is 404, as clients refuse it" || bad "uppercase link page"

printf 'from Go, <b>&\n' | gocli "$G" send "$RL" > /dev/null && ok "Go → recipe: sent, to the recipe box's link" || bad "Go → recipe: send"
out=$(recipe "$R" ig_recv 2> "$work/err") && jq -e --arg f "$GA" '.body == "from Go, <b>&\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "Go → recipe: delivered by ig_recv, verified" || bad "Go → recipe: ig_recv: $out $(cat "$work/err")"

printf 'from the recipe\n' > "$work/body"
recipe "$R" "ig_send $GL '$work/body'" && ok "recipe → Go: sent, to the Go box's link" || bad "recipe → Go: ig_send"
out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg f "$RA" '.body == "from the recipe\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go: delivered by irongall recv, verified" || bad "recipe → Go: recv: $out $(cat "$work/err")"

recipe "$R" "ig_rekey $(nopq_arg)" && ok "recipe: ig_rekey" || bad "recipe: ig_rekey"
gocli "$G" prekey renew > /dev/null && ok "Go: prekey renew" || bad "Go: prekey renew"
printf 'after both renewals\n' | gocli "$G" send "$RA" > /dev/null && recipe "$R" "ig_send $GA '$work/body'" && ok "both ways after renewals: sent" || bad "send after renewals"
out=$(recipe "$R" ig_recv 2>&1) && grep -q 'after both renewals' <<< "$out" && ok "recipe receives after renewals" || bad "recipe after renewals: $out"
out=$(gocli "$G" recv 2>&1) && grep -q 'from the recipe' <<< "$out" && ok "Go receives after renewals" || bad "Go after renewals: $out"

# --- 2. one box, both clients ---
printf 'into the recipe box\n' | gocli "$G" send "$RA" > /dev/null || bad "send into the recipe's box"
out=$(gocli "$R" recv 2>&1) && grep -q 'into the recipe box' <<< "$out" && ok "the Go client receives in a box the recipe made" || bad "Go in the recipe's box: $out"
[ "$(gocli "$R" addr | linkof)" = "$RL" ] && [ "$(recipe "$G" ig_addr | linkof)" = "$GL" ] && ok "each client prints the other's box's link" || bad "addr across clients"
recipe "$R" "ig_send $GA '$work/body'" || bad "send into the Go box"
out=$(recipe "$G" ig_recv 2>&1) && grep -q 'from the recipe' <<< "$out" && ok "the recipe receives in a box Go made" || bad "recipe in Go's box: $out"
gocli "$R" prekey renew > /dev/null && recipe "$R" "ig_send $GA '$work/body'" && out=$(recipe "$G" ig_recv 2>&1) && grep -q 'from the recipe' <<< "$out" \
  && ok "the recipe's box renewed by Go, then used by the recipe" || bad "Go prekey renew of the recipe's box: $out"

# --- 3. the recipe's error path on a real problem+json ---
nobody=$(printf '%064d' 0)
err=$(recipe "$R" "ig_send $nobody '$work/body'" 2>&1); rc=$?
[ $rc -ne 0 ] && grep -qxF '{"type":"error","status":404,"code":"no_such_mailbox","message":"ERROR 404 no_such_mailbox"}' <<< "$err" && ! grep -q 'no box has this address' <<< "$err" && ok "recipe prints a real problem's status and code, and none of the server's words (PROTOCOL.md §13)" || bad "recipe error path: rc=$rc $err"

# --- 4. the optional fields, sent/ and aliases, across the clients ---
recipe "$R" "ig_alias go $GL" > /dev/null && [ "$(gocli "$R" alias list | jq -r '"\(.type) \(.name) \(.address)"')" = "alias go $GA" ] && ok "an alias the recipe made is read by the Go client" || bad "the recipe's alias in the Go client"
gocli "$G" alias add sh "$RL" > /dev/null && [ "$(recipe "$G" ig_alias | jq -r '"\(.type) \(.name) \(.address)"')" = "alias sh $RA" ] && ok "an alias Go made is read by the recipe" || bad "Go's alias in the recipe"
M1=11111111-2222-4333-8444-555555555555
id=$(printf 'threaded, from Go\n' | gocli "$G" send --subject 'a subject' --reply-to $M1 sh | jq -r 'select(.type == "sent") | .id') && ig_hex "$id" || bad "Go send with flags, to an alias: $id"
out=$(recipe "$R" ig_recv 2> "$work/err") && jq -e --arg m $M1 '.subject == "a subject" and .in_reply_to == $m and .body == "threaded, from Go\n"' <<< "$out" > /dev/null \
  && ok "Go → recipe: subject and in_reply_to arrive, sent to an alias" || bad "Go → recipe with flags: $out $(cat "$work/err")"
mid=$(jq -r .msg_id <<< "$out")
jq -e --arg id "$id" --argjson d "$out" '.receipt.id == $id and (.receipt | keys == ["expires_at", "id", "received_at"]) and del(.receipt) == ($d | del(.type, .id))' "$G/sent/$RA.$mid.json" > /dev/null \
  && ok "Go's sent/ record is the line its recipient delivered, plus the real server's receipt" || bad "Go's sent/ record: $(cat "$G/sent/$RA.$mid.json" 2>&1)"
recipe "$R" "ig_send --subject 'the reply' --reply-to $mid go '$work/body'" || bad "recipe send with options, to an alias"
out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg m "$mid" --arg f "$RA" '.subject == "the reply" and .in_reply_to == $m and .from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go: a reply naming the message it answers, sent to an alias" || bad "recipe → Go with options: $out $(cat "$work/err")"
rec="$R/sent/$GA.$(jq -r .msg_id <<< "$out").json"
jq -e --argjson d "$out" '(.receipt | keys == ["expires_at", "id", "received_at"]) and del(.receipt) == ($d | del(.type, .id))' "$rec" > /dev/null && [ -e "$G/inbox/$(jq -r .receipt.id "$rec").json" ] \
  && ok "the recipe's sent/ record is the same, its receipt naming the file in the recipient's inbox/" || bad "the recipe's sent/ record: $(cat "$rec" 2>&1)"

# --- 5. a box whose identity is of the optional key type, ecdsa-sha2-nistp256, in each client ---
# The recipe takes the identity key it finds, so its box's key is made with ssh-keygen first. Each client's P-256 box
# then exchanges mail with the other client's Ed25519 box of step 1, which declared that it verifies the type.
RP="$work/rp"; GP="$work/gp"; mkdir -p "$RP"
ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$RP/identity" < /dev/null
RPL=$(recipe "$RP" "ig_init $(nopq_arg)" | linkof) && RPA=${RPL##*/} && ig_hex "$RPA" && [ "$(sed -n 2p "$RP/identity.doc" | cut -d' ' -f1)" = ecdsa-sha2-nistp256 ] \
  && ok "recipe init on a P-256 identity made by ssh-keygen" || bad "recipe init on P-256: $RPL"
GPO=$(gocli "$GP" init --identity-type ecdsa-sha2-nistp256 $(nopq_arg) 2> "$work/err") && GPL=$(linkof <<< "$GPO") && GPA=${GPL##*/} && ig_hex "$GPA" && jq -e '.message | startswith("WARNING: ")' <<< "$GPO" > /dev/null \
  && ok "Go init --identity-type ecdsa-sha2-nistp256, with its warning" || bad "Go init on P-256: $GPL $(cat "$work/err")"
[ "$(curl -s "$IG_BASE/v1/$GA" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] && [ "$(curl -s "$IG_BASE/v1/$RA" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] \
  && ok "each client's box is served with the sender key types it declared" || bad "sender_key_types: $(curl -s "$IG_BASE/v1/$GA" | jq -c .sender_key_types) $(curl -s "$IG_BASE/v1/$RA" | jq -c .sender_key_types)"
printf 'p256 recipe to go\n' > "$work/body5"
recipe "$RP" "ig_send $GL '$work/body5'" && out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg f "$RPA" '.body == "p256 recipe to go\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "recipe on P-256 → Go: delivered, verified under a certificate ssh-keygen made with a P-256 key" || bad "recipe on P-256 → Go: $out $(cat "$work/err")"
printf 'go to p256 recipe\n' | gocli "$G" send "$RPL" > /dev/null && out=$(recipe "$RP" ig_recv 2> "$work/err") && jq -e --arg f "$GA" '.body == "go to p256 recipe\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "Go → recipe on P-256: delivered" || bad "Go → recipe on P-256: $out $(cat "$work/err")"
printf 'p256 go to recipe\n' | gocli "$GP" send "$RL" > /dev/null && out=$(recipe "$R" ig_recv 2> "$work/err") && jq -e --arg f "$GPA" '.body == "p256 go to recipe\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "Go on P-256 → recipe: delivered, verified by ssh-keygen under a certificate the Go client made with a P-256 key" || bad "Go on P-256 → recipe: $out $(cat "$work/err")"
printf 'recipe to p256 go\n' > "$work/body5"
recipe "$R" "ig_send $GPL '$work/body5'" && out=$(gocli "$GP" recv 2> "$work/err") && jq -e --arg f "$RA" '.body == "recipe to p256 go\n" and .from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go on P-256: delivered" || bad "recipe → Go on P-256: $out $(cat "$work/err")"
# A box that declares Ed25519 only: the server refuses it a P-256 sender's mail, and the Go client does not even post it.
GE="$work/ge"
GEL=$(IRONGALL_SENDER_KEY_TYPES=ssh-ed25519 gocli "$GE" init $(nopq_arg) | linkof) && GEA=${GEL##*/} && [ "$(curl -s "$IG_BASE/v1/$GEA" | jq -c .sender_key_types)" = '["ssh-ed25519"]' ] \
  && ok "a box told to declare Ed25519 only is served so" || bad "IRONGALL_SENDER_KEY_TYPES: $(curl -s "$IG_BASE/v1/$GEA")"
out=$(printf 'x\n' | gocli "$GP" send "$GEL" 2>&1); [ $? -ne 0 ] && grep -q "does not verify identities of this box's key type" <<< "$out" \
  && ok "Go on P-256 does not send to a box that does not verify its key type" || bad "Go on P-256 → Ed25519-only box: $out"
out=$(recipe "$RP" "ig_send $GEL '$work/body5'" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 403 sender_key_type" <<< "$out" \
  && ok "the server refuses the recipe's P-256 box the same send: 403 sender_key_type, and no receipt" || bad "recipe on P-256 → Ed25519-only box: $out"

# --- 6. a box whose clock is off from the server's (PROTOCOL.md §0) ---
# The recipe reads one clock, ig_now, which is set apart here; the server and the Go boxes keep the real one. Each Go
# box is made at that moment, so no certificate is newer than the one its mail is signed under.
clock(){ echo "ig_now(){ echo \$((\$(date -u +%s) + ($1))); }"; }   # <seconds> → the recipe's clock, that far from the real one
for c in "-540 9 minutes slow" "2940 49 minutes fast"; do
  off=${c%% *}; name=${c#* }; d="$work/clock$off"; gf="$work/gf$off"
  L=$(recipe "$d" "$(clock "$off"); ig_init $(nopq_arg)" 2> "$work/err" | linkof) && A=${L##*/} && ig_hex "$A" && GFL=$(gocli "$gf" init $(nopq_arg) | linkof) && GFA=${GFL##*/} \
    && printf 'to the box whose clock is off\n' | gocli "$gf" send "$L" > /dev/null \
    && out=$(recipe "$d" "$(clock "$off"); ig_recv" 2>> "$work/err") && jq -e --arg f "$GFA" '.body == "to the box whose clock is off\n" and .from == $f' <<< "$out" > /dev/null \
    && printf 'from the box whose clock is off\n' > "$work/body6" && recipe "$d" "$(clock "$off"); ig_send $GFL '$work/body6'" 2>> "$work/err" \
    && out=$(gocli "$gf" recv 2>> "$work/err") && jq -e --arg f "$A" '.body == "from the box whose clock is off\n" and .from == $f' <<< "$out" > /dev/null \
    && recipe "$d" "$(clock "$off"); ig_rekey $(nopq_arg)" 2>> "$work/err" \
    && ok "a recipe box whose clock is $name registers, renews, and exchanges mail with a Go box made that moment" || bad "clock $name: $out $(cat "$work/err")"
done
out=$(recipe "$work/clock-late" "$(clock -660); ig_init $(nopq_arg)" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 401 pass_expired" <<< "$out" && grep -q "the server dates its answer 20" <<< "$out" && grep -q "this machine's clock reads" <<< "$out" \
  && ok "a recipe box 11 minutes slow is refused at its pass: the server's answer is dated by its clock, and the recipe says that beside what its own reads" || bad "clock 11 minutes slow: $out"
out=$(recipe "$work/clock-early" "$(clock 3660); ig_init $(nopq_arg)" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 400 prekey_time" <<< "$out" && grep -q "the server dates its answer 20" <<< "$out" \
  && L=$(recipe "$work/clock-early" "ig_init $(nopq_arg)" 2> "$work/err" | linkof) && ig_hex "${L##*/}" \
  && ok "a recipe box first made 61 minutes fast is refused, the answer dated by the server's clock; with the clock right, the same box registers" || bad "clock 61 minutes fast: $out $(cat "$work/err")"

# --- 7. revocation (PROTOCOL.md §6.3): the server keeps the identity's own signature and shows it in the read of the box, and each client checks it ---
V1="$work/v1"; V2="$work/v2"; V3="$work/v3"; V4="$work/v4"; V5="$work/v5"
V1L=$(recipe "$V1" "ig_init $(nopq_arg)" | linkof) && V1A=${V1L##*/} && V2L=$(gocli "$V2" init $(nopq_arg) | linkof) && V2A=${V2L##*/} && V3L=$(gocli "$V3" init $(nopq_arg) | linkof) && V3A=${V3L##*/} \
  && V4L=$(recipe "$V4" "ig_init $(nopq_arg)" | linkof) && V4A=${V4L##*/} && V5L=$(gocli "$V5" init $(nopq_arg) | linkof) && V5A=${V5L##*/} || bad "revocation: the boxes"
[ "$(curl -s -D "$work/head" -o "$work/box.json" -w '%{http_code}' "$IG_BASE/v1/$V1A")" = 200 ] && jq -e '(has("revoked_certificates") or has("revoked_certificates_signature")) | not' "$work/box.json" > /dev/null \
  && [ "$(tr -d '\r' < "$work/head" | grep -i '^cache-control:' | cut -d' ' -f2)" = no-store ] \
  && ok "a box nobody revoked: read 200 with no revocation in it, and the API's answers say no-store" || bad "not revoked: $(curl -s -D - "$IG_BASE/v1/$V1A")"
# The recipe revokes its box; mail it had sent a Go box is refused there, by the proof the server shows.
printf 'sent before the revocation\n' > "$work/body7"; recipe "$V1" "ig_send $V2L '$work/body7'" 2> "$work/err" || bad "revocation: the recipe's send: $(cat "$work/err")"
printf 'waiting in the box that is revoked\n' | gocli "$V2" send "$V1L" > /dev/null 2> "$work/err" || bad "revocation: the Go send: $(cat "$work/err")"
out=$(recipe "$V1" "ig_revoke ${V1A:0:63}" 2>&1); [ $? -ne 0 ] && [ "$(look "$V1A")" = 200 ] \
  && ok "the recipe does not revoke without the address in full, and nothing is published" || bad "revoke with a short address: $out"
out=$(recipe "$V1" "ig_revoke $V1A" 2>&1) && [ "$out" = "$(revoked_line $V1A)" ] && [ "$(look "$V1A")" = 410 ] \
  && curl -s "$IG_BASE/v1/$V1A" | jq -e '.code == "revoked" and (.record | keys == ["identity","revocation_signature","type"] and .type == "revocation_record")' > /dev/null \
  && ok "the recipe revokes its box: 410 from then on, and the server shows the record in it to anyone" || bad "recipe revoke: $out"
out=$(gocli "$V2" recv 2>&1); [ $? -eq 0 ] && grep -q '"code":"revoked"' <<< "$out" && ! grep -q '"body"' <<< "$out" && [ -s "$V2/peers/$V1A/revoke.sig" ] \
  && ok "the Go client refuses mail from the box the recipe revoked, and keeps the revocation it checked" || bad "Go recv from a revoked box: $out"
out=$(printf 'x\n' | gocli "$V2" send "$V1L" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: $V1A" <<< "$out" && ls "$V2"/outbox/failed/*.P > /dev/null 2>&1 \
  && ok "the Go client sends nothing to it: REVOKED, and the message moves to outbox/failed/" || bad "Go send to a revoked box: $out"
out=$(recipe "$V1" "ig_recv" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: this box's own address" <<< "$out" && ok "the revoked recipe box is told so by its own revocation" || bad "revoked recipe box's recv: $out"
# The Go client revokes its box; the recipe refuses the mail it had sent, and sends it nothing.
printf 'sent before the revocation\n' | gocli "$V3" send "$V4L" > /dev/null 2> "$work/err" || bad "revocation: the Go send: $(cat "$work/err")"
out=$(gocli "$V3" revocation publish "$V4A" 2>&1); [ $? -ne 0 ] && [ "$(look "$V3A")" = 200 ] \
  && ok "the Go client does not revoke for another box's address" || bad "Go revoke with another address: $out"
out=$(gocli "$V3" revocation publish "$V3A" 2>&1) && [ "$out" = "$(revoked_line $V3A)" ] && [ "$(look "$V3A")" = 410 ] \
  && jq -e '.revoked == true' <<< "$(gocli "$V3" status 2> /dev/null)" > /dev/null \
  && ok "the Go client revokes its box, and its status says so" || bad "Go revoke: $out"
out=$(recipe "$V4" "ig_recv" 2>&1); [ $? -eq 0 ] && grep -q '"code":"revoked"' <<< "$out" && ! grep -q '"body"' <<< "$out" && [ -s "$V4/peers/$V3A/revoke.sig" ] \
  && ok "the recipe refuses mail from the box the Go client revoked, and keeps the revocation it checked" || bad "recipe recv from a revoked box: $out"
out=$(recipe "$V4" "ig_send $V3L '$work/body7'" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED" <<< "$out" && ok "the recipe sends nothing to it: REVOKED" || bad "recipe send to a revoked box: $out"
# A record made in advance revokes with no box and no key, by either client or by curl; what is not one is refused.
gocli "$V5" revocation make > "$work/v5.json" 2> /dev/null && [ "$(look "$V5A")" = 200 ] && ok "a record is made, and nothing is published" || bad "Go revocation"
jq -c --arg s "$(printf 'revoke it' | base64)" '.revocation_signature = $s' "$work/v5.json" > "$work/v5-junk.json"
[ "$(curl -s -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v5-junk.json" "$IG_BASE/v1/$V5A/revocations" | jq -r .code)" = bad_revocation ] \
  && [ "$(curl -s -X PUT -H 'Content-Type: application/json' --data-binary "@$work/v5.json" "$IG_BASE/v1/$V4A/revocations" | jq -r .code)" = identity_mismatch ] \
  && [ "$(look "$V5A")" = 200 ] \
  && ok "the server refuses what is not a revocation of that address: 400 bad_revocation, 400 identity_mismatch" || bad "junk revocations"
out=$(recipe "$work/nobox" "ig_revoke $V5A '$work/v5.json'" 2>&1) && [ "$out" = "$(revoked_line $V5A)" ] && [ "$(look "$V5A")" = 410 ] \
  && [ "$(IRONGALL_HOME="$work/nobox2" "$work/irongall" revocation publish --record "$work/v5.json" "$V5A" 2>&1)" = "$(revoked_line $V5A)" ] \
  && ok "the Go client's record revokes from the recipe with no box, and again from the Go client with none: 200, nothing changes" || bad "revoke with a record: $out"

# --- 8. certificates revoked (PROTOCOL.md §6.3a): the identity's revocation ends what a certificate signed, and the address goes on ---
W1="$work/w1"; W2="$work/w2"; W3="$work/w3"
W1L=$(gocli "$W1" init $(nopq_arg) | linkof) && W1A=${W1L##*/} && W2L=$(recipe "$W2" "ig_init $(nopq_arg)" | linkof) && W2A=${W2L##*/} && W3L=$(gocli "$W3" init $(nopq_arg) | linkof) && W3A=${W3L##*/} || bad "revoked certificates: the boxes"
kept(){ jq -r .revoked_certificates "$1" | base64 -d; }   # <the record a box keeps a revocation of certificates as> → the statement in it
put(){ curl -s -o "$work/put.json" -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$1" "$IG_BASE/v1/$2/revocations"; }   # <record> <address> → the status; the body is left in put.json
printf 'under the first certificate\n' > "$work/body8"
gocli "$W1" send "$W2L" < "$work/body8" > /dev/null 2> "$work/err" && gocli "$W1" send "$W3L" < "$work/body8" > /dev/null 2>> "$work/err" && recipe "$W2" "ig_send $W3L '$work/body8'" 2>> "$work/err" || bad "revoked certificates: the first sends: $(cat "$work/err")"
# The Go client renews and revokes every certificate before its new one. Each client is shown the revocation, checks it, and refuses what the old one signed.
out=$(gocli "$W1" cert revoke-earlier 2>&1) && [ "$(curl -s -o "$work/box.json" -w '%{http_code}' "$IG_BASE/v1/$W1A")" = 200 ] \
  && jq -e 'has("revoked_certificates") and has("revoked_certificates_signature") and has("prekey")' "$work/box.json" > /dev/null \
  && ok "the Go client renews and revokes its earlier certificates: the server shows the revocation to anyone in the read of the box, and the address goes on" || bad "cert revoke-earlier: $out"
printf 'under the second certificate\n' > "$work/body8b"
gocli "$W1" send "$W2L" < "$work/body8b" > /dev/null 2> "$work/err" && gocli "$W1" send "$W3L" < "$work/body8b" > /dev/null 2>> "$work/err" || bad "revoked certificates: the sends after the renewal: $(cat "$work/err")"
out=$(recipe "$W2" "ig_recv" 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && ! grep -q 'under the first certificate' <<< "$out" \
  && curl -sf "$IG_BASE/v1/$W1A" | jq -r .revoked_certificates | base64 -d | cmp -s - <(kept "$W2/peers/$W1A/revoked-certs.json") && [ ! -e "$W2/peers/$W1A/revoke.sig" ] \
  && ok "the recipe refuses mail under the certificate the Go box revoked, delivers mail under its new one, and keeps the revocation it checked" || bad "recipe recv after the revocation: $out"
out=$(gocli "$W3" recv 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && [ "$(grep -c 'under the first certificate' <<< "$out")" = 1 ] \
  && cmp -s <(kept "$W2/peers/$W1A/revoked-certs.json") <(kept "$W3/peers/$W1A/revoked-certs.json") && [ -s "$W3/peers/$W1A/revoked-certs.json" ] \
  && ok "the Go client does the same, and takes the recipe box's mail under a certificate nobody revoked" || bad "Go recv after the revocation: $out"
recipe "$W2" "ig_send $W1L '$work/body8'" 2> "$work/err" && gocli "$W3" send "$W1L" < "$work/body8" > /dev/null 2>> "$work/err" && out=$(gocli "$W1" recv 2>&1) && [ "$(grep -c '"body"' <<< "$out")" = 2 ] \
  && [ "$(cat "$W2/peers/$W1A/serial" "$W2/peers/$W1A/cert-serial" | tr '\n' ' ')" = "$(cat "$W1/serial") $(cat "$W1/serial") " ] \
  && ok "both clients write to the box at its second certificate, naming its prekey by both serials" || bad "sends to the renewed box: $(cat "$work/err") $out"
# A revocation of certificates made with ssh-keygen alone: the recipe makes none, and its box's identity signs like any other.
mkcerts(){ printf 'irongall-revoke-certs-v1\n%s\n%s\n' "$W2A" "$2" > "$work/$1.certs" && ssh-keygen -q -Y sign -n "irongall-revoke-certs-v1:$W2A" -f "$3" < "$work/$1.certs" > "$work/$1.sig" \
  && jq -cn --arg i "$(base64 < "$W2/identity.doc" | tr -d '\n')" --arg l "$(base64 < "$work/$1.certs" | tr -d '\n')" --arg g "$(base64 < "$work/$1.sig" | tr -d '\n')" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$work/$1.json"; }   # <name> <serial> <key>
w2a=$(cat "$W2/serial")   # a box takes each number from its clock: the recipe box's first, and after its renewal its second
recipe "$W2" "ig_send $W3L '$work/body8'" 2> "$work/err" && recipe "$W2" "ig_rekey $(nopq_arg)" 2>> "$work/err" && recipe "$W2" "ig_send $W3L '$work/body8b'" 2>> "$work/err" || bad "revoked certificates: the recipe's renewal: $(cat "$work/err")"
w2b=$(cat "$W2/serial"); [ "$w2b" -gt "$w2a" ] || bad "revoked certificates: the recipe's renewal took no later number: $w2a, then $w2b"
mkcerts bywork "$w2a" "$W2/work/$w2b-cert.pub" && mkcerts one "$w2a" "$W2/identity" && mkcerts lower $((w2a - 1)) "$W2/identity" && mkcerts two "$w2b" "$W2/identity" || bad "revoked certificates: ssh-keygen did not sign a revocation"
[ "$(put "$work/bywork.json" "$W2A")" = 400 ] && [ "$(jq -r .code "$work/put.json")" = bad_revocation ] && [ "$(put "$work/one.json" "$W3A")" = 400 ] && [ "$(jq -r .code "$work/put.json")" = identity_mismatch ] \
  && curl -sf "$IG_BASE/v1/$W2A" | jq -e '(has("revoked_certificates") or has("revoked_certificates_signature")) | not' > /dev/null \
  && ok "the server refuses a revocation of certificates the box's working key signed, and one sent for another address: 400 bad_revocation, 400 identity_mismatch" || bad "junk revocations: $(cat "$work/put.json")"
[ "$(put "$work/one.json" "$W2A")" = 200 ] && [ "$(put "$work/one.json" "$W2A")" = 200 ] && [ "$(put "$work/lower.json" "$W2A")" = 409 ] && [ "$(jq -r .code "$work/put.json")" = conflict ] \
  && curl -sf "$IG_BASE/v1/$W2A" | jq -r .revoked_certificates | base64 -d | cmp -s - "$work/one.certs" \
  && ok "a revocation of certificates signed with ssh-keygen alone is taken with no pass: 200, the same again 200, one through a lower serial 409 conflict" || bad "the recipe box's revocation: $(cat "$work/put.json")"
out=$(gocli "$W3" recv 2>&1); [ $? -eq 0 ] && [ "$(grep -c '"code":"certificate_revoked"' <<< "$out")" = 1 ] && grep -q 'under the second certificate' <<< "$out" && ! grep -q 'under the first certificate' <<< "$out" \
  && kept "$W3/peers/$W2A/revoked-certs.json" | cmp -s - "$work/one.certs" \
  && ok "the Go client refuses the recipe box's mail under the certificate that revocation covers, and delivers its mail under the next" || bad "Go recv after the recipe box's revocation: $out"
# A revocation through the box's CURRENT certificate: the server takes no pass of the box and no mail for it, until it renews.
[ "$(put "$work/two.json" "$W2A")" = 200 ] || bad "the second revocation: $(cat "$work/put.json")"
out=$(recipe "$W2" "ig_recv" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 401 certificate_revoked" <<< "$out" && ok "a box whose current certificate is revoked has no pass the server takes" || bad "a revoked certificate's recv: $out"
# A sender asks what the server holds about a box before it posts to it (PROTOCOL.md §4.1): shown the revocation, it refuses the box's statement itself.
out=$(gocli "$W3" send "$W2L" < "$work/body8" 2>&1); [ $? -ne 0 ] && grep -q "under a certificate its identity has revoked" <<< "$out" && ! grep -q "prekey_expired" <<< "$out" && ls "$W3"/outbox/*.P > /dev/null 2>&1 \
  && kept "$W3/peers/$W2A/revoked-certs.json" | cmp -s - "$work/two.certs" && ! ls "$W3"/outbox/*.json > /dev/null 2>&1 \
  && ok "a sender asks before it posts: shown the revocation, it keeps it, seals nothing to a statement under a revoked certificate, and the message waits in the outbox" || bad "a send to a box whose certificate is revoked: $out"
recipe "$W2" "ig_rekey $(nopq_arg)" 2> "$work/err" && gocli "$W3" outbox flush > /dev/null 2>> "$work/err" && out=$(recipe "$W2" "ig_recv" 2>&1) && grep -q 'under the first certificate' <<< "$out" \
  && ok "one renewal, under a new certificate, cures both: the box polls again, and the waiting message is delivered" || bad "after the box renewed: $(cat "$work/err") $out"
out=$(gocli "$W3" revocation ask "$W2L" 2> /dev/null) && [ "$out" = "{\"type\":\"certificates_revoked\",\"address\":\"$W2A\",\"through\":$w2b}" ] && out=$(gocli "$W1" revocation ask "$W3L" 2> "$work/err") && [ "$(jq -r '"\(.type) \(.address)"' <<< "$out")" = "not_revoked $W3A" ] && jq -e '.message | contains("the word of whoever was asked")' <<< "$out" > /dev/null \
  && ok "asked at any time, the server shows a box's revocation of its certificates, or that it holds nothing, which the client says as the word of whoever it asked" || bad "revoked --ask: $out $(cat "$work/err")"

# --- 9. a revocation server beside this one (PROTOCOL.md §6.3): a second irongalld, since every mailbox server is one ---
# A server keeps a revocation for an address it has no box for, so no box here is registered at the second server: it holds only
# what each box publishes to it.
second(){ "$work/irongalld" serve --dev -listen "127.0.0.1:$1" -poll-burst 0 -registrations-per-hour 0 -misses-per-minute 0 2> "$work/server-$1.log" & }   # <port>: it holds no box of these, so each address it is asked about is a miss there
up(){ for _ in $(seq 300); do code=$(curl -s -o /dev/null -w '%{http_code}' "$1/v1/$(printf '0%.0s' $(seq 64))"); [ "$code" != 000 ] && [ "$code" != 503 ] && return 0; sleep 0.1; done; return 1; }   # <server>
rport=$((port + 1)); REV="http://127.0.0.1:$rport"; second "$rport"; rev=$!; up "$REV" || bad "the second server did not come up"
at(){ curl -s -o /dev/null -w '%{http_code}' "$1/v1/$2/revocations"; }   # <revocation server> <address> → the status of a lookup there
X1="$work/x1"; X2="$work/x2"; X3="$work/x3"; X4="$work/x4"; X5="$work/x5"; X6="$work/x6"
X1L=$(gocli "$X1" init $(nopq_arg) | linkof) && X1A=${X1L##*/} && X2L=$(recipe "$X2" "ig_init $(nopq_arg)" | linkof) && X2A=${X2L##*/} && X3L=$(gocli "$X3" init $(nopq_arg) | linkof) && X3A=${X3L##*/} \
  && X4L=$(recipe "$X4" "ig_init $(nopq_arg)" | linkof) && X4A=${X4L##*/} && X5L=$(gocli "$X5" init $(nopq_arg) | linkof) && X5A=${X5L##*/} && X6L=$(gocli "$X6" init $(nopq_arg) | linkof) && X6A=${X6L##*/} || bad "the revocation server: the boxes"
for b in "$X1" "$X2" "$X3" "$X4" "$X6"; do echo "$REV" > "$b/revocation-servers"; done      # the one setting, in the box, for whichever client runs it: X5 lists none
[ "$(at "$REV" "$X1A")" = 404 ] && [ "$(curl -s "$REV/v1/$X1A/revocations" | jq -r .code)" = not_revoked ] && [ "$(at "$REV" "$X5A")" = 404 ] && [ "$(gocli "$X1" status | jq -r '.revocation_servers[0]')" = "$REV" ] \
  && ok "a server answers 404 not_revoked for an address it holds no revocation of, with a box there or none, and a box's status names the servers it asks" || bad "the revocation server, before anything"
# Each client's revocation goes to both servers.
out=$(gocli "$X1" revocation publish "$X1A" 2>&1) && [ "$out" = "$(revoked_line $X1A)" ] && [ "$(look "$X1A")" = 410 ] && [ "$(at "$REV" "$X1A")" = 200 ] \
  && out2=$(recipe "$X2" "ig_revoke $X2A" 2>&1) && [ "$out2" = "$(revoked_line $X2A)" ] && [ "$(look "$X2A")" = 410 ] && [ "$(at "$REV" "$X2A")" = 200 ] \
  && cmp -s <(curl -s "$REV/v1/$X1A/revocations" | jq -S .) <(curl -s "$IG_BASE/v1/$X1A" | jq -S .record) \
  && cmp -s <(curl -s "$REV/v1/$X1A/revocations" | jq -S .) <(curl -s "$IG_BASE/v1/$X1A/revocations" | jq -S .) \
  && ok "each client publishes its revocation at this server and at the revocation server, which then serve the same record, in the read of the box and in their own read" || bad "revoke at both: $out / ${out2:-}"
# A revocation this server was never told of: the record goes to the revocation server alone, and this server goes on serving the box.
gocli "$X3" revocation make > "$work/x3.json" 2> /dev/null && [ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' --data-binary "@$work/x3.json" "$REV/v1/$X3A/revocations")" = 201 ] \
  && [ "$(look "$X3A")" = 200 ] && curl -sf "$IG_BASE/v1/$X3A" | jq -e '(has("revoked_certificates") or has("revoked_certificates_signature")) | not' > /dev/null \
  && [ "$(curl -s -o /dev/null -w '%{http_code}' "$REV/v1/$X3A")" = 410 ] && cmp -s <(curl -s "$REV/v1/$X3A" | jq -S .record) <(jq -S . "$work/x3.json") \
  && ok "a server with no box at an address keeps a revocation of it, and its read of the address is 410 with the record" || bad "a revocation at the revocation server alone"
d3="$X3.atrev"; mkdir -p -m 700 "$d3" && cp "$X3/identity" "$d3/identity" && out=$(IRONGALL_BASE=$REV gocli "$d3" init $(nopq_arg) 2>&1); [ $? -ne 0 ] && grep -qi 'revoked' <<< "$out" && [ "$(curl -s -o /dev/null -w '%{http_code}' "$REV/v1/$X3A")" = 410 ] \
  && ok "and refuses that address's registration: it is revoked there, box or none" || bad "a registration of an address revoked with no box: $out"
printf 'to an address its owner ended\n' > "$work/body9"
gocli "$X5" send "$X3L" < "$work/body9" > /dev/null 2> "$work/err" && ok "the control: a box that asks this server alone posts to the revoked address, and this server takes it" || bad "the control: $(cat "$work/err")"
out=$(gocli "$X6" send "$X3L" < "$work/body9" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: $X3A is revoked" <<< "$out" && [ -s "$X6/peers/$X3A/revoke.sig" ] && ls "$X6"/outbox/failed/"$X3A".*.P > /dev/null 2>&1 \
  && out=$(recipe "$X4" "ig_send $X3L '$work/body9'" 2>&1); [ $? -ne 0 ] && grep -q "REVOKED: $X3A is revoked" <<< "$out" && [ -s "$X4/peers/$X3A/revoke.sig" ] \
  && ok "a revocation this server never held is shown to each client by the revocation server: it is checked and kept, and nothing is posted" || bad "a hidden revocation: $out"
# The revocation of certificates goes to both, and a box that never met its owner is shown it by either.
out=$(gocli "$X6" cert revoke-earlier 2>&1) && [ "$(curl -s "$REV/v1/$X6A/revocations" | jq -r 'keys | join(",")')" = "identity,revoked_certificates,revoked_certificates_signature,type" ] \
  && cmp -s <(curl -s "$REV/v1/$X6A/revocations" | jq -r .revoked_certificates) <(curl -s "$IG_BASE/v1/$X6A" | jq -r .revoked_certificates) \
  && ok "cert revoke-earlier publishes the revocation of certificates at both servers" || bad "a revocation of certificates at both: $out"
# A third server listed, which gives no answer: mail goes, the owner is told, and a revocation is reported as not everywhere.
dport=$((port + 2)); DEAD="http://127.0.0.1:$dport"
for b in "$X4" "$X6"; do printf '%s\n%s\n' "$REV" "$DEAD" > "$b/revocation-servers"; done
out=$(gocli "$X6" send "$X5L" < "$work/body9" 2>&1); [ $? -eq 0 ] && grep -q "the revocation server $DEAD gave no answer, which changes nothing here" <<< "$out" \
  && out2=$(recipe "$X4" "ig_send $X5L '$work/body9'" 2>&1); [ $? -eq 0 ] && grep -q "the revocation server $DEAD gave no answer, which changes nothing here" <<< "$out2" \
  && [ "$(gocli "$X5" recv 2> /dev/null | jq -r .body | grep -c 'to an address its owner ended')" = 2 ] \
  && ok "with a listed server that gives no answer, each client says so and its mail goes all the same" || bad "a server gone: $out / ${out2:-}"
out=$(gocli "$X6" revocation publish "$X6A" 2>&1); [ $? -eq 1 ] && grep -q "was NOT taken by $DEAD" <<< "$out" && grep -q "it was taken by $IG_BASE and $REV" <<< "$out" && ! grep -q '"type":"revoked"' <<< "$out" && [ "$(look "$X6A")" = 410 ] && [ "$(at "$REV" "$X6A")" = 200 ] && [ -s "$X6/revoked.sig" ] \
  && out2=$(recipe "$X4" "ig_revoke $X4A" 2>&1); [ $? -ne 0 ] && grep -q "NOT taken by the revocation server $DEAD" <<< "$out2" && ! grep -q '"type":"revoked"' <<< "$out2" && [ "$(look "$X4A")" = 410 ] && [ "$(at "$REV" "$X4A")" = 200 ] && [ -s "$X4/revoked.sig" ] \
  && ok "a revocation that not every server took is at the others, is kept by its box, and the command fails saying which did not take it" || bad "revoke with a server gone: $out / ${out2:-}"
# That server up, the same command again is the cure: the two that hold the address revoked answer 410, which each client takes once
# what that server then serves verifies, and the third takes the record.
second "$dport"; rev2=$!; up "$DEAD" || bad "the third server did not come up"
out=$(gocli "$X6" revocation publish "$X6A" 2>&1) && [ "$out" = "$(revoked_line $X6A)" ] && curl -s "$DEAD/v1/$X6A/revocations" | jq -e '.revocation_signature' > /dev/null \
  && curl -s "$REV/v1/$X6A/revocations" | jq -e '.revocation_signature and .revoked_certificates' > /dev/null \
  && out2=$(recipe "$X4" "ig_revoke $X4A" 2>&1) && [ "$out2" = "$(revoked_line $X4A)" ] && [ "$(at "$DEAD" "$X4A")" = 200 ] \
  && ok "the same command again publishes what a server missed, and a 410 from a server that holds the address revoked is taken once its record verifies" || bad "revoke again: $out / ${out2:-}"

# --- the sender ACL: a Go box that blocks a recipe box, and a recipe send that the server then refuses for good ---
XB="$work/xb"; XBL=$(recipe "$XB" "ig_init $(nopq_arg)" | linkof) && XBA=${XBL##*/} || bad "recipe init for the ACL: $XBL"
out=$(gocli "$G" peer block "$XBL" 2>&1) && curl -s -H "Authorization: $(cat "$G/pass")" "$IG_BASE/v1/$GA/acl" | jq -e --arg x "$XBA" '.allow == ["*"] and .deny == [$x] and .version > 0' > /dev/null \
  && out=$(recipe "$XB" "ig_send $GL '$work/body'" 2>&1); [ $? -ne 0 ] && grep -q 'ERROR 403 sender_not_allowed' <<< "$out" && grep -q 'moved to outbox/failed/' <<< "$out" && [ -n "$(ls "$XB/outbox/failed/"*.P 2> /dev/null)" ] \
  && ok "a Go box's block reaches the server as its ACL, which refuses the recipe box's send for good: it moves to outbox/failed/" || bad "the ACL: $out"

echo "interop: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ]

#!/usr/bin/env bash
# interop.sh — the stock client, sh/irongall.sh from the public irongall-client checkout beside this repo, with its real ig_api (curl),
# against a real `irongalld serve --dev`, interoperating with the Go client `irongall` from the public client repo:
#   1. mail both ways between a recipe box and a Go box, sent to each box's link, across a prekey renewal on each side; the page each link opens;
#   2. ONE box run by both clients: the Go client receives in a box the recipe made, and the recipe in one Go made;
#   3. the recipe's error path on a real problem+json body;
#   4. the envelope's optional fields, each client's sent/ record (with the real server's receipt) and aliases, across the clients;
#   5. a box whose identity is of the optional key type, in each client, and the sender key types a box declares.
# Every script step runs in a FRESH shell (agents run each command in a new one). --no-pq boxes only when the local
# age is older than 1.3 (it cannot make or send to a post-quantum box); the Go client handles both either way.
# Needs: go, bash ≥ 4, age, age-keygen, ssh-keygen, curl, jq, sha256sum, base64, od. Run from anywhere:
#   test/interop.sh            SCRIPT=<path> overrides the irongall.sh it sources.
# With IRONGALL_TEST_BOXES_TABLE, IRONGALL_TEST_MSGS_TABLE, IRONGALL_TEST_ACCOUNTS_TABLE and IRONGALL_TEST_BUCKET set, the server runs on those tables and
# that bucket instead of --dev, with a throwaway server key: tables and a bucket kept for tests, never the ones a running server uses.
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
trap '[ -n "${srv:-}" ] && kill "$srv" 2> /dev/null' EXIT

export PATH=$PATH:/usr/local/go/bin
(cd "$repo" && go build -o "$work/irongalld" ./cmd/irongalld && go build -o "$work/irongall" github.com/IronGall-dev/irongall-client/cmd/irongall) || { echo "build failed"; exit 1; }
[ -r "$SCRIPT" ] || { echo "no $SCRIPT"; exit 1; }
echo "stock client: $SCRIPT ($(grep -c '^ig_[a-z_]*()' "$SCRIPT") functions)"

if age-keygen -pq > /dev/null 2>&1; then kt=pq; else kt=no-pq; fi
echo "local age: $(age --version) → recipe boxes are $kt"
port=$((20000 + RANDOM % 20000))
if [ -n "${IRONGALL_TEST_MSGS_TABLE:-}" ]; then
  (umask 077 && printf '1 %s\n' "$(head -c 32 /dev/urandom | base64)" > "$work/keys")
  store=(-boxes-table "$IRONGALL_TEST_BOXES_TABLE" -msgs-table "$IRONGALL_TEST_MSGS_TABLE" -accounts-table "$IRONGALL_TEST_ACCOUNTS_TABLE" -bucket "$IRONGALL_TEST_BUCKET" -keys "$work/keys" -names "127.0.0.1:$port")
else
  store=(--dev)
fi
echo "server: irongalld serve ${store[*]:0:6}"
"$work/irongalld" serve "${store[@]}" -listen "127.0.0.1:$port" -poll-burst 0 -registrations-per-hour 0 2> "$work/server.log" & srv=$!
export IG_BASE="http://127.0.0.1:$port" IRONGALL_BASE="http://127.0.0.1:$port"
for _ in $(seq 300); do   # up once the API answers other than 503 (loading)
  code=$(curl -s -o /dev/null -w '%{http_code}' "$IG_BASE/v1/$(printf '0%.0s' $(seq 64))/identity"); [ "$code" != 000 ] && [ "$code" != 503 ] && break; sleep 0.1
done

R="$work/r"; G="$work/g"
recipe(){ local home=$1; shift; IRONGALL_HOME=$home bash -c ". '$SCRIPT'; $*"; }   # a fresh shell per call
gocli(){ local home=$1; shift; IRONGALL_HOME=$home "$work/irongall" "$@"; }
nopq_arg(){ [ "$kt" = no-pq ] && echo --no-pq; }

# --- 1. both ways, across renewals ---
ig_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
RL=$(recipe "$R" "ig_init $(nopq_arg)") && RA=${RL##*/} && ig_hex "$RA" && [ "$RL" = "$IG_BASE/to/$RA" ] && ok "recipe init prints its link: $RL" || bad "recipe init: $RL"
GL=$(gocli "$G" init $(nopq_arg)) && GA=${GL##*/} && ig_hex "$GA" && [ "$GL" = "$IG_BASE/to/$GA" ] && ok "Go init prints its link: $GL" || bad "Go init: $GL"
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
gocli "$G" rekey > /dev/null && ok "Go: rekey" || bad "Go: rekey"
printf 'after both renewals\n' | gocli "$G" send "$RA" > /dev/null && recipe "$R" "ig_send $GA '$work/body'" && ok "both ways after renewals: sent" || bad "send after renewals"
out=$(recipe "$R" ig_recv 2>&1) && grep -q 'after both renewals' <<< "$out" && ok "recipe receives after renewals" || bad "recipe after renewals: $out"
out=$(gocli "$G" recv 2>&1) && grep -q 'from the recipe' <<< "$out" && ok "Go receives after renewals" || bad "Go after renewals: $out"

# --- 2. one box, both clients ---
printf 'into the recipe box\n' | gocli "$G" send "$RA" > /dev/null || bad "send into the recipe's box"
out=$(gocli "$R" recv 2>&1) && grep -q 'into the recipe box' <<< "$out" && ok "the Go client receives in a box the recipe made" || bad "Go in the recipe's box: $out"
[ "$(gocli "$R" addr)" = "$RL" ] && [ "$(recipe "$G" ig_addr)" = "$GL" ] && ok "each client prints the other's box's link" || bad "addr across clients"
recipe "$R" "ig_send $GA '$work/body'" || bad "send into the Go box"
out=$(recipe "$G" ig_recv 2>&1) && grep -q 'from the recipe' <<< "$out" && ok "the recipe receives in a box Go made" || bad "recipe in Go's box: $out"
gocli "$R" rekey > /dev/null && recipe "$R" "ig_send $GA '$work/body'" && out=$(recipe "$G" ig_recv 2>&1) && grep -q 'from the recipe' <<< "$out" \
  && ok "the recipe's box renewed by Go, then used by the recipe" || bad "Go rekey of the recipe's box: $out"

# --- 3. the recipe's error path on a real problem+json ---
nobody=$(printf '%064d' 0)
err=$(recipe "$R" "ig_send $nobody '$work/body'" 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q '^ERROR 404 no_such_mailbox; the server says: "' <<< "$err" && ok "recipe prints a real problem's status and code, and the server's words as its words" || bad "recipe error path: rc=$rc $err"

# --- 4. the optional fields, sent/ and aliases, across the clients ---
recipe "$R" "ig_alias go $GL" > /dev/null && [ "$(gocli "$R" alias)" = "go $GA" ] && ok "an alias the recipe made is read by the Go client" || bad "the recipe's alias in the Go client"
gocli "$G" alias sh "$RL" > /dev/null && [ "$(recipe "$G" ig_alias)" = "sh $RA" ] && ok "an alias Go made is read by the recipe" || bad "Go's alias in the recipe"
M1=11111111-2222-4333-8444-555555555555
id=$(printf 'threaded, from Go\n' | gocli "$G" send --subject 'a subject' --reply-to $M1 sh) && ig_hex "$id" || bad "Go send with flags, to an alias: $id"
out=$(recipe "$R" ig_recv 2> "$work/err") && jq -e --arg m $M1 '.subject == "a subject" and .in_reply_to == $m and .body == "threaded, from Go\n"' <<< "$out" > /dev/null \
  && ok "Go → recipe: subject and in_reply_to arrive, sent to an alias" || bad "Go → recipe with flags: $out $(cat "$work/err")"
mid=$(jq -r .msg_id <<< "$out")
jq -e --arg id "$id" --argjson d "$out" '.receipt.id == $id and (.receipt | keys == ["expires_at", "id", "received_at"]) and del(.receipt) == $d' "$G/sent/$RA.$mid.json" > /dev/null \
  && ok "Go's sent/ record is the line its recipient delivered, plus the real server's receipt" || bad "Go's sent/ record: $(cat "$G/sent/$RA.$mid.json" 2>&1)"
recipe "$R" "ig_send --subject 'the reply' --reply-to $mid go '$work/body'" || bad "recipe send with options, to an alias"
out=$(gocli "$G" recv 2> "$work/err") && jq -e --arg m "$mid" --arg f "$RA" '.subject == "the reply" and .in_reply_to == $m and .from == $f' <<< "$out" > /dev/null \
  && ok "recipe → Go: a reply naming the message it answers, sent to an alias" || bad "recipe → Go with options: $out $(cat "$work/err")"
rec="$R/sent/$GA.$(jq -r .msg_id <<< "$out").json"
jq -e --argjson d "$out" '(.receipt | keys == ["expires_at", "id", "received_at"]) and del(.receipt) == $d' "$rec" > /dev/null && [ -e "$G/inbox/$(jq -r .receipt.id "$rec").json" ] \
  && ok "the recipe's sent/ record is the same, its receipt naming the file in the recipient's inbox/" || bad "the recipe's sent/ record: $(cat "$rec" 2>&1)"

# --- 5. a box whose identity is of the optional key type, ecdsa-sha2-nistp256, in each client ---
# The recipe takes the identity key it finds, so its box's key is made with ssh-keygen first. Each client's P-256 box
# then exchanges mail with the other client's Ed25519 box of step 1, which declared that it verifies the type.
RP="$work/rp"; GP="$work/gp"; mkdir -p "$RP"
ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$RP/identity" < /dev/null
RPL=$(recipe "$RP" "ig_init $(nopq_arg)") && RPA=${RPL##*/} && ig_hex "$RPA" && [ "$(sed -n 2p "$RP/identity.doc" | cut -d' ' -f1)" = ecdsa-sha2-nistp256 ] \
  && ok "recipe init on a P-256 identity made by ssh-keygen" || bad "recipe init on P-256: $RPL"
GPL=$(gocli "$GP" init --identity-type ecdsa-sha2-nistp256 $(nopq_arg) 2> "$work/err") && GPA=${GPL##*/} && ig_hex "$GPA" && grep -q '^WARNING: ' "$work/err" \
  && ok "Go init --identity-type ecdsa-sha2-nistp256, with its warning" || bad "Go init on P-256: $GPL $(cat "$work/err")"
[ "$(curl -s "$IG_BASE/v1/$GA/identity" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] && [ "$(curl -s "$IG_BASE/v1/$RA/identity" | jq -c .sender_key_types)" = '["ssh-ed25519","ecdsa-sha2-nistp256"]' ] \
  && ok "each client's box is served with the sender key types it declared" || bad "sender_key_types: $(curl -s "$IG_BASE/v1/$GA/identity" | jq -c .sender_key_types) $(curl -s "$IG_BASE/v1/$RA/identity" | jq -c .sender_key_types)"
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
GEL=$(IRONGALL_SENDER_KEY_TYPES=ssh-ed25519 gocli "$GE" init $(nopq_arg)) && GEA=${GEL##*/} && [ "$(curl -s "$IG_BASE/v1/$GEA/identity" | jq -c .sender_key_types)" = '["ssh-ed25519"]' ] \
  && ok "a box told to declare Ed25519 only is served so" || bad "IRONGALL_SENDER_KEY_TYPES: $(curl -s "$IG_BASE/v1/$GEA/identity")"
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
  L=$(recipe "$d" "$(clock "$off"); ig_init $(nopq_arg)" 2> "$work/err") && A=${L##*/} && ig_hex "$A" && GFL=$(gocli "$gf" init $(nopq_arg)) && GFA=${GFL##*/} \
    && printf 'to the box whose clock is off\n' | gocli "$gf" send "$L" > /dev/null \
    && out=$(recipe "$d" "$(clock "$off"); ig_recv" 2>> "$work/err") && jq -e --arg f "$GFA" '.body == "to the box whose clock is off\n" and .from == $f' <<< "$out" > /dev/null \
    && printf 'from the box whose clock is off\n' > "$work/body6" && recipe "$d" "$(clock "$off"); ig_send $GFL '$work/body6'" 2>> "$work/err" \
    && out=$(gocli "$gf" recv 2>> "$work/err") && jq -e --arg f "$A" '.body == "from the box whose clock is off\n" and .from == $f' <<< "$out" > /dev/null \
    && recipe "$d" "$(clock "$off"); ig_rekey $(nopq_arg)" 2>> "$work/err" \
    && ok "a recipe box whose clock is $name registers, renews, and exchanges mail with a Go box made that moment" || bad "clock $name: $out $(cat "$work/err")"
done
out=$(recipe "$work/clock-late" "$(clock -660); ig_init $(nopq_arg)" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 401 pass_expired" <<< "$out" && grep -q "the server's clock reads" <<< "$out" && grep -q "this machine's clock reads" <<< "$out" \
  && ok "a recipe box 11 minutes slow is refused at its pass: the server states its clock, and the recipe what its own reads" || bad "clock 11 minutes slow: $out"
out=$(recipe "$work/clock-early" "$(clock 3660); ig_init $(nopq_arg)" 2>&1); [ $? -ne 0 ] && grep -q "ERROR 400 bad_key" <<< "$out" && grep -q "has not begun; the server's clock reads" <<< "$out" \
  && L=$(recipe "$work/clock-early" "ig_init $(nopq_arg)" 2> "$work/err") && ig_hex "${L##*/}" \
  && ok "a recipe box first made 61 minutes fast is refused, the server stating its clock; with the clock right, the same box registers" || bad "clock 61 minutes fast: $out $(cat "$work/err")"

echo "interop: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ]

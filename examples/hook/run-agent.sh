#!/usr/bin/env bash
# run-agent.sh - a scripted agent gated end-to-end by deleguard.
#
# The agent is a small script (not a model): it wants to book a $450
# flight on united.com, and it may only do so through the pre-tool-call
# hook. The "booking" itself is a real local action: writing
# booking-confirmed.txt (a stub for a booking command). No money moves,
# no network call happens, no real agent account is used.
#
# Run:  bash examples/hook/run-agent.sh [work-dir]
#   - attempt 1, no approval: hook returns NEEDS-APPROVAL, the file is
#     NOT written (the agent is blocked before the action runs).
#   - a human approves the exact action with `deleguard approve`.
#   - attempt 2, with approval + audit log: hook returns ALLOW, the
#     file IS written, and the decision is in the audit log.
#   - attempt 3, same approval reused: hook returns DENY (single-use),
#     the file is NOT overwritten.
#
# Exit 0 when all three attempts behave as expected, 1 otherwise.
# Set DELEGUARD_BIN to point at the CLI (default: `deleguard` on PATH).
set -uo pipefail

HOOK="$(cd "$(dirname "$0")" && pwd)/pre-tool-call.sh"
WORK="${1:-/tmp/deleguard-hook-demo}"
DELEGUARD_BIN="${DELEGUARD_BIN:-deleguard}"
# A fresh `tsc` build leaves dist/cli.js non-executable, so a .js path
# is run through node; an installed `deleguard` on PATH runs directly.
if [[ "$DELEGUARD_BIN" == *.js ]]; then
  DG=(node "$DELEGUARD_BIN")
else
  DG=("$DELEGUARD_BIN")
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK" || fail "cannot cd to $WORK"

"${DG[@]}" init --dir "$WORK" > /dev/null || fail "deleguard init failed"
POLICY="$WORK/deleguard.json"
BOOK="$WORK/examples/actions/book.json"
APPROVAL="$WORK/examples/approvals/appr-1.json"
LOG="$WORK/deleguard-audit.jsonl"
BOOKING="$WORK/booking-confirmed.txt"
GATED=(node -e "require('node:fs').writeFileSync('booking-confirmed.txt', 'BOOKED flight.book \$450 united.com\n')")

echo "== attempt 1: book with no approval (expect BLOCKED, no file) =="
if DELEGUARD_BIN="$DELEGUARD_BIN" bash "$HOOK" --policy "$POLICY" --action "$BOOK" -- "${GATED[@]}"; then
  fail "attempt 1: hook allowed a booking with no approval"
fi
[ -e "$BOOKING" ] && fail "attempt 1: booking file was written despite the block"
echo "blocked as expected: booking-confirmed.txt does not exist"
echo ""

echo "== human approves the exact action =="
"${DG[@]}" approve --policy "$POLICY" --action "$BOOK" --by alice --out "$APPROVAL" > /dev/null \
  || fail "deleguard approve failed"
echo "approval issued: $APPROVAL"
echo ""

echo "== attempt 2: book with approval (expect ALLOW, file written) =="
DELEGUARD_BIN="$DELEGUARD_BIN" bash "$HOOK" --policy "$POLICY" --action "$BOOK" \
  --approval "$APPROVAL" --log "$LOG" -- "${GATED[@]}" \
  || fail "attempt 2: hook blocked an approved booking"
[ -f "$BOOKING" ] || fail "attempt 2: booking file was not written"
echo "allowed as expected: $(cat "$BOOKING")"
echo ""

echo "== attempt 3: reuse the same approval (expect BLOCKED, file kept) =="
if DELEGUARD_BIN="$DELEGUARD_BIN" bash "$HOOK" --policy "$POLICY" --action "$BOOK" \
  --approval "$APPROVAL" --log "$LOG" -- "${GATED[@]}"; then
  fail "attempt 3: hook allowed a reused approval"
fi
[ "$(cat "$BOOKING")" = 'BOOKED flight.book $450 united.com' ] \
  || fail "attempt 3: booking file changed on a blocked attempt"
echo "blocked as expected (single-use): booking file unchanged"
echo ""

echo "== audit log =="
"${DG[@]}" verify --log "$LOG" || fail "audit log did not verify"
echo ""
echo "HOOK DEMO OK: DENY blocked, ALLOW ran, reuse blocked."

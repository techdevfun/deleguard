#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Runs in a scratch dir so nothing pollutes the repo. The transcript is
# rendered to demo/deleguard-demo.gif by scripts/make-gif.py.
#
# The demo is the United travel fixture (SYNTHETIC: Alice, a $500 limit
# on united.com, $450 / $900 amounts are invented to show the rules;
# they are not United fares, limits, or policy). Approval expiry is
# demonstrated by checking with --at two hours past the issue time.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/deleguard-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/deleguard"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/work"
mkdir -p "$WORK"
cd "$WORK"
deleguard init --dir "$WORK" > /dev/null
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LATER="$(date -u -d "+2 hours" +%Y-%m-%dT%H:%M:%SZ)"

OUT="$ROOT/demo/transcript.txt"
{
  echo "# deleguard demo - real CLI output on the SYNTHETIC United travel fixture"
  echo "# (Alice, \$500 limit on united.com, \$450 / \$900 amounts are invented;"
  echo "#  see examples/README.md for provenance. Approval issued at $NOW.)"
  echo ""
  echo "\$ deleguard init"
  echo "deleguard.json + 6 example actions written (see above)"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/search.json"
  deleguard check --policy deleguard.json --action examples/actions/search.json || echo "exit: $?"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/book.json"
  deleguard check --policy deleguard.json --action examples/actions/book.json || echo "exit: $?"
  echo ""
  echo "\$ deleguard approve --policy deleguard.json --action examples/actions/book.json --by alice --out examples/approvals/appr-1.json"
  deleguard approve --policy deleguard.json --action examples/actions/book.json --by alice --out examples/approvals/appr-1.json
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/book.json --approval examples/approvals/appr-1.json --log deleguard-audit.jsonl"
  deleguard check --policy deleguard.json --action examples/actions/book.json --approval examples/approvals/appr-1.json --log deleguard-audit.jsonl || echo "exit: $?"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/book-over-limit.json"
  deleguard check --policy deleguard.json --action examples/actions/book-over-limit.json || echo "exit: $?"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/book-aggregator.json"
  deleguard check --policy deleguard.json --action examples/actions/book-aggregator.json || echo "exit: $?"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/sub-agent-no-grant.json"
  deleguard check --policy deleguard.json --action examples/actions/sub-agent-no-grant.json || echo "exit: $?"
  echo ""
  echo "\$ deleguard check --policy deleguard.json --action examples/actions/expired-approval.json --approval examples/approvals/appr-1.json --at $LATER"
  deleguard check --policy deleguard.json --action examples/actions/expired-approval.json --approval examples/approvals/appr-1.json --at "$LATER" || echo "exit: $?"
  echo ""
  echo "\$ deleguard audit --log deleguard-audit.jsonl"
  deleguard audit --log deleguard-audit.jsonl
  echo ""
  echo "\$ deleguard verify --log deleguard-audit.jsonl"
  deleguard verify --log deleguard-audit.jsonl
} > "$OUT" 2>&1
echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"

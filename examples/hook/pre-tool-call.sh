#!/usr/bin/env bash
# pre-tool-call.sh - gate a REAL command behind a deleguard verdict.
#
# A pre-tool-call hook for a scripted agent (or any harness): the gated
# command runs ONLY when `deleguard check` returns ALLOW (exit 0).
# DENY (exit 1) and NEEDS-APPROVAL (exit 2) both block the command, and
# the command never starts. Exit codes are the gate: the shell enforces
# them, no verdict is ever printed and then ignored.
#
# Usage:
#   pre-tool-call.sh --policy <file> --action <file>
#                    [--approval <file>] [--log <file>]
#                    -- <command...>
#
# The deleguard binary is found via $DELEGUARD_BIN, else `deleguard` on
# PATH (after `npm link`, or a symlink to dist/cli.js). The gated command
# is any real command: a booking script, a payment stub, a file write.
# Nothing here touches money, the network, or a real agent account: the
# demo in run-agent.sh gates a local file write.
set -uo pipefail

POLICY=""
ACTION=""
APPROVAL=""
LOG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --policy)   POLICY="$2"; shift 2 ;;
    --action)   ACTION="$2"; shift 2 ;;
    --approval) APPROVAL="$2"; shift 2 ;;
    --log)      LOG="$2"; shift 2 ;;
    --)         shift; break ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$POLICY" ] || [ -z "$ACTION" ]; then
  echo "usage: pre-tool-call.sh --policy <file> --action <file> [--approval <file>] [--log <file>] -- <command...>" >&2
  exit 2
fi
if [ $# -eq 0 ]; then
  echo "error: no command given after --" >&2
  exit 2
fi

DELEGUARD_BIN="${DELEGUARD_BIN:-deleguard}"
# A fresh `tsc` build leaves dist/cli.js non-executable, so a .js path
# is run through node; an installed `deleguard` on PATH runs directly.
if [[ "$DELEGUARD_BIN" == *.js ]]; then
  DG=(node "$DELEGUARD_BIN")
else
  DG=("$DELEGUARD_BIN")
fi

CHECK_ARGS=(check --policy "$POLICY" --action "$ACTION")
if [ -n "$APPROVAL" ]; then CHECK_ARGS+=(--approval "$APPROVAL"); fi
if [ -n "$LOG" ]; then CHECK_ARGS+=(--log "$LOG"); fi

if "${DG[@]}" "${CHECK_ARGS[@]}"; then
  echo "deleguard: ALLOW - running the gated command: $*" >&2
  exec "$@"
else
  CODE=$?
  echo "deleguard: BLOCKED (check exit $CODE) - gated command NOT run: $*" >&2
  exit "$CODE"
fi

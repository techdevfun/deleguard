# Pre-tool-call hook (a real harness, not a fixture)

`pre-tool-call.sh` gates a REAL command behind a deleguard verdict.
It is the hook a scripted agent (or any harness) calls before a tool
runs: the gated command executes ONLY when `deleguard check` returns
ALLOW (exit 0). DENY (exit 1) and NEEDS-APPROVAL (exit 2) both block
it, and the command never starts. The shell enforces the exit code;
no verdict is printed and then ignored.

## Use it

```sh
# Book a flight only if the policy allows this exact action:
bash pre-tool-call.sh --policy deleguard.json --action examples/actions/book.json \
  --approval examples/approvals/appr-1.json --log deleguard-audit.jsonl \
  -- ./book-flight.sh
# ALLOW (exit 0) -> ./book-flight.sh runs.
# DENY or NEEDS-APPROVAL -> it never runs, exit code is the check's.
```

The deleguard binary comes from `$DELEGUARD_BIN` (a path to
`dist/cli.js` works, it is run through node) or from `deleguard` on
your PATH (after `npm link`). The gated command is any real command:
a booking script, a payment stub, a file write.

## Demo: a scripted agent, gated end to end

`run-agent.sh` is the scripted agent. It wants to book a $450 flight
on united.com and may only do so through the hook. The "booking" is a
real local action (writing `booking-confirmed.txt`, a stub for a
booking command). No money moves, no network call happens, no real
agent account is used.

```sh
bash examples/hook/run-agent.sh
```

It proves three things, with the file as the witness:

1. Attempt 1, no approval: NEEDS-APPROVAL blocks the write.
   `booking-confirmed.txt` does not exist.
2. A human approves the exact action; attempt 2: ALLOW runs the
   write. The file exists and says `BOOKED flight.book $450`.
3. Attempt 3 reuses the same approval: DENY (single-use) blocks the
   write and the file is unchanged. `verify` then confirms the log.

The same three attempts are asserted in `test/e2e.test.js`, so CI
proves the hook blocks and allows a real action on every push.

## Time to first gated action (measured, not estimated)

Measured on this machine, 12 November 2026, from a source checkout:

- `npm install` + `npm run build`: 4.0 s (a second run: 3.8 s).
- `run-agent.sh` (init, blocked attempt, approve, allowed attempt,
  reuse blocked, verify): 0.9 s.
- Total, source checkout to first gated action: about 5 seconds of
  command time, excluding the time to read the docs.

For comparison, the rivals document their own first-run paths in
minutes, not seconds, and we did not re-time them ourselves:

- Agent_Sudo calls its evaluation path "Evaluate Agent_Sudo in
  5 Minutes" (`pipx install agent-sudo-mcp && agent-sudo eval`,
  PyPI `agent-sudo-mcp` 0.5.6); wiring it into an agent after that
  needs `agent-sudo init-approval`, `agent-sudo workspace set`, and
  editing the MCP client config with absolute paths.
- tenuo calls its Python quickstart "Get running in 5 minutes"
  (PyPI `tenuo`); its Claude Code path (`tenuo-claude-code`) needs
  Python 3.10+ plus Docker or a native authorizer install
  (`tenuo-claude install-authorizer`, then `bootstrap`).

The honest trade: deleguard is faster to a first gated action because
it does less. It has no cryptography, no proof-of-possession, no
enforcement at a tool boundary, and no MCP server. If you need those,
use tenuo or Agent_Sudo (see "Where rivals beat us" in the README).
What deleguard offers is the smallest possible gate: one shell call,
one JSON policy, exit codes, no keys, no server.

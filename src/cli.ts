#!/usr/bin/env node
/**
 * deleguard 0.1.0 - a pre-execution authorization gate for agent actions.
 *
 *   deleguard init [--dir <dir>]
 *   deleguard check --policy <file> --action <file> [--approval <file>]
 *                    [--at <ISO>] [--format table|json] [--log <file>]
 *   deleguard approve --policy <file> --action <file> --by <human>
 *                     [--expires-minutes N] [--out <file>]
 *   deleguard explain --policy <file> --action <file> [--approval <file>]
 *   deleguard audit --log <file> [--format table|json]
 *   deleguard verify --log <file>
 *
 * Exit codes for `check`: 0 = ALLOW, 1 = DENY, 2 = NEEDS-APPROVAL or
 * POLICY_ERROR. `approve` refuses (exit 1) when the action is DENY for
 * non-approval reasons. `explain` always exits 0. `audit` exits 0.
 * `verify` exits 0 when the log is clean, 1 when it is not.
 *
 * deleguard only ANSWERS the delegation question. It does not intercept
 * tool calls, run a proxy, establish identity, or call any API. The
 * harness decides what to do with the verdict.
 */
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  loadAction,
  loadApproval,
  loadPolicy,
  PolicyError,
  type Approval,
} from "./policy.js";
import { evaluate, actionDigest, type Evaluation } from "./evaluate.js";
import {
  appendRecord,
  consumedApprovalIds,
  readLog,
  verifyLog,
} from "./audit.js";
import { scaffold } from "./init.js";

export const VERSION = "0.1.0";

const HELP = `deleguard ${VERSION} - a pre-execution authorization gate for agent actions.

Usage:
  deleguard init [--dir <dir>]
  deleguard check --policy <file> --action <file> [--approval <file>]
                  [--at <ISO>] [--format table|json] [--log <file>]
  deleguard approve --policy <file> --action <file> --by <human>
                    [--expires-minutes N] [--out <file>]
  deleguard explain --policy <file> --action <file> [--approval <file>]
  deleguard audit --log <file> [--format table|json]
  deleguard verify --log <file>

Commands:
  init      Scaffold deleguard.json + 6 example actions (United travel
            fixture) in a directory. Refuses to overwrite.
  check     Answer ALLOW (exit 0), DENY (exit 1) or NEEDS-APPROVAL
            (exit 2) for one action against a policy. A malformed
            policy is POLICY_ERROR (exit 2, fail closed).
  approve   Issue an approval bound to the exact action (sha256 of the
            canonical action JSON). Default expiry 15 minutes. Refuses
            when the action is DENY for non-approval reasons.
  explain   Print the per-rule trace for one action. Exit 0.
  audit     List decisions from an audit log. Exit 0.
  verify    Check an audit log's hash chain and sequence. Exit 0/1.

Options:
  --policy <f>       Policy file (deleguard.json).
  --action <f>       Action file (JSON).
  --approval <f>     Approval file from 'deleguard approve'.
  --at <ISO>         Evaluation time (default: now). For tests.
  --format <f>       table (default) or json.
  --log <f>          Audit log to append the decision to (check) or read.
  --by <human>       Who issues the approval (approve).
  --expires-minutes N  Approval lifetime in minutes (default 15).
  --out <f>          Where to write the approval JSON (default: stdout).
  --dir <dir>        Directory for 'init' (default: current directory).

deleguard decides; it does not enforce. Identity binding belongs to the
harness that calls it. See README.md "Honest limits".`;

interface Flags {
  [key: string]: string | boolean | undefined;
}

function parseArgs(argv: string[]): { cmd: string; flags: Flags; rest: string[] } {
  const flags: Flags = {};
  const rest: string[] = [];
  let cmd = "";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else if (cmd === "") {
      cmd = a;
    } else {
      rest.push(a);
    }
  }
  return { cmd, flags, rest };
}

function flagStr(flags: Flags, name: string): string | undefined {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

function need(flags: Flags, name: string): string {
  const v = flagStr(flags, name);
  if (v === undefined) {
    console.error(`error: --${name} is required`);
    process.exit(2);
  }
  return v;
}

function renderCheckTable(ev: Evaluation, actionTool: string): string {
  const lines: string[] = [];
  lines.push(`deleguard check - ${actionTool}`);
  lines.push("");
  lines.push("Rule               Result  Detail");
  lines.push("------------------------------------------------------------------------");
  for (const r of ev.reasons) {
    // No truncation: the full rule message must render (the APPROVAL_VALID
    // line is the headline proof of exact-action binding).
    lines.push(`${r.rule.padEnd(18)} ${(r.pass ? "PASS" : "FAIL").padEnd(7)} ${r.message}`);
  }
  lines.push("------------------------------------------------------------------------");
  lines.push(`VERDICT ${ev.verdict} (policy ${ev.policyHash.slice(0, 12)}, action ${ev.actionDigest.slice(0, 12)})`);
  return lines.join("\n");
}

function renderCheckJson(ev: Evaluation): string {
  return JSON.stringify(
    {
      verdict: ev.verdict,
      reasons: ev.reasons,
      policyHash: ev.policyHash,
      actionDigest: ev.actionDigest,
      approvalRequired: ev.approvalRequired,
    },
    null,
    2,
  );
}

function exitForVerdict(v: string): number {
  if (v === "ALLOW") return 0;
  if (v === "DENY") return 1;
  return 2;
}

function loadEvalInputs(flags: Flags): {
  policy: ReturnType<typeof loadPolicy>["policy"];
  policyHash: string;
  action: ReturnType<typeof loadAction>;
  approval: Approval | undefined;
  at: Date | undefined;
} {
  const { policy, hash } = loadPolicy(resolve(need(flags, "policy")));
  const action = loadAction(resolve(need(flags, "action")));
  const approvalPath = flagStr(flags, "approval");
  const approval = approvalPath ? loadApproval(resolve(approvalPath)) : undefined;
  const atStr = flagStr(flags, "at");
  const at = atStr ? new Date(atStr) : undefined;
  if (at !== undefined && Number.isNaN(at.getTime())) {
    console.error(`error: --at "${atStr}" is not a valid ISO timestamp`);
    process.exit(2);
  }
  return { policy, policyHash: hash, action, approval, at };
}

function cmdInit(flags: Flags, rest: string[]): number {
  const dir = resolve(flagStr(flags, "dir") ?? rest[0] ?? ".");
  let written: string[];
  try {
    written = scaffold(dir);
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    return 1;
  }
  console.log(`deleguard init - wrote ${written.length} file(s) to ${dir}:`);
  for (const f of written) console.log(`  ${f}`);
  console.log("");
  console.log("Next steps:");
  console.log("  deleguard check --policy deleguard.json --action examples/actions/search.json");
  console.log("  deleguard check --policy deleguard.json --action examples/actions/book.json");
  console.log("  deleguard approve --policy deleguard.json --action examples/actions/book.json --by alice");
  return 0;
}

function cmdCheck(flags: Flags): number {
  const { policy, policyHash, action, approval, at } = loadEvalInputs(flags);
  const logPath = flagStr(flags, "log");
  const consumed = consumedApprovalIds(logPath ? resolve(logPath) : undefined);
  const ev = evaluate(policy, policyHash, action, {
    approval,
    consumedApprovalIds: consumed,
    at,
  });
  const format = flagStr(flags, "format") ?? "table";
  if (approval && !logPath) {
    // Single-use is enforced by scanning the audit log at check time.
    // Without --log it cannot be checked, so warn loudly on stderr
    // (stdout stays clean for --format json). The verdict is unchanged:
    // ALLOW stays ALLOW; the operator is told the approval may replay.
    console.error(
      "warning: --approval used without --log, so single-use cannot be checked.",
    );
    console.error(
      "warning: this approval may be replayed; pass --log <file> to enforce single-use.",
    );
  }
  if (format === "json") console.log(renderCheckJson(ev));
  else console.log(renderCheckTable(ev, action.tool));
  if (logPath) {
    const ts = (at ?? new Date()).toISOString();
    appendRecord(resolve(logPath), {
      ts,
      policyVersion: policy.version,
      policyHash,
      principal: action.principal,
      agent: action.agent,
      tool: action.tool,
      evaluation: ev,
      approvalId: approval ? approval.approvalId : null,
    });
  }
  return exitForVerdict(ev.verdict);
}

function cmdApprove(flags: Flags): number {
  const { policy, policyHash, action } = loadEvalInputs(flags);
  const by = need(flags, "by");
  const minutesRaw = flagStr(flags, "expires-minutes");
  const minutes = minutesRaw === undefined ? 15 : Number(minutesRaw);
  if (!Number.isFinite(minutes) || minutes <= 0) {
    console.error("error: --expires-minutes must be a number > 0");
    return 2;
  }
  // An approval cannot launder a denied action: evaluate without one
  // and refuse unless the verdict is ALLOW or NEEDS-APPROVAL.
  const probe = evaluate(policy, policyHash, action, {});
  if (probe.verdict === "DENY") {
    console.error("error: refusing to approve an action that is DENY for non-approval reasons:");
    for (const r of probe.reasons.filter((x) => !x.pass)) {
      console.error(`  ${r.rule}: ${r.message}`);
    }
    return 1;
  }
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + minutes * 60 * 1000);
  const approval: Approval = {
    approvalId: "appr-" + randomBytes(6).toString("hex"),
    actionDigest: actionDigest(action),
    principal: action.principal,
    agent: action.agent,
    tool: action.tool,
    amount: action.amount,
    issuedBy: by,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    used: false,
  };
  const out = flagStr(flags, "out");
  const text = JSON.stringify(approval, null, 2) + "\n";
  if (out) {
    if (existsSync(resolve(out))) {
      console.error(`error: refusing to overwrite existing file: ${out}`);
      return 1;
    }
    writeFileSync(resolve(out), text, "utf8");
    console.log(`approval ${approval.approvalId} written to ${out}`);
  } else {
    console.log(text.trimEnd());
  }
  console.log(
    `approval ${approval.approvalId} for ${action.tool} (${action.amount ?? "-"} ${action.currency ?? ""}) - expires ${approval.expiresAt}`,
  );
  return 0;
}

function cmdExplain(flags: Flags): number {
  const { policy, policyHash, action, approval, at } = loadEvalInputs(flags);
  const logPath = flagStr(flags, "log");
  const consumed = consumedApprovalIds(logPath ? resolve(logPath) : undefined);
  const ev = evaluate(policy, policyHash, action, {
    approval,
    consumedApprovalIds: consumed,
    at,
  });
  console.log(`deleguard explain - ${action.tool} by ${action.principal} via ${action.agent}`);
  console.log(`chain: ${(action.chain as string[]).join(" -> ")}`);
  console.log("");
  for (const r of ev.reasons) {
    console.log(`${r.pass ? "PASS" : "FAIL"} ${r.rule}: ${r.message}`);
  }
  console.log("");
  console.log(`Verdict: ${ev.verdict}`);
  console.log("Note: deleguard trusts the caller-supplied identity. The harness");
  console.log("must bind identity before calling deleguard; this tool does not");
  console.log("authenticate anyone. A generic user_confirmed flag is ignored;");
  console.log("only an approval bound to this exact action digest counts.");
  return 0;
}

function cmdAudit(flags: Flags): number {
  const logArg = need(flags, "log");
  const logPath = resolve(logArg);
  const records = readLog(logPath);
  if (records.length === 0) {
    console.log(`audit log ${logArg} is empty or missing - no decisions recorded.`);
    return 0;
  }
  const format = flagStr(flags, "format") ?? "table";
  if (format === "json") {
    console.log(JSON.stringify(records, null, 2));
    return 0;
  }
  console.log("Seq  Time                 Principal  Agent         Tool           Verdict");
  console.log("------------------------------------------------------------------------");
  for (const r of records) {
    console.log(
      `${String(r.seq).padEnd(5)} ${r.ts.padEnd(20)} ${r.principal.padEnd(10)} ${r.agent.padEnd(13)} ${r.tool.padEnd(14)} ${r.verdict}`,
    );
  }
  console.log("------------------------------------------------------------------------");
  console.log(`${records.length} decision(s) in ${logArg}`);
  return 0;
}

function cmdVerify(flags: Flags): number {
  const logPath = resolve(need(flags, "log"));
  const result = verifyLog(logPath);
  if (result.ok) {
    console.log(`verify OK: ${result.records} record(s), hash chain intact, no gaps, no secret-looking values.`);
    return 0;
  }
  console.log(`verify FAILED: ${result.records} record(s), ${result.issues.length} issue(s):`);
  for (const issue of result.issues) {
    console.log(`  seq ${issue.seq ?? "?"}: ${issue.message}`);
  }
  return 1;
}

function main(argv: string[]): number {
  const { cmd, flags, rest } = parseArgs(argv);
  if (flags.help === true || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return 0;
  }
  if (cmd === "--version" || cmd === "-v" || flags.version === true) {
    console.log(`deleguard ${VERSION}`);
    return 0;
  }
  try {
    switch (cmd) {
      case "init":
        return cmdInit(flags, rest);
      case "check":
        return cmdCheck(flags);
      case "approve":
        return cmdApprove(flags);
      case "explain":
        return cmdExplain(flags);
      case "audit":
        return cmdAudit(flags);
      case "verify":
        return cmdVerify(flags);
      case "":
        console.log(HELP);
        return 0;
      default:
        console.error(`error: unknown command "${cmd}"`);
        console.log(HELP);
        return 2;
    }
  } catch (err) {
    if (err instanceof PolicyError) {
      console.error(err.message);
      return 2;
    }
    console.error(`error: ${(err as Error).message}`);
    return 2;
  }
}

process.exit(main(process.argv.slice(2)));

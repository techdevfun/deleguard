/**
 * End-to-end CLI tests: run the real built binary in a temp directory
 * through the full init -> check -> approve -> check -> audit -> verify
 * flow, plus exit codes, JSON output, policy errors, and the audit
 * hash-chain tamper check.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;
const AT = "2026-11-12T14:00:00Z";

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "deleguard-e2e-"));
  const init = run(["init", "--dir", dir], dir);
  assert.equal(init.status, 0, init.stderr);
  return dir;
}

test("full flow: init -> search ALLOW -> book NEEDS-APPROVAL -> approve -> book ALLOW -> audit -> verify", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = (n) => join(dir, "examples", "actions", n);
  const log = join(dir, "deleguard-audit.jsonl");

  const search = run(["check", "--policy", pol, "--action", act("search.json"), "--at", AT], dir);
  assert.equal(search.status, 0, search.stdout + search.stderr);
  assert.match(search.stdout, /VERDICT ALLOW/);

  const book = run(["check", "--policy", pol, "--action", act("book.json"), "--at", AT], dir);
  assert.equal(book.status, 2, book.stdout);
  assert.match(book.stdout, /VERDICT NEEDS-APPROVAL/);

  const apprOut = join(dir, "examples", "approvals", "appr-1.json");
  const approve = run(
    ["approve", "--policy", pol, "--action", act("book.json"), "--by", "alice", "--out", apprOut],
    dir,
  );
  assert.equal(approve.status, 0, approve.stdout + approve.stderr);
  assert.ok(existsSync(apprOut));
  const appr = JSON.parse(readFileSync(apprOut, "utf8"));
  assert.equal(appr.actionDigest.length, 64);
  assert.equal(appr.used, false);

  // The approval was issued at real now; check at real now (no --at)
  // so the 15-minute window holds.
  const bookOk = run(
    ["check", "--policy", pol, "--action", act("book.json"), "--approval", apprOut, "--log", log],
    dir,
  );
  assert.equal(bookOk.status, 0, bookOk.stdout + bookOk.stderr);
  assert.match(bookOk.stdout, /VERDICT ALLOW/);

  // Reusing the same approval is DENY (single-use, enforced via the log).
  const reuse = run(
    ["check", "--policy", pol, "--action", act("book.json"), "--approval", apprOut, "--log", log],
    dir,
  );
  assert.equal(reuse.status, 1, reuse.stdout);
  assert.match(reuse.stdout, /APPROVAL_VALID/);

  const audit = run(["audit", "--log", log], dir);
  assert.equal(audit.status, 0, audit.stderr);
  assert.match(audit.stdout, /ALLOW/);
  assert.match(audit.stdout, /DENY/);

  const verify = run(["verify", "--log", log], dir);
  assert.equal(verify.status, 0, verify.stdout + verify.stderr);
  assert.match(verify.stdout, /verify OK/);
});

test("demo denials: over-limit, aggregator, sub-agent (exit 1 each)", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = (n) => join(dir, "examples", "actions", n);
  for (const [file, rule] of [
    ["book-over-limit.json", "AMOUNT"],
    ["book-aggregator.json", "MERCHANT"],
    ["sub-agent-no-grant.json", "CHAIN"],
  ]) {
    const r = run(["check", "--policy", pol, "--action", act(file), "--at", AT], dir);
    assert.equal(r.status, 1, `${file}: ${r.stdout}`);
    assert.match(r.stdout, new RegExp(rule), `${file} should fail ${rule}`);
    assert.match(r.stdout, /VERDICT DENY/);
  }
});

test("expired approval is DENY (check with --at past expiry)", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = join(dir, "examples", "actions", "book.json");
  const apprOut = join(dir, "examples", "approvals", "appr-exp.json");
  const approve = run(
    ["approve", "--policy", pol, "--action", act, "--by", "alice", "--out", apprOut],
    dir,
  );
  assert.equal(approve.status, 0, approve.stderr);
  const later = run(
    ["check", "--policy", pol, "--action", act, "--approval", apprOut, "--at", "2026-11-12T16:00:00Z"],
    dir,
  );
  assert.equal(later.status, 1, later.stdout);
  assert.match(later.stdout, /approval expired/);
});

test("approve refuses a DENY action (cannot launder over-limit)", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = join(dir, "examples", "actions", "book-over-limit.json");
  const r = run(["approve", "--policy", pol, "--action", act, "--by", "alice"], dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to approve/);
});

test("approve refuses a DENY action for a denied tool", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const cancel = join(dir, "cancel.json");
  writeFileSync(
    cancel,
    JSON.stringify({
      principal: "alice",
      agent: "travel-agent",
      chain: ["alice", "travel-agent"],
      tool: "flight.cancel",
      merchant: "united.com",
    }),
  );
  const r = run(["approve", "--policy", pol, "--action", cancel, "--by", "alice"], dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to approve/);
});

test("check --format json returns verdict + reasons + hashes", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = join(dir, "examples", "actions", "search.json");
  const r = run(
    ["check", "--policy", pol, "--action", act, "--at", AT, "--format", "json"],
    dir,
  );
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.verdict, "ALLOW");
  assert.equal(out.policyHash.length, 64);
  assert.equal(out.actionDigest.length, 64);
  assert.ok(Array.isArray(out.reasons) && out.reasons.length > 0);
});

test("explain prints the per-rule trace and exits 0", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const act = join(dir, "examples", "actions", "book-aggregator.json");
  const r = run(["explain", "--policy", pol, "--action", act, "--at", AT], dir);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /FAIL MERCHANT/);
  assert.match(r.stdout, /Verdict: DENY/);
});

test("malformed policy fails closed with POLICY_ERROR (exit 2, no verdict)", () => {
  const dir = setup();
  const bad = join(dir, "bad-policy.json");
  const pol = JSON.parse(readFileSync(join(dir, "deleguard.json"), "utf8"));
  pol.delegations[0].maxAmount = -5;
  writeFileSync(bad, JSON.stringify(pol));
  const r = run(
    ["check", "--policy", bad, "--action", join(dir, "examples", "actions", "search.json")],
    dir,
  );
  assert.equal(r.status, 2);
  assert.match(r.stderr, /POLICY_ERROR/);
  assert.doesNotMatch(r.stdout, /VERDICT/);
});

test("init refuses to overwrite an existing policy", () => {
  const dir = setup();
  const r = run(["init", "--dir", dir], dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to overwrite/);
});

test("audit on a missing log is a clear message, exit 0", () => {
  const dir = setup();
  const r = run(["audit", "--log", join(dir, "nope.jsonl")], dir);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /empty or missing/);
});

test("verify catches a tampered audit log (edited verdict)", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const log = join(dir, "deleguard-audit.jsonl");
  const search = join(dir, "examples", "actions", "search.json");
  const ok = run(["check", "--policy", pol, "--action", search, "--at", AT, "--log", log], dir);
  assert.equal(ok.status, 0);
  const lines = readFileSync(log, "utf8").trim().split("\n");
  const rec = JSON.parse(lines[0]);
  rec.verdict = "DENY";
  writeFileSync(log, JSON.stringify(rec) + "\n");
  const v = run(["verify", "--log", log], dir);
  assert.equal(v.status, 1);
  assert.match(v.stdout, /verify FAILED/);
  assert.match(v.stdout, /does not recompute/);
});

test("verify catches a sequence gap (deleted record)", () => {
  const dir = setup();
  const pol = join(dir, "deleguard.json");
  const log = join(dir, "deleguard-audit.jsonl");
  const search = join(dir, "examples", "actions", "search.json");
  run(["check", "--policy", pol, "--action", search, "--at", AT, "--log", log], dir);
  run(["check", "--policy", pol, "--action", search, "--at", AT, "--log", log], dir);
  const lines = readFileSync(log, "utf8").trim().split("\n");
  writeFileSync(log, lines[1] + "\n"); // keep only seq 2
  const v = run(["verify", "--log", log], dir);
  assert.equal(v.status, 1);
  assert.match(v.stdout, /sequence gap/);
});

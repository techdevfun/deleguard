/**
 * Unit tests for deleguard's policy evaluation: the decision matrix.
 * Pure function tests against dist/evaluate.js - no CLI, no disk, no
 * network. Times are injected with --at equivalents (Date objects).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../dist/evaluate.js";
import { validatePolicy, sha256Hex, canonicalJson } from "../dist/policy.js";
import { DEFAULT_POLICY } from "../dist/init.js";

const AT = new Date("2026-11-12T14:00:00Z");
const HASH = sha256Hex(canonicalJson(DEFAULT_POLICY));

function policy(overrides = {}) {
  const p = JSON.parse(JSON.stringify(DEFAULT_POLICY));
  return { ...p, ...overrides };
}

function action(overrides = {}) {
  return {
    principal: "alice",
    agent: "travel-agent",
    chain: ["alice", "travel-agent"],
    tool: "flight.search",
    merchant: "united.com",
    dataClasses: ["itinerary", "price"],
    ...overrides,
  };
}

function ev(p, a, opts = {}) {
  const pol = validatePolicy(p);
  return evaluate(pol, sha256Hex(canonicalJson(pol)), a, { at: AT, ...opts });
}

function failedRules(result) {
  return result.reasons.filter((r) => !r.pass).map((r) => r.rule);
}

test("search on united.com is ALLOW", () => {
  const r = ev(policy(), action());
  assert.equal(r.verdict, "ALLOW");
  assert.deepEqual(failedRules(r), []);
});

test("book $450 needs approval (threshold 0)", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 450, currency: "USD" }),
  );
  assert.equal(r.verdict, "NEEDS-APPROVAL");
  assert.deepEqual(failedRules(r), ["APPROVAL_REQUIRED"]);
});

test("book $450 with a generic user_confirmed flag still needs approval", () => {
  const r = ev(
    policy(),
    action({
      tool: "flight.book",
      amount: 450,
      currency: "USD",
      user_confirmed: true,
    }),
  );
  assert.equal(r.verdict, "NEEDS-APPROVAL");
});

test("book $900 over the $500 limit is DENY", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 900, currency: "USD" }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("AMOUNT"));
});

test("book at exactly the $500 limit is NEEDS-APPROVAL, not DENY", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 500, currency: "USD" }),
  );
  assert.equal(r.verdict, "NEEDS-APPROVAL");
  assert.ok(!failedRules(r).includes("AMOUNT"));
});

test("book $450 in EUR is DENY (currency mismatch)", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 450, currency: "EUR" }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("AMOUNT"));
});

test("book via kayak.com is DENY (merchant allowlist is exact-host)", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 450, currency: "USD", merchant: "kayak.com" }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("MERCHANT"));
});

test("book via www.united.com is DENY (exact host, no subdomain wildcard)", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: 450, currency: "USD", merchant: "www.united.com" }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("MERCHANT"));
});

test("flight.cancel is DENY (deniedTools beats the grant)", () => {
  const r = ev(policy(), action({ tool: "flight.cancel" }));
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("DENIED_TOOL"));
});

test("book with no amount is DENY (never assume 0)", () => {
  const a = action({ tool: "flight.book", currency: "USD" });
  delete a.amount;
  const r = ev(policy(), a);
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("AMOUNT"));
});

test("book with no merchant is DENY", () => {
  const a = action({ tool: "flight.book", amount: 100, currency: "USD" });
  delete a.merchant;
  const r = ev(policy(), a);
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("MERCHANT"));
});

test("negative amount is DENY", () => {
  const r = ev(
    policy(),
    action({ tool: "flight.book", amount: -5, currency: "USD" }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("AMOUNT"));
});

test("data class outside the grant is DENY", () => {
  const r = ev(policy(), action({ dataClasses: ["itinerary", "payment-card"] }));
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("DATA_CLASSES"));
});

test("sub-agent without a grant is DENY (no implicit inheritance)", () => {
  const r = ev(
    policy(),
    action({
      agent: "sub-agent",
      chain: ["alice", "travel-agent", "sub-agent"],
      tool: "flight.book",
      amount: 200,
      currency: "USD",
    }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("CHAIN"));
});

test("chain depth over maxDepth is DENY even with a grant", () => {
  const p = policy();
  p.delegations.push({
    id: "del-2",
    from: "travel-agent",
    to: "sub-agent",
    tools: ["flight.search", "flight.book"],
    maxAmount: 500,
    currency: "USD",
    merchants: ["united.com"],
    dataClasses: ["itinerary", "price"],
    notBefore: "2026-11-01T00:00:00Z",
    expiresAt: "2026-12-31T23:59:59Z",
    maxDepth: 1,
    requireApprovalAbove: 0,
  });
  const r = ev(
    p,
    action({
      agent: "sub-agent",
      chain: ["alice", "travel-agent", "sub-agent"],
      tool: "flight.search",
    }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("CHAIN_DEPTH"));
});

test("child grant widening the parent is DENY (subset rule)", () => {
  const p = policy();
  p.delegations.push({
    id: "del-2",
    from: "travel-agent",
    to: "sub-agent",
    tools: ["flight.search", "flight.book"],
    maxAmount: 900,
    currency: "USD",
    merchants: ["united.com"],
    dataClasses: ["itinerary", "price"],
    notBefore: "2026-11-01T00:00:00Z",
    expiresAt: "2026-12-31T23:59:59Z",
    maxDepth: 2,
    requireApprovalAbove: 0,
  });
  // Parent maxDepth is 1, so depth also fails; widen check must appear too.
  const r = ev(
    p,
    action({
      agent: "sub-agent",
      chain: ["alice", "travel-agent", "sub-agent"],
      tool: "flight.search",
    }),
  );
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("CHAIN_SUBSET"));
});

test("a proper two-hop chain within depth 2 is ALLOW", () => {
  const p = policy();
  p.delegations[0].maxDepth = 2;
  p.delegations.push({
    id: "del-2",
    from: "travel-agent",
    to: "sub-agent",
    tools: ["flight.search"],
    maxAmount: 500,
    currency: "USD",
    merchants: ["united.com"],
    dataClasses: ["itinerary"],
    notBefore: "2026-11-01T00:00:00Z",
    expiresAt: "2026-12-01T23:59:59Z",
    maxDepth: 2,
  });
  const r = ev(
    p,
    action({
      agent: "sub-agent",
      chain: ["alice", "travel-agent", "sub-agent"],
      tool: "flight.search",
      dataClasses: ["itinerary"],
    }),
  );
  assert.equal(r.verdict, "ALLOW");
});

test("expired grant is DENY", () => {
  const r = ev(policy(), action(), { at: new Date("2027-01-05T00:00:00Z") });
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("TIME_WINDOW"));
});

test("grant not yet active is DENY", () => {
  const r = ev(policy(), action(), { at: new Date("2026-10-15T00:00:00Z") });
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("TIME_WINDOW"));
});

test("unknown tool in the action is DENY", () => {
  const r = ev(policy(), action({ tool: "hotel.book" }));
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("TOOL_ALLOWED"));
});

test("chain not starting at the principal is DENY", () => {
  const r = ev(policy(), action({ chain: ["travel-agent", "sub-agent"], agent: "sub-agent" }));
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("CHAIN"));
});

// --- Approvals: binding, reuse, expiry.

function makeApproval(a, overrides = {}) {
  const { sha256Hex: h, canonicalJson: c } = { sha256Hex, canonicalJson };
  return {
    approvalId: "appr-test1",
    actionDigest: h(c(a)),
    principal: "alice",
    agent: "travel-agent",
    tool: "flight.book",
    amount: 450,
    issuedBy: "alice",
    issuedAt: "2026-11-12T13:55:00Z",
    expiresAt: "2026-11-12T14:10:00Z",
    used: false,
    ...overrides,
  };
}

const BOOK = action({ tool: "flight.book", amount: 450, currency: "USD" });

test("valid approval bound to the exact action turns book ALLOW", () => {
  const r = ev(policy(), BOOK, { approval: makeApproval(BOOK) });
  assert.equal(r.verdict, "ALLOW");
  assert.equal(r.approvalConsumed, true);
});

test("approval for a different amount is DENY (digest binding)", () => {
  const other = action({ tool: "flight.book", amount: 451, currency: "USD" });
  const r = ev(policy(), BOOK, { approval: makeApproval(other) });
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("APPROVAL_VALID"));
});

test("approval reused after consumption is DENY (single-use)", () => {
  const appr = makeApproval(BOOK);
  const first = ev(policy(), BOOK, { approval: appr });
  assert.equal(first.verdict, "ALLOW");
  const second = ev(policy(), BOOK, {
    approval: appr,
    consumedApprovalIds: new Set([appr.approvalId]),
  });
  assert.equal(second.verdict, "DENY");
  assert.ok(failedRules(second).includes("APPROVAL_VALID"));
});

test("expired approval is DENY", () => {
  const appr = makeApproval(BOOK, { expiresAt: "2026-11-12T13:59:00Z" });
  const r = ev(policy(), BOOK, { approval: appr });
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("APPROVAL_VALID"));
});

test("approval for a different tool is DENY", () => {
  const appr = makeApproval(BOOK, { tool: "flight.search" });
  const r = ev(policy(), BOOK, { approval: appr });
  assert.equal(r.verdict, "DENY");
  assert.ok(failedRules(r).includes("APPROVAL_VALID"));
});

// --- Policy validation: malformed policies fail closed.

test("malformed policy: maxAmount < 0 throws PolicyError", () => {
  const p = policy();
  p.delegations[0].maxAmount = -1;
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: expiresAt <= notBefore throws", () => {
  const p = policy();
  p.delegations[0].expiresAt = "2026-11-01T00:00:00Z";
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: delegation to unknown agent throws", () => {
  const p = policy();
  p.delegations[0].to = "ghost-agent";
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: bad tool pattern throws", () => {
  const p = policy();
  p.delegations[0].tools = ["flight..book"];
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: duplicate delegation id throws", () => {
  const p = policy();
  p.delegations.push({ ...p.delegations[0] });
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: defaultDecision allow throws", () => {
  const p = policy({ defaultDecision: "allow" });
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("malformed policy: version 2 throws", () => {
  const p = policy({ version: 2 });
  assert.throws(() => validatePolicy(p), /POLICY_ERROR/);
});

test("action digest is order-independent (canonical JSON)", () => {
  const a1 = { b: 1, a: { d: 4, c: 3 } };
  const a2 = { a: { c: 3, d: 4 }, b: 1 };
  assert.equal(canonicalJson(a1), canonicalJson(a2));
  assert.equal(HASH.length, 64);
});

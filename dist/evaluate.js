/**
 * Policy evaluation: the decision layer of deleguard.
 *
 * evaluate() takes a validated policy, a proposed action, an optional
 * approval and an evaluation time, and returns a deterministic verdict
 * (ALLOW / DENY / NEEDS-APPROVAL) plus one trace entry per rule. The
 * same inputs always produce the same verdict. Nothing here enforces
 * anything, calls a network, or trusts the model: the harness decides
 * what to do with the verdict.
 *
 * Rule order (each rule reports PASS/FAIL independently so `explain`
 * can show the full trace):
 *   DENIED_TOOL, CHAIN, CHAIN_DEPTH, CHAIN_SUBSET, TOOL_ALLOWED,
 *   TIME_WINDOW, AMOUNT, MERCHANT, DATA_CLASSES, APPROVAL_REQUIRED,
 *   APPROVAL_VALID.
 *
 * Verdict: any failing rule in DENIED_TOOL..DATA_CLASSES is DENY.
 * APPROVAL_REQUIRED failing alone is NEEDS-APPROVAL. A supplied
 * approval that fails APPROVAL_VALID is DENY (a bad approval never
 * upgrades a decision). A generic `user_confirmed: true` flag on the
 * action is NOT an approval and is ignored.
 */
import { canonicalJson, sha256Hex, } from "./policy.js";
/** Tools that move money: a missing amount on one of these is DENY. */
const MONEY_TOOLS = ["book", "buy", "pay", "purchase", "charge"];
export function isMoneyTool(tool) {
    const leaf = tool.split(".").pop() ?? tool;
    return MONEY_TOOLS.includes(leaf);
}
export function actionDigest(action) {
    return sha256Hex(canonicalJson(action));
}
export function evaluate(policy, policyHash, action, opts = {}) {
    const reasons = [];
    const digest = actionDigest(action);
    const now = opts.at ??
        (typeof action.timestamp === "string" && action.timestamp !== ""
            ? new Date(action.timestamp)
            : new Date());
    const nowMs = now.getTime();
    const fail = (rule, message) => {
        reasons.push({ rule, pass: false, message });
    };
    const ok = (rule, message) => {
        reasons.push({ rule, pass: true, message });
    };
    // --- Action shape (fail closed: a malformed action is DENY, not ALLOW).
    let actionOk = true;
    if (typeof action.principal !== "string" || action.principal === "") {
        fail("ACTION", "action has no principal");
        actionOk = false;
    }
    if (typeof action.agent !== "string" || action.agent === "") {
        fail("ACTION", "action has no agent");
        actionOk = false;
    }
    if (!Array.isArray(action.chain) || action.chain.length < 2) {
        fail("ACTION", "action chain needs at least [principal, agent]");
        actionOk = false;
    }
    if (typeof action.tool !== "string" ||
        !/^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$/.test(action.tool)) {
        fail("ACTION", `action tool "${String(action.tool)}" is not a valid tool name`);
        actionOk = false;
    }
    if (!actionOk) {
        return finish("DENY", reasons, policyHash, digest, false, false);
    }
    const chain = action.chain;
    const grants = [];
    let chainOk = true;
    // --- DENIED_TOOL: an explicitly denied tool is DENY, whatever the grants say.
    if (policy.deniedTools.includes(action.tool)) {
        fail("DENIED_TOOL", `tool ${action.tool} is on the denied list`);
    }
    else {
        ok("DENIED_TOOL", `tool ${action.tool} is not denied`);
    }
    // --- CHAIN: the chain must start at the principal, end at the agent,
    // and every hop must have a delegation grant. No implicit inheritance.
    if (chain[0] !== action.principal) {
        fail("CHAIN", `chain starts at ${chain[0]}, not at principal ${action.principal}`);
        chainOk = false;
    }
    if (chain[chain.length - 1] !== action.agent) {
        fail("CHAIN", `chain ends at ${chain[chain.length - 1]}, not at agent ${action.agent}`);
        chainOk = false;
    }
    for (let i = 0; i < chain.length - 1; i++) {
        const grant = policy.delegations.find((d) => d.from === chain[i] && d.to === chain[i + 1]);
        if (!grant) {
            fail("CHAIN", `no delegation grant from ${chain[i]} to ${chain[i + 1]}`);
            chainOk = false;
        }
        else {
            grants.push(grant);
        }
    }
    if (chainOk) {
        ok("CHAIN", `every hop has a grant (${chain.join(" -> ")})`);
    }
    // --- CHAIN_DEPTH: hops must fit every grant's maxDepth.
    const hops = chain.length - 1;
    if (grants.length > 0) {
        const over = grants.filter((g) => hops > g.maxDepth);
        if (over.length > 0) {
            fail("CHAIN_DEPTH", `chain depth ${hops} exceeds maxDepth ${over[0].maxDepth} of ${over[0].id}`);
        }
        else {
            ok("CHAIN_DEPTH", `chain depth ${hops} fits every grant's maxDepth`);
        }
    }
    // --- CHAIN_SUBSET: each child grant must be a subset of its parent.
    if (grants.length > 1) {
        let subsetOk = true;
        for (let i = 1; i < grants.length; i++) {
            const parent = grants[i - 1];
            const child = grants[i];
            const widened = [];
            if (!child.tools.every((t) => parent.tools.includes(t))) {
                widened.push("tools");
            }
            if (child.maxAmount > parent.maxAmount)
                widened.push("maxAmount");
            if (child.currency !== parent.currency)
                widened.push("currency");
            if (!child.merchants.every((m) => parent.merchants.includes(m))) {
                widened.push("merchants");
            }
            if (!child.dataClasses.every((d) => parent.dataClasses.includes(d))) {
                widened.push("dataClasses");
            }
            if (Date.parse(child.expiresAt) > Date.parse(parent.expiresAt)) {
                widened.push("expiresAt");
            }
            if (widened.length > 0) {
                fail("CHAIN_SUBSET", `grant ${child.id} widens ${parent.id} on: ${widened.join(", ")}`);
                subsetOk = false;
            }
        }
        if (subsetOk)
            ok("CHAIN_SUBSET", "every child grant is a subset of its parent");
    }
    else if (grants.length === 1 && hops === 1) {
        ok("CHAIN_SUBSET", "single-hop chain, nothing to subset");
    }
    else {
        ok("CHAIN_SUBSET", "subset check skipped - the chain has no complete grant set");
    }
    // --- TOOL_ALLOWED: the tool must be in every grant on the chain.
    if (grants.length > 0) {
        const missing = grants.filter((g) => !g.tools.includes(action.tool));
        if (missing.length > 0) {
            fail("TOOL_ALLOWED", `tool ${action.tool} is not granted by ${missing[0].id}`);
        }
        else {
            ok("TOOL_ALLOWED", `tool ${action.tool} is granted on every hop`);
        }
    }
    // --- TIME_WINDOW: the evaluation time must sit inside every grant.
    if (grants.length > 0) {
        const outside = grants.filter((g) => nowMs < Date.parse(g.notBefore) || nowMs > Date.parse(g.expiresAt));
        if (outside.length > 0) {
            const g = outside[0];
            fail("TIME_WINDOW", nowMs < Date.parse(g.notBefore)
                ? `grant ${g.id} is not yet active (notBefore ${g.notBefore})`
                : `grant ${g.id} expired at ${g.expiresAt}`);
        }
        else {
            ok("TIME_WINDOW", "evaluation time is inside every grant window");
        }
    }
    // --- AMOUNT: a money tool without an amount is DENY (never assume 0).
    // A present amount must match the grant currency and fit every maxAmount.
    const money = isMoneyTool(action.tool);
    if (money && action.amount === undefined) {
        fail("AMOUNT", `money tool ${action.tool} has no amount (never assume 0)`);
    }
    else if (action.amount !== undefined) {
        if (typeof action.amount !== "number" || action.amount < 0) {
            fail("AMOUNT", "amount must be a number >= 0");
        }
        else if (grants.length > 0) {
            const badCurrency = grants.filter((g) => g.currency !== action.currency);
            if (badCurrency.length > 0) {
                fail("AMOUNT", `currency ${String(action.currency)} does not match grant currency ${badCurrency[0].currency}`);
            }
            else {
                const over = grants.filter((g) => action.amount > g.maxAmount);
                if (over.length > 0) {
                    fail("AMOUNT", `amount ${action.amount} ${action.currency} exceeds maxAmount ${over[0].maxAmount} ${over[0].currency} of ${over[0].id}`);
                }
                else {
                    ok("AMOUNT", `amount ${action.amount} ${action.currency} fits every grant limit`);
                }
            }
        }
    }
    else {
        ok("AMOUNT", "no amount on a non-money tool");
    }
    // --- MERCHANT: exact-host match against every grant's allowlist.
    // A money tool without a merchant cannot be checked, so it is DENY.
    if (money && action.merchant === undefined) {
        fail("MERCHANT", `money tool ${action.tool} names no merchant`);
    }
    else if (action.merchant !== undefined && grants.length > 0) {
        const denied = grants.filter((g) => !g.merchants.includes(action.merchant));
        if (denied.length > 0) {
            fail("MERCHANT", `merchant ${action.merchant} is not on the allowlist of ${denied[0].id}`);
        }
        else {
            ok("MERCHANT", `merchant ${action.merchant} is allowlisted on every hop`);
        }
    }
    else if (action.merchant === undefined) {
        ok("MERCHANT", "no merchant on a non-money tool");
    }
    // --- DATA_CLASSES: the action's data classes must fit every grant.
    if (action.dataClasses !== undefined && grants.length > 0) {
        if (!Array.isArray(action.dataClasses)) {
            fail("DATA_CLASSES", "dataClasses must be an array");
        }
        else {
            const missing = grants.filter((g) => !action.dataClasses.every((d) => g.dataClasses.includes(d)));
            if (missing.length > 0) {
                fail("DATA_CLASSES", `data classes ${JSON.stringify(action.dataClasses)} exceed grant ${missing[0].id}`);
            }
            else {
                ok("DATA_CLASSES", "data classes fit every grant");
            }
        }
    }
    else {
        ok("DATA_CLASSES", "no data classes requested beyond the grant");
    }
    // --- APPROVAL: required when any grant's threshold is exceeded.
    let approvalRequired = false;
    if (typeof action.amount === "number" && grants.length > 0) {
        const thresholds = grants
            .map((g) => g.requireApprovalAbove)
            .filter((t) => t !== undefined);
        if (thresholds.some((t) => action.amount > t)) {
            approvalRequired = true;
        }
    }
    let approvalConsumed = false;
    if (approvalRequired) {
        const approval = opts.approval;
        if (!approval) {
            fail("APPROVAL_REQUIRED", `amount ${action.amount} ${action.currency} needs a human approval (threshold exceeded)`);
        }
        else {
            // APPROVAL_VALID: bound to the exact action digest + principal +
            // agent + tool, unexpired, and not already consumed.
            const problems = [];
            if (approval.actionDigest !== digest) {
                problems.push("approval digest does not match this exact action");
            }
            if (approval.principal !== action.principal) {
                problems.push("approval principal does not match the action");
            }
            if (approval.agent !== action.agent) {
                problems.push("approval agent does not match the action");
            }
            if (approval.tool !== action.tool) {
                problems.push("approval tool does not match the action");
            }
            if (Date.parse(approval.issuedAt) > nowMs) {
                problems.push("approval is not yet issued at the evaluation time");
            }
            if (Date.parse(approval.expiresAt) <= nowMs) {
                problems.push(`approval expired at ${approval.expiresAt}`);
            }
            if (opts.consumedApprovalIds &&
                opts.consumedApprovalIds.has(approval.approvalId)) {
                problems.push("approval was already used (single-use)");
            }
            if (problems.length > 0) {
                fail("APPROVAL_VALID", problems.join("; "));
            }
            else {
                ok("APPROVAL_VALID", `approval ${approval.approvalId} matches this exact action and is unexpired`);
                approvalConsumed = true;
            }
        }
    }
    else {
        ok("APPROVAL_REQUIRED", "no approval threshold exceeded");
    }
    // --- Verdict.
    const hardFail = reasons.some((r) => !r.pass && r.rule !== "APPROVAL_REQUIRED");
    let verdict;
    if (hardFail)
        verdict = "DENY";
    else if (reasons.some((r) => !r.pass && r.rule === "APPROVAL_REQUIRED")) {
        verdict = "NEEDS-APPROVAL";
    }
    else
        verdict = "ALLOW";
    return finish(verdict, reasons, policyHash, digest, approvalRequired, approvalConsumed);
}
function finish(verdict, reasons, policyHash, actionDigest, approvalRequired, approvalConsumed) {
    return {
        verdict,
        reasons,
        policyHash,
        actionDigest,
        approvalRequired,
        approvalConsumed,
    };
}

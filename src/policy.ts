/**
 * Policy model + validation for deleguard 0.1.0.
 *
 * A policy is a human-written JSON file (deleguard.json). Validation runs
 * before any verdict: a malformed policy fails closed (POLICY_ERROR,
 * exit 2) and no verdict is issued. Validation never consults the network
 * and never trusts caller-supplied identity beyond the policy itself.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

export interface Principal {
  id: string;
  displayName?: string;
}

export interface Agent {
  id: string;
  version?: string;
}

export interface Delegation {
  id: string;
  from: string;
  to: string;
  tools: string[];
  maxAmount: number;
  currency: string;
  merchants: string[];
  dataClasses: string[];
  notBefore: string;
  expiresAt: string;
  maxDepth: number;
  requireApprovalAbove?: number;
}

export interface Policy {
  version: number;
  principals: Principal[];
  agents: Agent[];
  delegations: Delegation[];
  deniedTools: string[];
  defaultDecision: string;
}

export interface Action {
  principal: string;
  agent: string;
  chain: string[];
  tool: string;
  amount?: number;
  currency?: string;
  merchant?: string;
  dataClasses?: string[];
  timestamp?: string;
  [key: string]: unknown;
}

export interface Approval {
  approvalId: string;
  actionDigest: string;
  principal: string;
  agent: string;
  tool: string;
  amount?: number;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  used: boolean;
}

export class PolicyError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super("POLICY_ERROR: " + problems.join("; "));
    this.name = "PolicyError";
    this.problems = problems;
  }
}

const TOOL_RE = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$/;
const CURRENCY_RE = /^[A-Z]{3}$/;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isIso(s: unknown): s is string {
  return typeof s === "string" && !Number.isNaN(Date.parse(s));
}

/** Validate a parsed policy object. Returns the typed policy or throws. */
export function validatePolicy(raw: unknown): Policy {
  const problems: string[] = [];
  if (!isObj(raw)) {
    throw new PolicyError(["policy must be a JSON object"]);
  }
  if (raw.version !== 1) problems.push("version must be 1");
  if (!Array.isArray(raw.principals) || raw.principals.length === 0) {
    problems.push("principals must be a non-empty array");
  }
  if (!Array.isArray(raw.agents) || raw.agents.length === 0) {
    problems.push("agents must be a non-empty array");
  }
  if (!Array.isArray(raw.delegations) || raw.delegations.length === 0) {
    problems.push("delegations must be a non-empty array");
  }
  if (!Array.isArray(raw.deniedTools)) {
    problems.push("deniedTools must be an array");
  }
  if (raw.defaultDecision !== "deny") {
    problems.push('defaultDecision must be "deny"');
  }

  const principalIds = new Set<string>();
  if (Array.isArray(raw.principals)) {
    for (const p of raw.principals) {
      if (!isObj(p) || typeof p.id !== "string" || p.id === "") {
        problems.push("each principal needs a non-empty string id");
      } else principalIds.add(p.id);
    }
  }
  const agentIds = new Set<string>();
  if (Array.isArray(raw.agents)) {
    for (const a of raw.agents) {
      if (!isObj(a) || typeof a.id !== "string" || a.id === "") {
        problems.push("each agent needs a non-empty string id");
      } else agentIds.add(a.id);
    }
  }
  const delegationIds = new Set<string>();
  if (Array.isArray(raw.delegations)) {
    for (const d of raw.delegations) {
      if (!isObj(d)) {
        problems.push("each delegation must be an object");
        continue;
      }
      if (typeof d.id !== "string" || d.id === "") {
        problems.push("each delegation needs a non-empty string id");
      } else if (delegationIds.has(d.id)) {
        problems.push(`duplicate delegation id "${d.id}"`);
      } else {
        delegationIds.add(d.id);
      }
      // `from` is the delegating identity: a principal (first hop) or an
      // agent delegating onward (later hops). Either must be known.
      if (
        typeof d.from !== "string" ||
        (!principalIds.has(d.from) && !agentIds.has(d.from))
      ) {
        problems.push(
          `delegation "${String(d.id)}" has unknown delegator "${String(d.from)}"`,
        );
      }
      if (typeof d.to !== "string" || !agentIds.has(d.to)) {
        problems.push(
          `delegation "${String(d.id)}" grants to unknown agent "${String(d.to)}"`,
        );
      }
      if (!Array.isArray(d.tools) || d.tools.length === 0) {
        problems.push(`delegation "${String(d.id)}" needs a non-empty tools array`);
      } else {
        for (const t of d.tools) {
          if (typeof t !== "string" || !TOOL_RE.test(t)) {
            problems.push(
              `delegation "${String(d.id)}" has unknown tool pattern "${String(t)}"`,
            );
          }
        }
      }
      if (typeof d.maxAmount !== "number" || d.maxAmount < 0) {
        problems.push(`delegation "${String(d.id)}" has maxAmount < 0 or not a number`);
      }
      if (typeof d.currency !== "string" || !CURRENCY_RE.test(d.currency)) {
        problems.push(
          `delegation "${String(d.id)}" has an invalid currency (want 3-letter code)`,
        );
      }
      if (!Array.isArray(d.merchants)) {
        problems.push(`delegation "${String(d.id)}" needs a merchants array`);
      }
      if (!Array.isArray(d.dataClasses)) {
        problems.push(`delegation "${String(d.id)}" needs a dataClasses array`);
      }
      if (!isIso(d.notBefore) || !isIso(d.expiresAt)) {
        problems.push(
          `delegation "${String(d.id)}" needs ISO notBefore and expiresAt`,
        );
      } else if (Date.parse(d.expiresAt) <= Date.parse(d.notBefore)) {
        problems.push(
          `delegation "${String(d.id)}" has expiresAt <= notBefore`,
        );
      }
      if (
        typeof d.maxDepth !== "number" ||
        !Number.isInteger(d.maxDepth) ||
        d.maxDepth < 1
      ) {
        problems.push(
          `delegation "${String(d.id)}" needs maxDepth as an integer >= 1`,
        );
      }
      if (
        d.requireApprovalAbove !== undefined &&
        (typeof d.requireApprovalAbove !== "number" ||
          d.requireApprovalAbove < 0)
      ) {
        problems.push(
          `delegation "${String(d.id)}" has requireApprovalAbove < 0 or not a number`,
        );
      }
    }
  }
  if (Array.isArray(raw.deniedTools)) {
    for (const t of raw.deniedTools) {
      if (typeof t !== "string" || !TOOL_RE.test(t)) {
        problems.push(`deniedTools has unknown tool pattern "${String(t)}"`);
      }
    }
  }
  if (problems.length > 0) throw new PolicyError(problems);
  return raw as unknown as Policy;
}

/** Load and validate a policy file. Throws PolicyError or a read error. */
export function loadPolicy(path: string): { policy: Policy; hash: string } {
  const text = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PolicyError([`policy file ${path} is not valid JSON`]);
  }
  const policy = validatePolicy(parsed);
  const hash = sha256Hex(canonicalJson(policy));
  return { policy, hash };
}

/** Canonical JSON string of a value (sorted keys). */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJson(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") +
    "}"
  );
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Load an action file. Throws an Error with a plain message on bad input. */
export function loadAction(path: string): Action {
  const text = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`action file ${path} is not valid JSON`);
  }
  if (!isObj(parsed)) throw new Error("action must be a JSON object");
  return parsed as unknown as Action;
}

/** Load an approval file. Throws an Error with a plain message on bad input. */
export function loadApproval(path: string): Approval {
  const text = readFileSync(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`approval file ${path} is not valid JSON`);
  }
  if (!isObj(parsed)) throw new Error("approval must be a JSON object");
  return parsed as unknown as Approval;
}

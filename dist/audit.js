/**
 * Audit log: append-only NDJSON decision records with a SHA-256 hash
 * chain. Each record links to the previous record's hash, so a gap,
 * a reorder, or an edit is visible to `verify`.
 *
 * Honest limit: the log is a local file. The chain is tamper-EVIDENCE,
 * not tamper-proof: anyone who can rewrite the whole file can rebuild
 * the chain. Keep the log append-only and check it with `verify`.
 * Single-use approvals are enforced by scanning this log at check
 * time: if the log is deleted, reuse becomes possible, and `verify`
 * reports the sequence gap.
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { canonicalJson, sha256Hex } from "./policy.js";
/** Fields hashed into a record (everything except `hash` itself). */
export function recordHashInput(rec) {
    return canonicalJson({
        seq: rec.seq,
        ts: rec.ts,
        prevHash: rec.prevHash,
        policyVersion: rec.policyVersion,
        policyHash: rec.policyHash,
        principal: rec.principal,
        agent: rec.agent,
        tool: rec.tool,
        verdict: rec.verdict,
        actionDigest: rec.actionDigest,
        approvalId: rec.approvalId,
        approvalConsumed: rec.approvalConsumed,
        failedRules: rec.failedRules,
    });
}
export function readLog(path) {
    if (!existsSync(path))
        return [];
    const text = readFileSync(path, "utf8");
    const records = [];
    for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "")
            continue;
        records.push(JSON.parse(trimmed));
    }
    return records;
}
/** Approval ids already consumed (an ALLOW record that used one). */
export function consumedApprovalIds(path) {
    if (!path || !existsSync(path))
        return new Set();
    const used = new Set();
    for (const rec of readLog(path)) {
        if (rec.approvalConsumed && rec.approvalId)
            used.add(rec.approvalId);
    }
    return used;
}
/** Append one decision record and return it. */
export function appendRecord(path, input) {
    const prev = readLog(path);
    const last = prev[prev.length - 1];
    const base = {
        seq: prev.length === 0 ? 1 : last.seq + 1,
        ts: input.ts,
        prevHash: prev.length === 0 ? "GENESIS" : last.hash,
        policyVersion: input.policyVersion,
        policyHash: input.policyHash,
        principal: input.principal,
        agent: input.agent,
        tool: input.tool,
        verdict: input.evaluation.verdict,
        actionDigest: input.evaluation.actionDigest,
        approvalId: input.approvalId,
        approvalConsumed: input.evaluation.approvalConsumed,
        failedRules: input.evaluation.reasons
            .filter((r) => !r.pass)
            .map((r) => r.rule),
    };
    const rec = { ...base, hash: sha256Hex(recordHashInput(base)) };
    appendFileSync(path, JSON.stringify(rec) + "\n", "utf8");
    return rec;
}
/** Patterns that look like a secret accidentally written into the log. */
const SECRET_RE = /(api[_-]?key|secret|password|passwd|bearer|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,})/i;
/**
 * Verify a log file: sequence monotonic, timestamps non-decreasing,
 * prevHash chain intact, record hashes recompute, policy hash
 * consistent per policy version, and no secret-looking values.
 */
export function verifyLog(path) {
    const issues = [];
    let rawLines = [];
    if (existsSync(path)) {
        rawLines = readFileSync(path, "utf8")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l !== "");
    }
    const records = [];
    rawLines.forEach((line, i) => {
        if (SECRET_RE.test(line)) {
            issues.push({
                seq: null,
                message: `line ${i + 1} contains a secret-looking value`,
            });
        }
        try {
            records.push(JSON.parse(line));
        }
        catch {
            issues.push({ seq: null, message: `line ${i + 1} is not valid JSON` });
        }
    });
    const policyHashByVersion = new Map();
    let prevHash = "GENESIS";
    let prevTs = "";
    records.forEach((rec, i) => {
        if (rec.seq !== i + 1) {
            issues.push({
                seq: rec.seq ?? null,
                message: `sequence gap: expected seq ${i + 1}, found ${rec.seq}`,
            });
        }
        if (prevTs !== "" && rec.ts < prevTs) {
            issues.push({
                seq: rec.seq,
                message: `timestamp ${rec.ts} goes backwards from ${prevTs}`,
            });
        }
        prevTs = rec.ts;
        if (rec.prevHash !== prevHash) {
            issues.push({
                seq: rec.seq,
                message: `prevHash does not match the previous record's hash`,
            });
        }
        if (rec.hash !== sha256Hex(recordHashInput(rec))) {
            issues.push({
                seq: rec.seq,
                message: `record hash does not recompute (record was edited)`,
            });
        }
        prevHash = rec.hash;
        const known = policyHashByVersion.get(rec.policyVersion);
        if (known === undefined) {
            policyHashByVersion.set(rec.policyVersion, rec.policyHash);
        }
        else if (known !== rec.policyHash) {
            issues.push({
                seq: rec.seq,
                message: `policy hash changed within policy version ${rec.policyVersion}`,
            });
        }
    });
    return { ok: issues.length === 0, records: records.length, issues };
}

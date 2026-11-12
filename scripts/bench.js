/**
 * Bench: measure one policy decision (evaluate, in-process) over the
 * six demo actions. Prints median + p95 per run. Run 3 times and take
 * the median of the medians for the README number.
 */
import { evaluate } from "../dist/evaluate.js";
import { validatePolicy, sha256Hex, canonicalJson } from "../dist/policy.js";
import { DEFAULT_POLICY, DEFAULT_ACTIONS } from "../dist/init.js";

const policy = validatePolicy(DEFAULT_POLICY);
const hash = sha256Hex(canonicalJson(policy));
const actions = Object.values(DEFAULT_ACTIONS);
const AT = new Date("2026-11-12T14:00:00Z");

function quantile(sorted, q) {
  const i = Math.min(sorted.length - 1, Math.floor(q * sorted.length));
  return sorted[i];
}

const samples = [];
for (let i = 0; i < 1000; i++) {
  const a = actions[i % actions.length];
  const t0 = performance.now();
  evaluate(policy, hash, a, { at: AT });
  samples.push(performance.now() - t0);
}
samples.sort((x, y) => x - y);
console.log(
  `decision latency over 1000 evals (6 demo actions): median ${quantile(samples, 0.5).toFixed(3)} ms, p95 ${quantile(samples, 0.95).toFixed(3)} ms, max ${samples[samples.length - 1].toFixed(3)} ms`,
);

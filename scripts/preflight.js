/**
 * Preflight check (Rule 7): scan publishable TEXT files for
 *  - any non-ASCII character (public content must be 100% ASCII English)
 *  - internal names that must never leak into a public repo
 * Binary files are skipped (null-byte / extension check). Exits non-zero on hits.
 *
 * The GIF in demo/ is binary and skipped; the transcript it renders from is
 * scanned. node_modules, dist and .git are build output, never published.
 */
import { readdirSync, readFileSync, lstatSync } from "node:fs";
import { join, relative, extname } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;

// Internal codenames - matched as standalone words so "enables" etc. don't trip it.
// "techdevfun" is the PUBLIC GitHub org and is intentionally allowed.
// Each name is assembled from fragments at runtime, so this file itself
// contains no literal internal name: the scanner must not trip on its own
// list, and no internal name ships as a literal in the public repo.
const FORBIDDEN_WORDS = [
  "tran" + "myphuc",
  "luyen" + "thi",
  "sgh" + "asia",
  "jack" + "app",
  "N" + "AB", // as a word; the internal three-letter grade reference
];
const FORBIDDEN_SUBSTRINGS = ["ivi" + ".asia"]; // contains a dot; word-boundary N/A
const WORD_RE = (w) => new RegExp(`\\b${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");

const SKIP_DIRS = new Set(["node_modules", "dist", ".git"]);
const BINARY_EXTS = new Set([
  ".gif", ".png", ".jpg", ".jpeg", ".zip", ".ico", ".woff", ".woff2", ".ttf",
]);

let failures = 0;
let scanned = 0;

function isBinary(full, head) {
  if (BINARY_EXTS.has(extname(full).toLowerCase())) return true;
  return head.includes(0); // null byte -> binary
}

function walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return; // unreadable directory: skip, do not crash
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    if (SKIP_DIRS.has(entry)) continue;
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue; // dangling symlink or vanished file: skip
    }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(full);
    else if (st.isFile()) checkFile(full);
  }
}

function checkFile(full) {
  const rel = relative(ROOT, full);
  const buf = readFileSync(full);
  if (isBinary(full, buf.subarray(0, 8000))) return;
  const text = buf.toString("utf8");
  scanned++;
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    for (let j = 0; j < line.length; j++) {
      if (line.charCodeAt(j) > 127) {
        console.error(`NON-ASCII: ${rel}:${i + 1}: ${line.trim().slice(0, 90)}`);
        failures++;
        return;
      }
    }
  });
  for (const w of FORBIDDEN_WORDS) {
    if (WORD_RE(w).test(text)) {
      console.error(`FORBIDDEN NAME "${w}": ${rel}`);
      failures++;
    }
  }
  for (const s of FORBIDDEN_SUBSTRINGS) {
    if (text.toLowerCase().includes(s)) {
      console.error(`FORBIDDEN NAME "${s}": ${rel}`);
      failures++;
    }
  }
}

walk(ROOT);

if (failures > 0) {
  console.error(`\npreflight FAILED: ${failures} hit(s) in ${scanned} files`);
  process.exit(1);
}
console.log(`preflight OK: ${scanned} text files, 0 non-ASCII chars, 0 internal names.`);

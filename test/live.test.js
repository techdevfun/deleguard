/**
 * Live smoke tests: the deleguard name is free on npm and in the
 * techdevfun org. Soft-skip when offline (a network failure is not a
 * product failure). These run in CI via `npm run test:live`.
 */
import test from "node:test";
import assert from "node:assert/strict";

async function getStatus(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(url, { method: "GET", signal: ctrl.signal });
    return res.status;
  } finally {
    clearTimeout(t);
  }
}

test("live: npm package 'deleguard' is free (404)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/deleguard");
  } catch {
    t.skip("offline - npm registry unreachable");
    return;
  }
  assert.equal(status, 404);
});

test("live: org repo techdevfun/deleguard is free (404)", async (t) => {
  let status;
  try {
    status = await getStatus("https://api.github.com/repos/techdevfun/deleguard");
  } catch {
    t.skip("offline - api.github.com unreachable");
    return;
  }
  assert.equal(status, 404);
});

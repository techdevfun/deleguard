# Contributing

Contributions go through a pull request to `main`. Keep the scope
small: deleguard decides, it does not enforce. Any feature that
intercepts tool calls, runs a proxy, brokers credentials, or works
around a vendor's ban or terms of service is out of scope and will be
rejected.

## Development

```sh
npm install
npm run build
npm test
npm run test:live
node scripts/preflight.js
```

`npm test` runs unit + e2e tests (46 tests). `npm run test:live`
re-checks that the `deleguard` name is free on npm and in the
techdevfun org; it soft-skips when offline. `scripts/preflight.js`
scans all public text files for non-ASCII characters and internal
names: public content must be 100% ASCII English.

## Rules for changes

- Zero runtime dependencies. TypeScript strict, Node 20+.
- New behavior needs a test: unit tests for the decision matrix,
  e2e tests for CLI behavior and exit codes.
- No invented numbers in examples or docs. Fixture values are labeled
  synthetic where they appear.
- The demo transcript (`demo/transcript.txt`) is generated from the real
  CLI by `scripts/capture-demo.sh`; never hand-edit it.

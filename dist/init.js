/**
 * `deleguard init`: scaffold a starter policy + the six United travel
 * actions in a directory. Refuses to overwrite existing files.
 *
 * The fixture is SYNTHETIC: Alice, a $500 limit on united.com, and
 * amounts of $450 / $900 are invented for the demo. They illustrate the
 * decision rules; they are not United fares, limits, or policy.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
export const DEFAULT_POLICY = {
    version: 1,
    principals: [{ id: "alice", displayName: "Alice" }],
    agents: [
        { id: "travel-agent", version: "1.4.0" },
        { id: "sub-agent", version: "0.9.0" },
    ],
    delegations: [
        {
            id: "del-1",
            from: "alice",
            to: "travel-agent",
            tools: ["flight.search", "flight.book"],
            maxAmount: 500,
            currency: "USD",
            merchants: ["united.com"],
            dataClasses: ["itinerary", "price"],
            notBefore: "2026-11-01T00:00:00Z",
            expiresAt: "2026-12-31T23:59:59Z",
            maxDepth: 1,
            requireApprovalAbove: 0,
        },
    ],
    deniedTools: ["flight.cancel"],
    defaultDecision: "deny",
};
export const DEFAULT_ACTIONS = {
    "search.json": {
        principal: "alice",
        agent: "travel-agent",
        chain: ["alice", "travel-agent"],
        tool: "flight.search",
        merchant: "united.com",
        dataClasses: ["itinerary", "price"],
    },
    "book.json": {
        principal: "alice",
        agent: "travel-agent",
        chain: ["alice", "travel-agent"],
        tool: "flight.book",
        amount: 450,
        currency: "USD",
        merchant: "united.com",
        dataClasses: ["itinerary", "price"],
    },
    "book-over-limit.json": {
        principal: "alice",
        agent: "travel-agent",
        chain: ["alice", "travel-agent"],
        tool: "flight.book",
        amount: 900,
        currency: "USD",
        merchant: "united.com",
        dataClasses: ["itinerary", "price"],
    },
    "book-aggregator.json": {
        principal: "alice",
        agent: "travel-agent",
        chain: ["alice", "travel-agent"],
        tool: "flight.book",
        amount: 450,
        currency: "USD",
        merchant: "kayak.com",
        dataClasses: ["itinerary", "price"],
    },
    "sub-agent-no-grant.json": {
        principal: "alice",
        agent: "sub-agent",
        chain: ["alice", "travel-agent", "sub-agent"],
        tool: "flight.book",
        amount: 200,
        currency: "USD",
        merchant: "united.com",
        dataClasses: ["itinerary", "price"],
    },
    "expired-approval.json": {
        principal: "alice",
        agent: "travel-agent",
        chain: ["alice", "travel-agent"],
        tool: "flight.book",
        amount: 450,
        currency: "USD",
        merchant: "united.com",
        dataClasses: ["itinerary", "price"],
    },
};
const ACTIONS_README = `# Example actions (United travel fixture)

The six actions for the demo in the README. All values are SYNTHETIC:
Alice, the $500 limit, and the $450 / $900 amounts are invented to show
the decision rules. They are not United fares, limits, or policy.

- search.json: flight.search on united.com -> ALLOW
- book.json: flight.book $450 -> NEEDS-APPROVAL (any booking needs one)
- book-over-limit.json: flight.book $900 -> DENY (over the $500 limit)
- book-aggregator.json: flight.book $450 via kayak.com -> DENY (merchant
  not allowlisted; the grant covers united.com only)
- sub-agent-no-grant.json: a sub-agent booking with no grant -> DENY
  (no implicit inheritance down the chain)
- expired-approval.json: the same $450 booking, checked with an approval
  past its expiry (use --at) -> DENY

Run them with:

  deleguard check --policy deleguard.json --action examples/actions/book.json
`;
export function scaffold(dir) {
    const written = [];
    const actionsDir = join(dir, "examples", "actions");
    const approvalsDir = join(dir, "examples", "approvals");
    mkdirSync(actionsDir, { recursive: true });
    mkdirSync(approvalsDir, { recursive: true });
    const write = (rel, content) => {
        const full = join(dir, rel);
        if (existsSync(full)) {
            throw new Error(`refusing to overwrite existing file: ${rel}`);
        }
        writeFileSync(full, content, "utf8");
        written.push(rel);
    };
    write("deleguard.json", JSON.stringify(DEFAULT_POLICY, null, 2) + "\n");
    for (const [name, action] of Object.entries(DEFAULT_ACTIONS)) {
        write(join("examples", "actions", name), JSON.stringify(action, null, 2) + "\n");
    }
    write(join("examples", "actions", "README.md"), ACTIONS_README);
    write(join("examples", "approvals", ".gitkeep"), "# Approvals issued by `deleguard approve` go here.\n");
    return written;
}

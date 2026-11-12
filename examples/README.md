# Examples (United travel fixture)

The policy in `deleguard.json` and the six actions in `actions/` are
SYNTHETIC. Alice, the $500 limit on united.com, and the $450 / $900
amounts are invented to show the decision rules. They are not United
fares, limits, or policy.

The news hook is real: on 11 November 2026 United Airlines said it
will bar unauthorized third-party AI agents from booking, changing,
or buying tickets through its site, app, travel agencies, and
aggregators, citing personal-data risk, transactions against the
customer's intent, and federal-rule risk. Agents may still show
flights and prices, and bookings made before 11 November 2026 are not
cancelled (CBS News, 11 November 2026; Skift, 11 November 2026;
PhocusWire, 11 November 2026). deleguard has no relationship with
United Airlines.

## The six actions

| File | Expected verdict |
| --- | --- |
| `actions/search.json` | ALLOW - search on united.com is inside the grant |
| `actions/book.json` | NEEDS-APPROVAL - any booking needs a human approval |
| `actions/book-over-limit.json` | DENY - $900 exceeds the $500 limit |
| `actions/book-aggregator.json` | DENY - kayak.com is not on the merchant allowlist |
| `actions/sub-agent-no-grant.json` | DENY - the sub-agent has no grant |
| `actions/expired-approval.json` | DENY with an approval past its expiry (use `--at`) |

## Run them

```sh
deleguard init
deleguard check --policy deleguard.json --action examples/actions/search.json
deleguard check --policy deleguard.json --action examples/actions/book.json
deleguard approve --policy deleguard.json --action examples/actions/book.json --by alice --out examples/approvals/appr-1.json
deleguard check --policy deleguard.json --action examples/actions/book.json --approval examples/approvals/appr-1.json --log deleguard-audit.jsonl
deleguard audit --log deleguard-audit.jsonl
deleguard verify --log deleguard-audit.jsonl
```

Approvals issued by `deleguard approve` go in `approvals/`.

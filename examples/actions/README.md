# Example actions (United travel fixture)

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

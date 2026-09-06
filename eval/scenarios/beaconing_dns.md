# Scenario 1 — DNS beaconing (v1 case)

## Lead
- host `10.0.0.5` queries `cdn-update.example.com` at a suspiciously regular cadence
- low volume, no user-visible purpose

## Expected behaviour of the agent
1. `query_logs` on `dns` filtered to the host pair (narrow, ≤ 2 calls)
2. optional `enrich_ip` on the host (protocols, peers)
3. `write_report` with: evidence, verdict (suspicious/inconclusive), confidence, next checks

## Ground truth (for eval)
- ≥ 5 periodic queries to the same domain, short fixed intervals
- response sizes near-constant → tunneling candidate

## Dataset
Public Zeek sample logs (see docs/architecture.md § Data). No production data.

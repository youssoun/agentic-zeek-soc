# Architecture

```
            ┌────────────┐     narrow queries      ┌───────────────┐
Zeek logs ─▶│  ingest    │──▶ parquet ────────────▶│  agent loop   │──▶ reports/*.md
(TSV)       │  (pandas)  │                         │ (Gemini FC)   │
            └────────────┘                         │  query_logs() │
                                                   │  enrich_ip()  │
                                                   │  write_report │
                                                   └───────────────┘
```

## Design rules

1. **Token-cheap by construction** — every tool returns compact JSON, queries are narrow,
   the agent never receives raw log dumps. The evidence layer does the filtering.
2. **Wire-first** — conn/dns/tls/http parquet tables are the single source of truth.
   No SIEM normalization in the loop; fidelity stays intact.
3. **The report is the deliverable** — facts, verdict, confidence, next checks.
   Human-readable, diffable, reviewable. No black-box verdicts.
4. **Eval before features** — each scenario (eval/scenarios/*.md) has ground truth;
   a scenario ships only when the agent resolves it within a token budget.

## Data

Public corpora: Zeek sample logs (zeek.org), Stratosphere IPS malware-traffic dataset,
CIC flow datasets. Everything public, reproducible, and license-clean. Production
network data never enters this repo.

## Roadmap

- v0.1 (this repo): heuristic investigator, DNS beaconing scenario, key-less run
- v1.0: Gemini function-calling loop, token budget per scenario, eval harness
- v1.1: exfil-sized transfers, lateral movement (SMB), TLS fingerprint oddities
- v2: the agent drafts detection-rule improvements for every FP it closes

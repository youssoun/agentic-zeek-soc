# agentic-zeek-soc

**An agentic SOC that reads the wire.** Give it a lead from Zeek telemetry — it investigates,
produces an investigation note, and stops. No dashboards, no alert noise: an agent with
tools over structured network evidence.

```
Zeek logs (conn / dns / tls / http)
        │  ingest → parquet
        ▼
┌─────────────────────────┐
│  Agent loop (Gemini)    │
│  tools: query_logs()    │
│         enrich_ip()     │
│         write_report()  │
└─────────────────────────┘
        ▼
  reports/*.md  ← investigation note (facts, confidence, next checks)
```

## Why wire telemetry for agents

Agents don't fix bad signal — they invoice it. The same triage scenario against
normalized SIEM logs makes an LLM spend most of its budget re-establishing context;
structured wire telemetry (Zeek conn/dns/tls) hands it facts directly — a few hundred
tokens instead of thousands.

The wire is the cheapest context an agent can read: full fidelity, no re-ingestion
tax, nothing normalized away. This repo is the experiment: how far can a small agent
go when its evidence layer is Zeek?

## Scope

- **v1** — one scenario end to end: DNS beaconing. The agent receives a lead
  (host pair with periodic low-volume DNS), queries the logs, correlates
  conn/dns/tls, and writes an investigation note with a confidence score.
- **v1.1** — exfiltration-sized transfers, lateral movement (SMB patterns), odd TLS fingerprints.
- **v2** — agent proposes detection rule improvements for every false positive it closes.

## Data ethics

Public datasets only (Zeek sample logs, open malware-traffic corpora).
No production data, ever. The point is method, not data.

## Status

🚧 v1 in progress — see `eval/scenarios/beaconing_dns.md` for the first case.

## Author

**Youssef Agharmine** — [GitHub](https://github.com/youssoun) · [LinkedIn](https://www.linkedin.com/in/youssefagharmine/)
*I help SOC teams see what firewalls and EDR miss | NDR & AI-driven Threat Detection*

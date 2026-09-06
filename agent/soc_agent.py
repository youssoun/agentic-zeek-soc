# soc_agent.py — the investigation loop. v1 scenario: DNS beaconing lead.
# Uses Gemini function calling when GOOGLE_API_KEY is set; falls back to a
# deterministic heuristic investigator otherwise (so the repo runs key-less).
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from tools import query_logs, enrich_ip, write_report  # noqa: E402


TOOLS_DECL = [
    {"name": "query_logs", "description": "Run a narrow query over one Zeek log (conn/dns/tls/http). Args: {log, where{col:val}, columns[], limit}",
     "parameters": {"type": "object", "properties": {
         "log": {"type": "string", "enum": ["conn", "dns", "tls", "http"]},
         "where": {"type": "object", "description": "exact-match filters"},
         "columns": {"type": "array", "items": {"type": "string"}},
         "limit": {"type": "integer"}}}},
    {"name": "enrich_ip", "description": "Cross-log profile of one IP: protocols, peers, DNS names queried.",
     "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}}},
    {"name": "write_report", "description": "Persist the investigation note (markdown). Args: {title, body_md}",
     "parameters": {"type": "object", "properties": {
         "title": {"type": "string"}, "body_md": {"type": "string"}},
         "required": ["title", "body_md"]}},
]


def heuristic_investigator(lead: dict) -> str:
    """Deterministic v0.1 investigator for the DNS beaconing scenario.
    lead = {"orig_h": "10.0.0.5", "query": "cdn-update.example.com"}"""
    orig = lead["orig_h"]
    dns = query_logs({"log": "dns", "where": {"id.orig_h": orig, "query": lead["query"]}, "limit": 50})
    proto = enrich_ip(orig)
    n = dns["count"]
    names = [r.get("query", "") for r in dns["rows"]]
    verdict = "suspicious" if n >= 5 else "inconclusive"
    body = (
        f"## Lead\n{orig} → {lead['query']}\n\n"
        f"## Evidence (wire)\n- DNS queries to `{lead['query']}`: **{n}**\n"
        f"- sample names: {names[:5] if (names := [r.get('query','') for r in dns['rows']]) else '—'}\n"
        f"- protocols seen: {proto['protocols']}\n- top peers: {proto['peers'][:5]}\n\n"
        f"## Verdict\n{verdict} (confidence: {'high' if n >= 10 else 'medium' if n >= 5 else 'low'})\n\n"
        f"## Next checks\n- interval regularity across `conn` sessions\n- response size pattern "
        f"(tunneling check)\n- TLS SNI match on the same host pair\n"
    )
    path = write_report(f"DNS beaconing {orig}", body)
    return f"report written → {path}\n{body}"


def agent_loop(lead: dict) -> str:
    """Gemini function-calling loop when a key exists; heuristic fallback otherwise."""
    if not os.environ.get("GOOGLE_API_KEY"):
        print("[v0.1] no GOOGLE_API_KEY → deterministic heuristic investigator")
        return heuristic_investigator(lead)

    from google import genai
    client = genai.Client()
    tools = [query_logs, enrich_ip, write_report]
    chat = client.chats.create(
        model="gemini-2.0-flash",
        config={"tools": tools, "system_instruction":
            "You are a SOC investigation agent. Evidence comes from Zeek wire telemetry only. "
            "Investigate the lead with the fewest tool calls possible (token-cheap: every "
            "query should be narrow). Finish ONLY by writing a report with: facts, verdict "
            "(suspicious/benign/inconclusive), confidence, and 2-3 next checks. No speculation "
            "beyond the evidence."},
    )
    r = chat.send_message("Investigate this lead:\n" + json.dumps(lead, indent=1))
    return r.text or "(no output)"


if __name__ == "__main__":
    lead = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {
        "orig_h": "10.0.0.5",
        "query": "cdn-update.example.com",
    }
    print(agent_loop(lead))

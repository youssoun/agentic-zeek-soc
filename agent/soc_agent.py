# soc_agent.py — the investigation loop.
# Priority: Mistral (MISTRAL_API_KEY) → Gemini (GOOGLE_API_KEY) → deterministic heuristics.
# The agent decides which tools to call; every call is narrow; a token bill is kept.
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from tools import query_logs, enrich_ip, write_report  # noqa: E402

TOOLS_DECL = [
    {"type": "function", "function": {
        "name": "query_logs",
        "description": (
            "Run a narrow query over one Zeek log. Returns {count, rows}. "
            "Column names are Zeek's: conn.log → ts, uid, id.orig_h, id.orig_p, id.resp_h, "
            "id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state. "
            "dns.log → ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, qtype_name, "
            "query, answers, ttls, rcode_name. tls.log → ts, uid, id.orig_h, id.orig_p, "
            "id.resp_h, id.resp_p, server_name, version, cipher, ja3. "
            "http.log → ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, host, method, "
            "uri, user_agent, status_code."),
        "parameters": {"type": "object", "properties": {
            "log": {"type": "string", "enum": ["conn", "dns", "tls", "http"]},
            "where": {"type": "object", "description": "exact-match filters, AND-ed"},
            "columns": {"type": "array", "items": {"type": "string"}},
            "limit": {"type": "integer"}}, "required": ["log"]}}},
    {"type": "function", "function": {
        "name": "enrich_ip",
        "description": "Cross-log profile of one IP: protocols, peers, DNS names queried, and beaconing_hints (per domain queried >= 3 times: queries count, interval_min_s, interval_max_s). Tight regular intervals are the classic DNS beaconing signature — read them, do not recompute them.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "write_report",
        "description": "Persist the investigation note (markdown). Facts, verdict, confidence, next checks.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"}, "body_md": {"type": "string"}},
            "required": ["title", "body_md"]}}},
]

SYSTEM = (
    "You are a SOC investigation agent. Evidence comes from Zeek wire telemetry only, "
    "through three tools. Investigate the lead with the fewest tool calls possible — every "
    "query should be narrow (filter by host pair, small limit). Column names are Zeek's "
    "(id.orig_h, id.resp_h, query, ...): never guess a column name, use the ones from the "
    "tool description or the error's available_columns. Never repeat an identical query — "
    "if a query returns the same result twice, change approach or finish. Finish ONLY by "
    "calling write_report with a markdown note: facts (with counts), verdict (suspicious / "
    "benign / inconclusive), confidence (low/medium/high), and 2-3 next checks. No "
    "speculation beyond the evidence. If the evidence is insufficient, say inconclusive.\n\n"
    "Evidence patterns: the enrich_ip tool computes beaconing_hints per domain — interval_min_s "
    "close to interval_max_s over many queries means machine-regular querying. The DNS beaconing "
    "pattern is: repeated queries to one domain at regular intervals, followed by repeated short "
    "connections from the host to the resolved IP. That pattern justifies verdict suspicious. "
    "A one-off lookup followed by ordinary traffic is benign. Judge on the evidence; do not "
    "inflate confidence."
)

DISPATCH = {"query_logs": query_logs, "enrich_ip": enrich_ip, "write_report": write_report}


def _call_with_retry(client, **kwargs):
    """Free tier hits 429 (code 1300) easily — exponential backoff, 4 tries."""
    import time
    delays = [20, 45, 90]
    for i, d in enumerate(delays):
        try:
            time.sleep(2)  # pacing de base entre deux appels API
            return client.chat.complete(**kwargs)
        except Exception as e:  # noqa: BLE001
            if "429" not in str(e) and "rate" not in str(e).lower():
                raise
            print(f"[429 rate limit] tentative {i + 1}/{len(delays)} — attente {d}s")
            time.sleep(d)
    raise RuntimeError("rate limit persistant après 4 tentatives")


def mistral_agent_loop(lead: dict, model: str = "mistral-small-latest", max_steps: int = 8):
    from mistralai import Mistral
    client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": "Investigate this lead:\n" + json.dumps(lead, indent=1)}]
    used = {"prompt": 0, "completion": 0}
    for step in range(max_steps):
        resp = _call_with_retry(client, model=model, messages=messages,
                                tools=TOOLS_DECL, tool_choice="auto")
        u = resp.usage
        used["prompt"] += u.prompt_tokens
        used["completion"] += u.completion_tokens
        msg = resp.choices[0].message
        calls = list(msg.tool_calls or [])
        if not calls:
            print(f"[tour {step + 1}] réponse finale")
            return (msg.content or "") + f"\n\n---\nFacture tokens: prompt={used['prompt']}, completion={used['completion']}, total={used['prompt'] + used['completion']}"
        # rejouer le tour assistant avec ses tool_calls (format dict API)
        assistant_msg = {"role": "assistant", "content": msg.content}
        assistant_msg["tool_calls"] = [{"id": tc.id, "type": "function",
                                        "function": {"name": tc.function.name,
                                                     "arguments": tc.function.arguments}}
                                       for tc in calls]
        messages.append(assistant_msg)
        for tc in calls:
            fn = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
                print(f"[tour {step + 1}] {fn}({json.dumps(args, ensure_ascii=False)[:100]})")
                result = DISPATCH[fn](**args)
            except Exception as e:  # noqa: BLE001 — l'agent doit voir l'erreur et s'adapter
                result = {"error": str(e), "hint": "re-check the tool parameter schema in the tool description"}
            messages.append({"role": "tool", "name": fn, "tool_call_id": tc.id,
                             "content": json.dumps(result, ensure_ascii=False, default=str)[:4000]})
            if os.environ.get("AZS_DEBUG"):
                print(f"   → résultat {fn}: {json.dumps(result, ensure_ascii=False, default=str)[:180]}")
    # budget épuisé : dernier appel sans outils, la note doit sortir en texte
    print("[budget] dernier tour forcé — la note en texte")
    messages.append({"role": "user", "content": "Tool budget exhausted. Write the final investigation note now, as plain markdown (facts, verdict, confidence, next checks). No tool calls."})
    resp = _call_with_retry(client, model=model, messages=messages)
    note = resp.choices[0].message.content or "(note vide)"
    write_report("DNS beaconing " + lead.get("orig_h", "?"), note)
    return note + f"\n\n---\nFacture tokens: prompt={used['prompt']}, completion={used['completion']}, total={used['prompt'] + used['completion']}"


def agent_loop(lead: dict) -> str:
    if os.environ.get("MISTRAL_API_KEY"):
        print(f"[agent] Mistral — {os.environ.get('AZS_MODEL', 'mistral-small-latest')}")
        return mistral_agent_loop(lead, os.environ.get("AZS_MODEL", "mistral-small-latest"))
    if os.environ.get("GOOGLE_API_KEY"):
        print("[agent] Gemini — v1.0 à venir")
        return heuristic_investigator(lead)
    print("[v0.1] aucune clé API → déterministe (heuristiques)")
    return heuristic_investigator(lead)


def heuristic_investigator(lead: dict) -> str:
    """Deterministic fallback (key-less)."""
    orig = lead["orig_h"]
    dns = query_logs({"log": "dns", "where": {"id.orig_h": orig, "query": lead["query"]}, "limit": 50})
    proto = enrich_ip(orig)
    n = dns["count"]
    names = [r.get("query", "") for r in dns["rows"]]
    verdict = "suspicious" if n >= 5 else "inconclusive"
    body = (
        f"## Lead\n{orig} → {lead['query']}\n\n"
        f"## Evidence (wire)\n- DNS queries to `{lead['query']}`: **{n}**\n"
        f"- sample names: {names[:5] if names else '—'}\n"
        f"- protocols seen: {proto['protocols']}\n- top peers: {proto['peers'][:5]}\n\n"
        f"## Verdict\n{verdict} (confidence: {'high' if n >= 10 else 'medium' if n >= 5 else 'low'})\n\n"
        f"## Next checks\n- interval regularity across `conn` sessions\n- response size pattern "
        f"(tunneling check)\n- TLS SNI match on the same host pair\n"
    )
    path = write_report(f"DNS beaconing {orig}", body)
    return f"report written → {path}\n{body}"


if __name__ == "__main__":
    lead = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {
        "orig_h": "10.0.0.5",
        "query": "cdn-update.example.com",
    }
    print(agent_loop(lead))

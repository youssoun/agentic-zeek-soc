# tools.py — the agent's hands: query_logs(), enrich_ip(), write_report()
# v0.1: heuristics-first. Every tool returns compact JSON (token-cheap by design).
import pathlib
import pandas as pd
import pyarrow.parquet as pq

DATA = pathlib.Path("data/parquet")
REPORTS = pathlib.Path("reports")


def _table(log: str) -> pd.DataFrame:
    p = DATA / f"{log}.parquet"
    return pq.read_table(p).to_pandas() if p.exists() else pd.DataFrame()


def query_logs(ql: dict) -> dict:
    """Run a narrow query over one Zeek log.
    ql = {"log": "conn"|"dns"|"tls"|"http",
          "where": {"src_addr": "10.0.0.5", ...},   # exact matches, AND-ed
          "columns": [...],                          # optional projection
          "limit": 20}
    Returns {count, rows} — rows are compact dicts (token-cheap by design).
    """
    df = _table(ql.get("log", "conn"))
    if df.empty:
        return {"count": 0, "rows": []}
    for k, v in (ql.get("where") or {}).items():
        if k in df.columns:
            df = df[df[k] == v]
    cols = list(ql.get("columns") or [c for c in df.columns if df[c].notna().any()][:10])
    # toujours inclure les colonnes filtrées (et 'query'/'ts' quand elles existent)
    for k in list((ql.get("where") or {}).keys()) + ["ts", "query"]:
        if k in df.columns and k not in cols:
            cols.insert(0, k)
    return {
        "count": int(len(df)),
        "rows": df[cols].head(ql.get("limit", 20)).fillna("").to_dict("records"),
    }


def enrich_ip(ip: str) -> dict:
    """Cross-log profile of one IP: protocols seen, peers, DNS names it resolves/queries,
    bytes up/down, periodicity hint. All derived from the wire — no external calls in v0.1."""
    out = {"ip": ip, "as_src": 0, "as_dst": 0, "protocols": [], "dns_names": [], "peers": []}
    conn = _table("conn")
    if not conn.empty:
        c = conn[(conn.get("id.orig_h") == ip) | (conn.get("id.resp_h") == ip)]
        if not c.empty:
            out["as_src"] = int((c.get("id.orig_h") == ip).sum())
            out["as_dst"] = int((c.get("id.resp_h") == ip).sum())
            if "proto" in c:
                out["protocols"] = sorted(c["proto"].dropna().unique().tolist())
            peers = set(c.get("id.orig_h", pd.Series(dtype=str)).dropna()) | set(c.get("id.resp_h", pd.Series(dtype=str)).dropna())
            out["peers"] = sorted(peers - {ip})[:10]
    dns = _table("dns")
    if not dns.empty:
        q = dns[(dns.get("id.orig_h") == ip) & dns.get("query", pd.Series(dtype=str)).notna()]
        out["dns_names"] = q.get("query", pd.Series(dtype=str)).dropna().unique().tolist()[:15]
    return out


def write_report(title: str, body_md: str) -> str:
    """Persist the investigation note. The report IS the deliverable."""
    REPORTS.mkdir(exist_ok=True)
    import datetime
    name = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + title.lower().replace(" ", "-") + ".md"
    (REPORTS / name).write_text(f"# {title}\n\n{body_md}\n")
    return str(REPORTS / name)

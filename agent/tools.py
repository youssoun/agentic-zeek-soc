# tools.py — the agent's hands: query_logs(), enrich_ip(), write_report()
# v0.1: heuristics-first. Every tool returns compact JSON (token-cheap by design).
from typing import Optional
import pathlib
import pandas as pd
import pyarrow.parquet as pq

DATA = pathlib.Path("data/parquet")
REPORTS = pathlib.Path("reports")


def _table(log: str) -> pd.DataFrame:
    p = DATA / f"{log}.parquet"
    return pq.read_table(p).to_pandas() if p.exists() else pd.DataFrame()


def query_logs(log: str = "conn", where: Optional[dict] = None, columns: Optional[list] = None, limit: int = 20) -> dict:
    """Run a narrow query over one Zeek log.
    Args match the tool schema the agent sees: log, where, columns, limit.
    Unknown columns return an explicit error with available column names,
    so the calling agent self-corrects instead of looping.
    """
    df = _table(log)
    if df.empty:
        return {"count": 0, "rows": [], "available_columns": []}
    where = where or {}
    mauvaises = [k for k in where if k not in df.columns]
    if mauvaises:
        return {"error": f"unknown column(s) {mauvaises}",
                "available_columns": list(df.columns)}
    for k, v in where.items():
        # liste = filtre IN (le modèle peut passer plusieurs valeurs)
        if isinstance(v, (list, tuple)):
            df = df[df[k].isin(list(v))]
        else:
            df = df[df[k] == v]
    cols = list(columns or [c for c in df.columns if df[c].notna().any()][:10])
    # toujours inclure les colonnes filtrées (et 'query'/'ts' quand elles existent)
    for k in list(where.keys()) + ["ts", "query"]:
        if k in df.columns and k not in cols:
            cols.insert(0, k)
    cols = [c for c in cols if c in df.columns]
    return {
        "count": int(len(df)),
        "rows": df[cols].head(limit).fillna("").to_dict("records"),
    }


def enrich_ip(ip: str) -> dict:
    """Cross-log profile of one IP: protocols seen, peers, DNS names it resolves/queries,
    periodicity hints. All derived from the wire — no external calls.
    beaconing_hints: for every domain queried >= 3 times by this host, the min/max interval
    between consecutive queries, in seconds. Regular intervals over >= 4 queries are the
    classic DNS beaconing signature — computed here (cheap in pandas) so the agent reads
    one field instead of deriving it."""
    out = {"ip": ip, "as_src": 0, "as_dst": 0, "protocols": [], "dns_names": [], "peers": [], "beaconing_hints": []}
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
        # périodicité par domaine (>= 3 requêtes) — la preuve que le wire donne gratuitement
        for domaine, grp in q.groupby("query"):
            ts = sorted(float(t) for t in grp["ts"].dropna())
            if len(ts) >= 3:
                intervals = [round(b - a, 2) for a, b in zip(ts, ts[1:])]
                out["beaconing_hints"].append({
                    "domain": domaine, "queries": len(ts),
                    "interval_min_s": min(intervals), "interval_max_s": max(intervals),
                })
    return out


def write_report(title: str, body_md: str) -> str:
    """Persist the investigation note. The report IS the deliverable."""
    REPORTS.mkdir(exist_ok=True)
    import datetime
    name = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + title.lower().replace(" ", "-") + ".md"
    (REPORTS / name).write_text(f"# {title}\n\n{body_md}\n")
    return str(REPORTS / name)

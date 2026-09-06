# zeek_ingest.py — parse Zeek TSV logs (conn, dns, tls, http) → parquet
# v0.1: minimal, dependency-light (pyarrow + pandas). Handles the standard
# Zeek #separator/#fields/#types header, tabular output format.
import pathlib
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

LOGS = ("conn", "dns", "tls", "http")


def _read_header(path):
    fields, types = None, None
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
            elif not line.startswith("#") and fields and types:
                break
    if not fields:
        raise ValueError(f"no #fields header in {path}")
    return [f_.strip() for f_ in fields], [t_.strip() for t_ in types]


def _zeek_value(v: str, t: str):
    if v in ("(empty)", "-"):
        return None
    if t in ("count", "port"):
        return int(v)
    if t in ("interval", "double"):
        return float(v)
    if t == "bool":
        return v == "T"
    if t in ("set[string]", "vector[string]"):
        return v.split(",") if v else []
    return v


def load_log(path_or_dir, log: str):
    """Load a Zeek log file (or a directory of dated logs) into a DataFrame."""
    import glob, os
    paths = []
    src = path_or_dir
    if os.path.isdir(src):
        paths = sorted(glob.glob(os.path.join(src, f"{log}.**.log")) + glob.glob(os.path.join(src, f"{log}.log")))
    else:
        paths = [src]
    frames = []
    for p in paths:
        fields, types = _read_header(p)
        rows = []
        with open(p, "r", errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                vals = line.rstrip("\n").split("\t")
                rows.append({f_: _zeek_value(v, t) for f_, t, v in zip(fields, types, vals)})
        if rows:
            frames.append(pd.DataFrame(rows))
    if not frames:
        return pd.DataFrame()
    df = pd.concat(frames, ignore_index=True)
    return df


def ingest(data_dir: str, out_dir: str = "data/parquet"):
    """Ingest all four logs from data_dir → data/parquet/<log>.parquet"""
    from pathlib import Path
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    for log in LOGS:
        try:
            df = load_log(data_dir, log)
        except FileNotFoundError:
            df = pd.DataFrame()
        pq.write_table(pa.Table.from_pandas(df, preserve_index=False), out / f"{log}.parquet")
        summary[log] = len(df)
    return summary


if __name__ == "__main__":
    import sys
    data = sys.argv[1] if len(sys.argv) > 1 else "data/zeek"
    print(ingest(data))

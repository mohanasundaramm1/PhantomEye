# ct/enrich/enrich_ct.py

import os, time, glob, json, socket, ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
import tldextract

# ---------- paths & config ----------

THIS_DIR  = os.path.dirname(__file__)
CT_DIR    = os.path.abspath(os.path.join(THIS_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(CT_DIR, ".."))

DATA_DIR = os.path.join(CT_DIR, "data")
RAW_DIR_DEFAULT      = os.path.join(DATA_DIR, "raw")
ENRICHED_DIR_DEFAULT = os.path.join(DATA_DIR, "enriched")
CACHE_DEFAULT        = os.path.join(DATA_DIR, "ip_api_cache.json")
STATE_DIR            = os.path.join(DATA_DIR, "state")
LATEST_PTR           = os.path.join(ENRICHED_DIR_DEFAULT, "_latest_enriched.json")
BOOKMARK_PATH        = os.path.join(STATE_DIR, "enrich_bookmark.json")

os.makedirs(ENRICHED_DIR_DEFAULT, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)

BRONZE     = os.getenv("CT_RAW_DIR", RAW_DIR_DEFAULT)
SILVER     = os.getenv("CT_ENRICHED_DIR", ENRICHED_DIR_DEFAULT)
CACHE_PATH = os.getenv("IP_API_CACHE", CACHE_DEFAULT)

MAX_BRONZE_FILES = int(os.getenv("MAX_BRONZE_FILES", "50"))
CAP_ROWS         = int(os.getenv("CAP_ROWS", "20000"))
MAX_DOMAINS      = int(os.getenv("MAX_DOMAINS", "1000"))
RESOLVE_THREADS  = int(os.getenv("RESOLVE_THREADS", "32"))

# if > 0: only consider rows newer than now - SINCE_MINUTES
SINCE_MINUTES    = int(os.getenv("SINCE_MINUTES", "0"))

# if 1: ignore bookmark (process based only on SINCE_MINUTES / CAP_ROWS)
IGNORE_BOOKMARK  = os.getenv("IGNORE_BOOKMARK", "0") == "1"

# if 1: delete bookmark before running (force full re-scan)
RESET_BOOKMARK   = os.getenv("RESET_BOOKMARK", "0") == "1"


# ---------- helpers ----------

def reg_domain(d: str) -> str:
    if not isinstance(d, str) or not d:
        return ""
    ext = tldextract.extract(d)
    # prefer top_domain_under_public_suffix, fall back to registered_domain
    reg = getattr(ext, "top_domain_under_public_suffix", None) or getattr(
        ext, "registered_domain", None
    ) or ""
    return reg.lower().strip()


def _read_bookmark():
    if RESET_BOOKMARK and os.path.exists(BOOKMARK_PATH):
        print(f"[info] RESET_BOOKMARK=1 → removing bookmark at {BOOKMARK_PATH}")
        try:
            os.remove(BOOKMARK_PATH)
        except OSError:
            pass

    if os.path.exists(BOOKMARK_PATH):
        try:
            with open(BOOKMARK_PATH, "r") as f:
                b = json.load(f)
                print(f"[info] loaded bookmark: {b}")
                return b
        except Exception as e:
            print("[warn] failed to read bookmark, ignoring:", e)
            return {}
    return {}


def _write_bookmark(bookmark: dict):
    tmp = BOOKMARK_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(bookmark, f)
    os.replace(tmp, BOOKMARK_PATH)
    print(f"[info] advanced bookmark → {bookmark}")


def read_bronze() -> pd.DataFrame:
    print(f"[info] BRONZE raw dir: {BRONZE}")

    all_paths = glob.glob(f"{BRONZE}/**/*.parquet", recursive=True)
    all_paths = [p for p in all_paths if os.path.isfile(p)]

    if not all_paths:
        print("no bronze data found in", BRONZE)
        return pd.DataFrame()

    # choose the most recently modified files, NOT lexicographically last
    all_paths_sorted = sorted(all_paths, key=os.path.getmtime)
    paths = all_paths_sorted[-MAX_BRONZE_FILES:]

    newest_mtime = datetime.fromtimestamp(os.path.getmtime(paths[-1]))
    oldest_mtime = datetime.fromtimestamp(os.path.getmtime(paths[0]))
    print(
        f"[info] discovered {len(all_paths)} parquet files under {BRONZE}; "
        f"using {len(paths)} most recent (mtime range: {oldest_mtime} → {newest_mtime})"
    )

    dfs = []
    for p in paths:
        try:
            dfp = pd.read_parquet(p)
            keep = [c for c in ("domain", "event_ts", "source", "ingest_ts") if c in dfp.columns]
            if keep:
                dfp = dfp[keep]
            dfs.append(dfp)
        except Exception as e:
            print("skip file", p, e)

    if not dfs:
        print("[warn] no rows loaded from parquet files")
        return pd.DataFrame()

    df = pd.concat(dfs, ignore_index=True)

    # normalize ingest_ts to UTC timestamp early so we can inspect ranges
    if "ingest_ts" in df.columns:
        df["ingest_ts"] = pd.to_datetime(df["ingest_ts"], utc=True, errors="coerce")
        print(
            "[info] ingest_ts range (raw):",
            df["ingest_ts"].min(),
            "→",
            df["ingest_ts"].max(),
        )
    else:
        print("[warn] no ingest_ts column in bronze; incremental logic will be disabled")

    # Optional: only keep recent minutes window
    if SINCE_MINUTES > 0 and "ingest_ts" in df.columns:
        cutoff = pd.Timestamp.utcnow().replace(tzinfo=timezone.utc) - pd.Timedelta(minutes=SINCE_MINUTES)
        print(f"[info] SINCE_MINUTES={SINCE_MINUTES} → keeping rows with ingest_ts > {cutoff}")
        df = df[df["ingest_ts"] > cutoff]

    # Incremental: filter by bookmark (unless explicitly ignored)
    bmk = _read_bookmark()
    last_ts = bmk.get("last_ingest_ts")
    if last_ts and "ingest_ts" in df.columns and not IGNORE_BOOKMARK:
        last_ts_parsed = pd.to_datetime(last_ts, utc=True, errors="coerce")
        print(f"[info] applying bookmark filter: ingest_ts > {last_ts_parsed}")
        before = len(df)
        df = df[df["ingest_ts"] > last_ts_parsed]
        print(f"[info] rows after bookmark filter: {before} → {len(df)}")
    elif last_ts and IGNORE_BOOKMARK:
        print(f"[info] IGNORE_BOOKMARK=1 → NOT filtering by bookmark (last_ingest_ts={last_ts})")
    else:
        print("[info] no bookmark present (first run or RESET_BOOKMARK=1)")

    if df.empty:
        print("no new bronze rows to enrich")
        return pd.DataFrame()

    # cap by CAP_ROWS, newest first
    if "ingest_ts" in df.columns:
        df = df.sort_values("ingest_ts").tail(CAP_ROWS)
    else:
        df = df.tail(CAP_ROWS)

    # domain normalization
    df["domain"] = (
        df["domain"]
        .astype(str)
        .str.lower()
        .str.strip()
        .str.rstrip(".")
        .str.replace("*.", "", regex=False)
    )
    df["registered_domain"] = df["domain"].map(reg_domain)
    df = df[df["registered_domain"].astype(bool)]

    # one row per registered_domain for enrichment
    df = df.drop_duplicates(subset=["registered_domain"])

    print(
        f"[info] bronze rows after filters: {len(df)} "
        f"(dedup registered_domain, CAP_ROWS={CAP_ROWS}, MAX_DOMAINS={MAX_DOMAINS})"
    )
    return df


def resolve_domain(d: str, timeout: float = 2.0):
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(d, None)
        return list({ai[4][0] for ai in infos if ai and ai[4]})
    except Exception:
        return []


def enrich_ip(ip: str, session: requests.Session):
    try:
        r = session.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,as,asname,org,query",
            timeout=2.5,
        )
        j = r.json()
        if j.get("status") == "success":
            return {
                "country": j.get("country"),
                "asn": j.get("as"),
                "asname": j.get("asname"),
                "org": j.get("org"),
            }
    except Exception:
        pass
    return {"country": None, "asn": None, "asname": None, "org": None}


def load_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache):
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, CACHE_PATH)


def is_ipv6(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).version == 6)
    except Exception:
        return 0


# ---------- main ----------

def main():
    df = read_bronze()
    if df.empty:
        return

    print(f"bronze rows (dedup regs): {len(df)}")

    regs = df["registered_domain"].dropna().unique().tolist()[:MAX_DOMAINS]

    # DNS resolve in parallel
    rows = []

    def _task(reg):
        ips = resolve_domain(reg)
        return reg, ips

    with ThreadPoolExecutor(max_workers=RESOLVE_THREADS) as ex:
        futs = {ex.submit(_task, reg): reg for reg in regs}
        for fut in as_completed(futs):
            reg, ips = fut.result()
            if not ips:
                rows.append({"registered_domain": reg, "ip": None})
            else:
                for ip in ips:
                    rows.append({"registered_domain": reg, "ip": ip})

    res_df = pd.DataFrame(rows)
    if res_df.empty:
        print("no IPs resolved")
        return

    cache = load_cache()
    session = requests.Session()
    enr_rows = []
    uniq_ips = [ip for ip in res_df["ip"].dropna().unique()]

    for ip in uniq_ips:
        if ip not in cache:
            cache[ip] = enrich_ip(ip, session)
            # beware of ip-api free limits; this controls speed
            time.sleep(0.15)
        enr_rows.append({"ip": ip, **cache[ip]})

    if uniq_ips:
        save_cache(cache)

    enr_df = (
        pd.DataFrame(enr_rows)
        if enr_rows
        else pd.DataFrame(columns=["ip", "country", "asn", "asname", "org"])
    )
    out = res_df.merge(enr_df, on="ip", how="left")

    agg = (
        out.groupby("registered_domain")
        .agg(
            num_unique_ips=("ip", "nunique"),
            has_ipv6=("ip", lambda s: int(any(is_ipv6(v) for v in s.dropna()))),
            num_countries=("country", "nunique"),
            num_asns=("asn", "nunique"),
            sample_asn=("asn", "first"),
            sample_isp=("asname", "first"),
            sample_country=("country", "first"),
        )
        .reset_index()
    )

    base = (
        df[["registered_domain", "domain", "event_ts", "source"]]
        .drop_duplicates("registered_domain")
    )
    agg = agg.merge(base, on="registered_domain", how="left").rename(
        columns={"domain": "domain_sample"}
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(SILVER, f"ct_enriched_{ts}.parquet")
    agg.to_parquet(out_path, index=False)
    print(f"wrote enriched domain features: {len(agg)} rows → {out_path}")

    # Update latest pointer file for the scorer
    with open(LATEST_PTR, "w") as f:
        json.dump({"path": out_path, "rows": len(agg), "created_utc": ts}, f)
    print(f"updated latest pointer: {LATEST_PTR}")

    # Advance bookmark (only if ingest_ts exists)
    if "ingest_ts" in df.columns and not df["ingest_ts"].empty:
        last_ingest_ts = df["ingest_ts"].max()
        _write_bookmark({"last_ingest_ts": str(last_ingest_ts)})

    # Debug / coverage
    print(agg.head(15))
    coverage_ips = (
        (agg["num_unique_ips"] > 0).mean() * 100.0
        if "num_unique_ips" in agg
        else 0.0
    )
    print(f"coverage: {coverage_ips:.1f}% domains have at least one resolved IP")


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# ct/score/measure_lead_time.py
#
# Measures the project's core differentiator directly: how many hours before
# a domain shows up in public reactive blocklists (OpenPhish, URLHaus) does
# this pipeline's CT-based scoring flag it as high-risk? "Predictive, not
# reactive" is a claim; this turns it into a number, computed the same way
# every time it's run, against whatever real data actually exists.
#
# Honesty constraints this script enforces on itself:
#   - Only domains the ML model scored HIGH RISK count as "CT flagged it" --
#     matching a blocklist domain by coincidence in low-score CT traffic
#     isn't the claim being tested.
#   - Deduplicates by registered_domain across ALL historical gold files,
#     taking the EARLIEST event_ts seen for each domain. This makes the
#     computation correct even across the repo's known history of duplicate/
#     stale re-scored gold files: re-scoring the same domain under a new
#     filename doesn't change when CT first actually saw it.
#   - Reports the effective sample size (distinct CT-observed high-risk
#     domains) prominently. A median/p90 over a small N is not a strong
#     claim, and this script does not pretend otherwise -- see the
#     "confidence" line in the report.
#   - This is designed to be re-run repeatedly and accumulate more real
#     signal over time as the (now fixed, see ct/enrich/enrich_worker.py
#     run_hot_cycle) hot-path scoring produces genuinely fresh distinct
#     snapshots every cycle, instead of a one-off inflated claim.
#
# Output:
#   - gold/detection_timeline/detection_timeline_<ts>.parquet -- one row per
#     CT-observed high-risk domain that also appeared in a blocklist, with
#     lead_time_hours (positive = CT saw it first).
#   - gold/detection_timeline/latest_summary.json -- the headline metrics,
#     machine-readable (for an API endpoint / dashboard panel to read).
#   - A human-readable report on stdout.

import argparse
import glob
import json
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import tldextract

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))

GOLD_DIR_DEFAULT = os.path.join(REPO_ROOT, "gold", "threat_scores")
OPENPHISH_DIR_DEFAULT = os.path.join(REPO_ROOT, "bronze", "openphish")
URLHAUS_DIR_DEFAULT = os.path.join(REPO_ROOT, "bronze", "urlhaus")
OUT_DIR_DEFAULT = os.path.join(REPO_ROOT, "gold", "detection_timeline")

DEFAULT_RISK_THRESHOLD = 0.90

# Deliberately deviates from the plain tldextract.extract() convention used
# elsewhere in the repo (ct/score/score_ct_with_latest.py, the enrichment
# DAGs): that convention treats PaaS/dynamic-DNS platforms (herokuapp.com,
# pages.dev, workers.dev, duckdns.org, ...) as ordinary domains, collapsing
# e.g. "evil-phish.herokuapp.com" -> "herokuapp.com". For lead-time matching
# that's actively wrong -- it compares "who saw traffic on Heroku's shared
# platform first" instead of "who saw the same malicious site first", and
# produces false matches with meaningless multi-hundred-hour deltas (this was
# caught by inspecting real output: every one of an initial 22 "matches" was
# exactly this collapse pattern, zero were genuine). include_psl_private_domains
# makes tldextract respect the Public Suffix List's private section, so these
# platforms are correctly treated as suffixes and the distinguishing
# subdomain is preserved.
_PSL_PRIVATE_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)


# ---------- helpers ----------

def reg_domain(d) -> str:
    """Normalize to the identity-bearing domain, respecting PSL private
    suffixes (see _PSL_PRIVATE_EXTRACTOR comment above) so that e.g.
    "evil.herokuapp.com" stays distinct from other *.herokuapp.com sites
    instead of collapsing to "herokuapp.com"."""
    if not isinstance(d, str) or not d:
        return ""
    ext = _PSL_PRIVATE_EXTRACTOR(d)
    reg = ext.top_domain_under_public_suffix or ""
    return reg.lower().strip()


def _host_from_url_or_domain(row_domain, row_url=None) -> str:
    """Bronze rows sometimes carry a bare domain, sometimes a URL. Prefer the
    domain column; fall back to extracting from the URL."""
    if isinstance(row_domain, str) and row_domain.strip():
        return row_domain
    if isinstance(row_url, str) and row_url.strip():
        return row_url
    return ""


# ---------- loaders ----------

def load_ct_high_risk(gold_dir: str, risk_threshold: float) -> pd.DataFrame:
    """Every distinct high-risk domain CT has ever observed, with the
    EARLIEST event_ts across all (possibly duplicate/stale) gold files.
    Grouped by raw_host (the actual observed hostname, e.g.
    "t4w.5c2.myftpupload.com"), not just registered_domain -- see
    compute_lead_time() for why both granularities matter."""
    files = sorted(glob.glob(os.path.join(gold_dir, "*.parquet")))
    frames = []
    for f in files:
        cols = ["registered_domain", "domain_sample", "event_ts", "risk_score"]
        try:
            df = pd.read_parquet(f, columns=cols)
        except Exception:
            try:
                df = pd.read_parquet(f)
                for c in cols:
                    if c not in df.columns:
                        df[c] = None
                df = df[cols]
            except Exception:
                continue
        frames.append(df)
    empty_cols = ["raw_host", "registered_domain", "ct_first_seen", "risk_score"]
    if not frames:
        return pd.DataFrame(columns=empty_cols)

    all_df = pd.concat(frames, ignore_index=True)
    all_df["registered_domain"] = all_df["registered_domain"].fillna("").astype(str).str.lower().str.strip()
    all_df["raw_host"] = all_df["domain_sample"].fillna("").astype(str).str.lower().str.strip()
    all_df.loc[all_df["raw_host"] == "", "raw_host"] = all_df["registered_domain"]
    all_df = all_df[all_df["registered_domain"] != ""]
    all_df["event_ts"] = pd.to_datetime(all_df["event_ts"], utc=True, errors="coerce")
    all_df = all_df[all_df["risk_score"] >= risk_threshold]

    if all_df.empty:
        return pd.DataFrame(columns=empty_cols)

    grouped = all_df.groupby("raw_host").agg(
        registered_domain=("registered_domain", "first"),
        ct_first_seen=("event_ts", "min"),
        risk_score=("risk_score", "max"),
    ).reset_index()
    return grouped.dropna(subset=["ct_first_seen"])


def load_blocklist_first_seen(openphish_dir: str, urlhaus_dir: str) -> pd.DataFrame:
    """Every distinct hostname seen across all OpenPhish/URLHaus bronze
    partitions, with the EARLIEST first_seen and which source(s) reported it.
    Grouped by raw_host (the literal observed hostname, e.g. from the
    reported URL), plus its PSL-aware registered_domain for the apex-level
    match tier."""
    parts = []

    for source, base in (("openphish", openphish_dir), ("urlhaus", urlhaus_dir)):
        files = sorted(glob.glob(os.path.join(base, "ingest_date=*", "*.parquet")))
        for f in files:
            try:
                cols = pd.read_parquet(f).columns  # small files; cheap enough
            except Exception:
                continue
            usecols = [c for c in ("domain", "url", "first_seen") if c in cols]
            try:
                df = pd.read_parquet(f, columns=usecols)
            except Exception:
                continue
            if "domain" not in df.columns:
                df["domain"] = None
            if "url" not in df.columns:
                df["url"] = None
            df["raw_host"] = df.apply(
                lambda r: _host_from_url_or_domain(r.get("domain"), r.get("url")), axis=1
            ).str.lower().str.strip()
            df["registered_domain"] = df["raw_host"].map(reg_domain)
            df["first_seen"] = pd.to_datetime(df.get("first_seen"), utc=True, errors="coerce")
            df["source"] = source
            parts.append(df[["raw_host", "registered_domain", "first_seen", "source"]])

    empty_cols = ["raw_host", "registered_domain", "blocklist_first_seen", "sources"]
    if not parts:
        return pd.DataFrame(columns=empty_cols)

    all_df = pd.concat(parts, ignore_index=True)
    all_df = all_df[all_df["registered_domain"] != ""]
    all_df = all_df.dropna(subset=["first_seen"])
    if all_df.empty:
        return pd.DataFrame(columns=empty_cols)

    grouped = all_df.groupby("raw_host").agg(
        registered_domain=("registered_domain", "first"),
        blocklist_first_seen=("first_seen", "min"),
        sources=("source", lambda s: ",".join(sorted(set(s)))),
    ).reset_index()
    return grouped


# ---------- computation ----------

_PRE_COLS = [
    "raw_host", "registered_domain", "ct_first_seen", "blocklist_first_seen",
    "risk_score", "sources", "match_tier",
]
_JOINED_COLS = _PRE_COLS[:-1] + ["lead_time_hours", "match_tier"]


def compute_lead_time(ct_df: pd.DataFrame, blocklist_df: pd.DataFrame) -> pd.DataFrame:
    """Two-tier match, most-confident first:

    1. "exact_hostname": the literal observed hostname matches on both sides
       (e.g. "t4w.5c2.myftpupload.com" seen by both CT and a blocklist). This
       is unambiguous -- same fully-qualified site, no suffix-list guessing.

    2. "registered_domain": PSL-aware apex match, for registered_domains not
       already covered by an exact_hostname match. Lower confidence: even
       PSL-aware normalization can't cover every shared-hosting/dynamic-DNS
       platform in existence (verified against real data -- see reg_domain()
       docstring), so an apex-only match may still mean "both datasets saw
       *something* on this shared platform" rather than "the same site."

    lead_time_hours > 0 means CT saw it before the blocklist did."""
    if ct_df.empty or blocklist_df.empty:
        return pd.DataFrame(columns=_JOINED_COLS)

    exact = ct_df.merge(blocklist_df, on="raw_host", suffixes=("", "_bl"), how="inner")
    exact["registered_domain"] = exact["registered_domain"]  # from ct_df (left)
    exact["match_tier"] = "exact_hostname"

    matched_hosts = set(exact["raw_host"])
    ct_apex = ct_df[~ct_df["raw_host"].isin(matched_hosts)].groupby("registered_domain").agg(
        ct_first_seen=("ct_first_seen", "min"), risk_score=("risk_score", "max"),
    ).reset_index()
    bl_apex = blocklist_df[~blocklist_df["raw_host"].isin(matched_hosts)].groupby("registered_domain").agg(
        blocklist_first_seen=("blocklist_first_seen", "min"),
        sources=("sources", lambda s: ",".join(sorted(set(",".join(s).split(","))))),
    ).reset_index()
    apex = ct_apex.merge(bl_apex, on="registered_domain", how="inner")
    apex["raw_host"] = apex["registered_domain"]
    apex["match_tier"] = "registered_domain"

    joined = pd.concat([exact[_PRE_COLS], apex[_PRE_COLS]], ignore_index=True)
    if joined.empty:
        return pd.DataFrame(columns=_JOINED_COLS)
    joined["lead_time_hours"] = (
        (joined["blocklist_first_seen"] - joined["ct_first_seen"]).dt.total_seconds() / 3600.0
    )
    return joined[_JOINED_COLS]


def summarize(ct_df: pd.DataFrame, joined_df: pd.DataFrame, risk_threshold: float) -> dict:
    n_ct = int(ct_df["registered_domain"].nunique()) if not ct_df.empty else 0
    n_matched = int(len(joined_df))
    n_exact = int((joined_df["match_tier"] == "exact_hostname").sum()) if n_matched else 0
    n_apex_only = n_matched - n_exact
    ahead = joined_df[joined_df["lead_time_hours"] > 0]
    behind_or_same = joined_df[joined_df["lead_time_hours"] <= 0]
    ahead_exact = ahead[ahead["match_tier"] == "exact_hostname"]

    summary = {
        "computed_utc": datetime.now(timezone.utc).isoformat(),
        "risk_threshold": risk_threshold,
        "n_ct_high_risk_domains": n_ct,
        "n_matched_total": n_matched,
        "n_matched_exact_hostname": n_exact,
        "n_matched_registered_domain_only": n_apex_only,
        "coverage_pct": round(100.0 * n_matched / n_ct, 2) if n_ct else None,
        "n_ct_ahead_of_blocklist": int(len(ahead)),
        "n_ct_ahead_exact_hostname_only": int(len(ahead_exact)),
        "n_blocklist_first_or_same_time": int(len(behind_or_same)),
        "pct_of_matches_ct_was_ahead": round(100.0 * len(ahead) / n_matched, 2) if n_matched else None,
        "median_lead_time_hours_when_ahead": (
            round(float(ahead["lead_time_hours"].median()), 2) if len(ahead) else None
        ),
        "p90_lead_time_hours_when_ahead": (
            round(float(np.percentile(ahead["lead_time_hours"], 90)), 2) if len(ahead) else None
        ),
        "n_ct_only_unconfirmed": n_ct - n_matched,
    }

    # Sample-size honesty: don't let a small N pass as a confident statistic,
    # and be explicit that registered_domain-only matches are lower-confidence
    # (may include shared-hosting-platform artifacts not covered by the PSL).
    if n_exact == 0 and n_apex_only == 0:
        confidence = "NO MATCHES -- cannot measure lead time yet."
    elif n_exact == 0:
        confidence = (
            f"NO exact-hostname matches; {n_apex_only} apex-only matches exist but are "
            f"LOWER CONFIDENCE -- likely includes shared-hosting-platform artifacts not "
            f"covered by the public suffix list. Do not treat as a proven lead-time claim."
        )
    elif n_exact < 30:
        confidence = f"LOW confidence -- only {n_exact} exact-hostname matches. Treat as directional, not a proven metric."
    elif n_exact < 200:
        confidence = f"MODERATE confidence -- {n_exact} exact-hostname matches."
    else:
        confidence = f"REASONABLE confidence -- {n_exact} exact-hostname matches."
    summary["confidence_note"] = confidence
    return summary


def _atomic_write_parquet(df: pd.DataFrame, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)


def _atomic_write_json(obj: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=str)
    os.replace(tmp, path)


def _print_report(summary: dict, joined_df: pd.DataFrame):
    print("=" * 72)
    print("CT DETECTION LEAD-TIME MEASUREMENT")
    print("(hours before a domain appears in OpenPhish/URLHaus that CT-based")
    print(" scoring already flagged it as high-risk)")
    print("=" * 72)
    for k, v in summary.items():
        if k == "confidence_note":
            continue
        print(f"  {k}: {v}")
    print()
    print(f"  CONFIDENCE: {summary['confidence_note']}")
    print("=" * 72)
    if len(joined_df):
        top = joined_df.sort_values("lead_time_hours", ascending=False).head(10)
        print("\nTop 10 earliest catches (largest lead time):")
        cols = ["raw_host", "match_tier", "ct_first_seen", "blocklist_first_seen", "sources", "lead_time_hours"]
        print(top[cols].to_string(index=False))


# ---------- CLI ----------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gold-dir", default=os.getenv("CT_SCORED_DIR", GOLD_DIR_DEFAULT))
    ap.add_argument("--openphish-dir", default=OPENPHISH_DIR_DEFAULT)
    ap.add_argument("--urlhaus-dir", default=URLHAUS_DIR_DEFAULT)
    ap.add_argument("--out-dir", default=OUT_DIR_DEFAULT)
    ap.add_argument("--risk-threshold", type=float, default=DEFAULT_RISK_THRESHOLD)
    ap.add_argument("--no-write", action="store_true", help="print the report but don't persist output")
    args = ap.parse_args(argv)

    print(f"[info] loading CT high-risk domains (risk_score >= {args.risk_threshold}) from {args.gold_dir}")
    ct_df = load_ct_high_risk(args.gold_dir, args.risk_threshold)
    print(f"[info] {len(ct_df)} distinct high-risk CT domains")

    print(f"[info] loading blocklist history from {args.openphish_dir} + {args.urlhaus_dir}")
    blocklist_df = load_blocklist_first_seen(args.openphish_dir, args.urlhaus_dir)
    print(f"[info] {len(blocklist_df)} distinct blocklisted domains")

    joined_df = compute_lead_time(ct_df, blocklist_df)
    summary = summarize(ct_df, joined_df, args.risk_threshold)

    _print_report(summary, joined_df)

    if not args.no_write:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(args.out_dir, f"detection_timeline_{ts}.parquet")
        _atomic_write_parquet(joined_df, out_path)
        summary_path = os.path.join(args.out_dir, "latest_summary.json")
        _atomic_write_json(summary, summary_path)
        print(f"\n[info] wrote {len(joined_df)} rows -> {out_path}")
        print(f"[info] wrote summary -> {summary_path}")

    return summary


if __name__ == "__main__":
    main()

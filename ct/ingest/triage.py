# ct/ingest/triage.py
#
# Cheap, fully-local triage scoring + deterministic sampling for CT intake.
#
# Applied *before* anything is forwarded downstream so that rate-limited
# enrichment (WHOIS/RDAP/DNS) only sees domains worth the cost:
#
#   1. sampling  - deterministic hash-based sampling (should_sample) bounds
#                  total intake volume; brand/suspicious-TLD hits bypass it.
#   2. triage    - triage_score(domain) -> (score 0-1, reasons) from
#                  local/free signals only (no network calls).
#
# All thresholds and lists load from config/triage.json (stdlib json only;
# the repo has no yaml dependency). Override path with CT_TRIAGE_CONFIG.

import os
import json
import math
import zlib
from collections import Counter

# ---------- config ----------

THIS_DIR = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
CONFIG_PATH_DEFAULT = os.path.join(REPO_ROOT, "config", "triage.json")

_config_cache = None


def load_config(path: str = None) -> dict:
    """Load triage config (cached). Override path via CT_TRIAGE_CONFIG env."""
    global _config_cache
    if path is None and _config_cache is not None:
        return _config_cache
    cfg_path = path or os.getenv("CT_TRIAGE_CONFIG", CONFIG_PATH_DEFAULT)
    with open(cfg_path) as f:
        cfg = json.load(f)
    if path is None:
        _config_cache = cfg
    return cfg


# ---------- primitives ----------


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string; 0.0 for empty input."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance, stdlib-only (two-row DP)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _tokens(domain: str) -> list:
    """Split a domain into label tokens: dots, hyphens and digits as breaks."""
    out = []
    for label in domain.split("."):
        for part in label.replace("_", "-").split("-"):
            tok = "".join(ch for ch in part if ch.isalpha())
            if tok:
                out.append(tok)
    return out


def _domain_under(domain: str, suffixes) -> bool:
    """True if `domain` equals or is a subdomain of any suffix, matched on
    label boundaries. Anchored on the END of the host so the classic
    lookalike trick (a.paypal.com.evil.tk) is NOT treated as under paypal.com --
    that host ends in .evil.tk, not .paypal.com. Same matching rule already used
    by on_free_subdomain_provider()."""
    for suf in suffixes:
        if domain == suf or domain.endswith("." + suf):
            return True
    return False


def _brand_match_distance_budget(kw: str) -> int:
    """Names <=5 chars match by exact token only -- edit distance is too
    collision-prone at short lengths: "apps", "able", "applied", "wappl",
    "maple" are all within distance 2 of "apple", and "ample" is distance 1
    -- found live, a 100%-confidence "apple" campaign whose members were
    apps.curdil.com, box.wappl.com, applied-pedagogy.com. Names >=6 chars
    keep a distance-1 budget (with a first-char anchor, see below, to stop
    that budget drifting onto unrelated words) -- this preserves catching
    genuine single-character typosquats like "paypal"->"paypai" (i/l swap)
    or "paypal"->"pypal" (missing letter, the classic homograph-attack
    shape), which distance<=6-chars-exact-only would otherwise also block
    despite those having no relationship to the apple/apps-style collision
    problem. The line sits between "apple" (5, exact-only, since even its
    own distance-1 neighbor "ample" is unrelated noise) and "paypal" (6,
    keeps its budget, no observed collision at that distance)."""
    return 0 if len(kw) <= 5 else 1


def brand_matches(domain: str, cfg: dict = None) -> list:
    """Return brand keywords matched by exact token, or by bounded Levenshtein
    distance on longer tokens -- token-BOUNDARY matching, not raw substring
    containment. See _brand_match_distance_budget() for why the distance
    budget depends on keyword length rather than being a single global value.

    A prior version matched via `kw in domain` as a fast-path before falling
    back to tokens, which happily matched "apple" inside "nzapplesandpears.com"
    (a produce association), "rappleyplumbingandheating.com" (r+APPLE+y), and
    "bergstromvolkswagenappleton.com" (a VW dealer in Appleton, WI) -- found
    live in the campaign queue, not a theoretical concern. _tokens() already
    splits on dots/hyphens/underscores, so exact-token-or-near-token matching
    correctly rejects all of those (they tokenize to one long unsplit token
    with a large Levenshtein distance from "apple") while still catching
    genuine attempts like "secure-apple-id.tk" (tokenizes to "apple" exactly).

    Provider-context suppression (the fix for legit-infrastructure false
    positives, e.g. s3.amazonaws.com wrongly scoring brand_match:amazon):

    - A *real brand* keyword (one with an entry in brand_self_domains) is
      suppressed ONLY when the host is under that brand's OWN domains. So the
      brand is never flagged on its own infrastructure, yet a phish for a
      DIFFERENT brand hosted on that infra (paypal-login.s3.amazonaws.com) still
      flags -- we only clear the "amazon" hit there, not the "paypal" hit.
    - A *generic sensitive word* (login/account/secure/verify/...; no
      brand_self_domains entry) is suppressed on ANY known-legit infrastructure
      (the union of every brand's own domains + infra_suffixes), since
      accounts.google.com / login.microsoftonline.com are legitimate. Free
      subdomain providers (pages.dev, web.app, ...) are deliberately NOT in this
      allowlist -- phishing lives there, so generic words must still fire.
    """
    cfg = cfg or load_config()
    keywords = cfg.get("brand_keywords", [])
    self_domains = cfg.get("brand_self_domains", {})
    # aggregate allowlist for generic-word suppression: all brands' own infra
    # plus generic CDN/cloud suffixes that carry no brand keyword themselves.
    allow_all = set(cfg.get("infra_suffixes", []))
    for doms in self_domains.values():
        allow_all.update(doms)

    hits = []
    toks = _tokens(domain)
    for kw in keywords:
        matched = False
        budget = _brand_match_distance_budget(kw)
        for tok in toks:
            if tok == kw:
                matched = True
                break
            # fuzzy branch only for keywords long enough to have a nonzero
            # budget; first-char anchor stops that budget drifting onto an
            # unrelated word that merely happens to be close in length.
            if budget > 0 and len(tok) >= 4 and tok[0] == kw[0] and levenshtein(tok, kw) <= budget:
                matched = True
                break
        if not matched:
            continue

        own = self_domains.get(kw)
        if own is not None:
            # real brand: only its own infra is exempt
            if _domain_under(domain, own):
                continue
        else:
            # generic word: any known-legit infra is exempt
            if _domain_under(domain, allow_all):
                continue

        hits.append(kw)
    return hits


def has_suspicious_tld(domain: str, cfg: dict = None) -> bool:
    cfg = cfg or load_config()
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    return tld in set(cfg.get("suspicious_tlds", []))


def on_free_subdomain_provider(domain: str, cfg: dict = None):
    """Return the matched provider suffix, or None."""
    cfg = cfg or load_config()
    for prov in cfg.get("free_subdomain_providers", []):
        if domain == prov or domain.endswith("." + prov):
            return prov
    return None


# ---------- sampling ----------


def should_sample(domain: str, cfg: dict = None) -> bool:
    """Deterministic keep/drop decision for a domain.

    Uses crc32(domain) mod 10000 against sample_rate so decisions are
    reproducible across restarts and processes (never random()).
    Brand-watchlist or suspicious-TLD domains bypass sampling entirely.
    """
    cfg = cfg or load_config()
    s = cfg.get("sampling", {})
    rate = float(s.get("sample_rate", 1.0))
    if rate >= 1.0:
        return True
    if s.get("always_include_suspicious_tld", True) and has_suspicious_tld(domain, cfg):
        return True
    if s.get("always_include_brand_match", True) and brand_matches(domain, cfg):
        return True
    bucket = zlib.crc32(domain.encode("utf-8")) % 10000
    return bucket < int(rate * 10000)


# ---------- triage score ----------


def triage_score(domain: str, cfg: dict = None):
    """Cheap local risk score for a domain.

    Returns (score, reasons): score in [0, 1], reasons is a list of
    per-signal strings explaining what fired.
    """
    cfg = cfg or load_config()
    t = cfg["triage"]
    w = t["weights"]
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return 0.0, []

    score = 0.0
    reasons = []

    if has_suspicious_tld(domain, cfg):
        score += w["suspicious_tld"]
        reasons.append("suspicious_tld:" + domain.rsplit(".", 1)[-1])

    # entropy of the registrable-ish label (longest label, skipping TLD)
    labels = domain.split(".")
    core = max(labels[:-1] or labels, key=len)
    ent = shannon_entropy(core)
    if len(core) >= 8 and ent >= t["entropy_threshold"]:
        score += w["high_entropy"]
        reasons.append("high_entropy:%.2f" % ent)

    brands = brand_matches(domain, cfg)
    if brands:
        score += w["brand_match"]
        reasons.append("brand_match:" + ",".join(sorted(set(brands))))

    hyphens = domain.count("-")
    if hyphens > t["max_hyphens"]:
        score += w["excessive_hyphens"]
        reasons.append("excessive_hyphens:%d" % hyphens)

    digits = sum(ch.isdigit() for ch in domain)
    alnum = sum(ch.isalnum() for ch in domain) or 1
    if digits / alnum > t["max_digit_ratio"]:
        score += w["excessive_digits"]
        reasons.append("excessive_digits:%.2f" % (digits / alnum))

    if len(domain) > t["max_domain_length"]:
        score += w["long_domain"]
        reasons.append("long_domain:%d" % len(domain))

    if any(label.startswith("xn--") for label in labels):
        score += w["punycode"]
        reasons.append("punycode")

    prov = on_free_subdomain_provider(domain, cfg)
    if prov:
        score += w["free_subdomain_provider"]
        reasons.append("free_subdomain_provider:" + prov)

    return min(score, 1.0), reasons

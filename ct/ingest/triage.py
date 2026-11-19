# ct/ingest/triage.py
#
# Cheap, fully-local triage scoring + deterministic sampling for CT intake.
#
# Applied *before* anything is forwarded downstream so that rate-limited
# enrichment (WHOIS/RDAP/DNS) only sees domains worth the cost:
#
#   1. triage    - triage_score(domain) -> (score 0-1, reasons) from
#                  local/free signals only (no network calls).
#   2. sampling  - only domains BELOW pass_threshold are sampled (should_sample);
#                  see route_domain() for why scoring must come first.
#
# Weights are fitted from data, not hand-set: see ml/core/fit_triage_weights.py.
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


# Visual homoglyph collapses -- character sequences that render as a single
# different character in most UI fonts, used specifically to dodge exact/
# edit-distance matching while looking identical to a human. "rn" -> "m" is
# the canonical case ("rnicrosoft.com", "rnetamask.io", ...): 2 raw edits
# from "microsoft" (insert n, substitute m->r), which exceeds the distance-1
# budget below AND fails the first-char anchor (r != m) -- so it was invisible
# to brand_matches() entirely, exact-budget or fuzzy, found live via the
# single-domain drilldown scoring www.rnicrosoft.com as 0.8% risk. Applied
# only as an ADDITIONAL exact-match candidate per token (never loosens the
# existing distance budget/anchor for anything else), so this can't reopen
# the apple/apps-style collision problem the budget function below guards
# against.
_HOMOGLYPH_COLLAPSES = (("rn", "m"),)


def _homoglyph_collapsed(tok: str) -> str:
    for seq, real in _HOMOGLYPH_COLLAPSES:
        tok = tok.replace(seq, real)
    return tok


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


_prep_cache = {}


def _brand_prep(cfg: dict):
    """Per-config derived data for brand_matches(), built once and reused.

    brand_matches() runs for every domain the forwarder sees (~1-2k/s), and
    rebuilding the ~150-entry allowlist set plus recomputing each keyword's
    distance budget on every call was a measurable share of the forwarder's
    CPU (it was saturated and CertStream was dropping certificates).

    Keyed on the identity of the config's list/dict objects (plus their
    lengths, as a cheap guard against in-place edits), with strong references
    held in the cache entry so an id can never be reused by a different
    object. A deep copy or a reloaded config gets its own entry."""
    keywords = cfg.get("brand_keywords", [])
    self_domains = cfg.get("brand_self_domains", {})
    infra = cfg.get("infra_suffixes", [])
    key = (id(keywords), len(keywords), id(self_domains), len(self_domains), id(infra), len(infra))
    hit = _prep_cache.get(key)
    if hit is not None:
        return hit[0]
    # aggregate allowlist for generic-word suppression: all brands' own infra
    # plus generic CDN/cloud suffixes that carry no brand keyword themselves.
    allow_all = set(infra)
    for doms in self_domains.values():
        allow_all.update(doms)
    prepared = (
        [(kw, _brand_match_distance_budget(kw), len(kw)) for kw in keywords],
        self_domains,
        allow_all,
    )
    if len(_prep_cache) > 32:  # configs are few; never let this grow unbounded
        _prep_cache.clear()
    _prep_cache[key] = (prepared, keywords, self_domains, infra)
    return prepared


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
    keywords, self_domains, allow_all = _brand_prep(cfg)

    hits = []
    toks = _tokens(domain)
    if not toks:
        return hits
    # The homoglyph collapse depends only on the token, so do it once per
    # token rather than once per (keyword x token) pair.
    toks_c = [(tok, _homoglyph_collapsed(tok), len(tok)) for tok in toks]
    for kw, budget, kw_len in keywords:
        matched = False
        for tok, collapsed, tok_len in toks_c:
            if tok == kw or collapsed == kw:
                matched = True
                break
            # fuzzy branch only for keywords long enough to have a nonzero
            # budget; first-char anchor stops that budget drifting onto an
            # unrelated word that merely happens to be close in length.
            # Edit distance is never less than the length difference, so a
            # token whose length differs from the keyword's by more than the
            # budget cannot match -- skip the O(n*m) computation for it.
            if (
                budget > 0
                and tok_len >= 4
                and tok[0] == kw[0]
                and abs(tok_len - kw_len) <= budget
                and levenshtein(tok, kw) <= budget
            ):
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
    # list membership, not set(...): building a 22-element set per domain cost
    # more than scanning the list once (and this runs for every domain).
    return tld in cfg.get("suspicious_tlds", ())


def on_free_subdomain_provider(domain: str, cfg: dict = None):
    """Return the matched provider suffix, or None."""
    cfg = cfg or load_config()
    for prov in cfg.get("free_subdomain_providers", []):
        if domain == prov or domain.endswith("." + prov):
            return prov
    return None


# ---------- sampling ----------


def should_sample(domain: str, cfg: dict = None, brand_hit: bool = None) -> bool:
    """Deterministic keep/drop decision for a domain.

    Uses crc32(domain) mod 10000 against sample_rate so decisions are
    reproducible across restarts and processes (never random()).
    Brand-watchlist or suspicious-TLD domains bypass sampling entirely.

    `brand_hit` lets a caller that has ALREADY run brand_matches() for this
    domain (route_domain, via its scoring reasons) pass the answer in rather
    than paying for the same match a second time; None means compute it.
    """
    cfg = cfg or load_config()
    s = cfg.get("sampling", {})
    rate = float(s.get("sample_rate", 1.0))
    if rate >= 1.0:
        return True
    if s.get("always_include_suspicious_tld", True) and has_suspicious_tld(domain, cfg):
        return True
    if s.get("always_include_brand_match", True):
        if brand_hit is None:
            brand_hit = bool(brand_matches(domain, cfg))
        if brand_hit:
            return True
    bucket = zlib.crc32(domain.encode("utf-8")) % 10000
    return bucket < int(rate * 10000)


# ---------- triage score ----------

# Every rule triage_score() can fire, in a fixed order. ml/core/
# fit_triage_weights.py fits one weight per entry, so rule DETECTION lives in
# one place (rule_hits) and both live scoring and weight-fitting use it --
# a fitted weight can never drift onto a subtly different rule definition.
RULES = (
    "suspicious_tld",
    "high_entropy",
    "brand_match",
    "sensitive_word",
    "excessive_hyphens",
    "excessive_digits",
    "long_domain",
    "punycode",
    "free_subdomain_provider",
)


def _normalize(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def rule_hits(domain: str, cfg: dict = None) -> dict:
    """Which triage rules fire for `domain`, as {rule: reason_string}.

    Rules that don't fire are absent. Pure detection -- no weights -- so the
    same function serves live scoring and offline weight fitting."""
    cfg = cfg or load_config()
    t = cfg["triage"]
    domain = _normalize(domain)
    if not domain:
        return {}

    hits = {}
    if has_suspicious_tld(domain, cfg):
        hits["suspicious_tld"] = "suspicious_tld:" + domain.rsplit(".", 1)[-1]

    # entropy of the registrable-ish label (longest label, skipping TLD)
    labels = domain.split(".")
    core = max(labels[:-1] or labels, key=len)
    ent = shannon_entropy(core)
    if len(core) >= 8 and ent >= t["entropy_threshold"]:
        hits["high_entropy"] = "high_entropy:%.2f" % ent

    # Real brands (keywords with a brand_self_domains entry: paypal, microsoft,
    # ...) and generic sensitive words (login, update, account, ...) are
    # separate rules because they are very different evidence. Measured on
    # one day of CT (2026-09-23): "update" alone fired 5,208 times on
    # sslip.io and generic words fired across ordinary hosting everywhere,
    # while a real brand name off its own infrastructure is rare. One shared
    # weight can't be right for both; splitting lets fitting weight each.
    matched = sorted(set(brand_matches(domain, cfg)))
    real = [kw for kw in matched if kw in cfg.get("brand_self_domains", {})]
    generic = [kw for kw in matched if kw not in real]
    if real:
        hits["brand_match"] = "brand_match:" + ",".join(real)
    if generic:
        hits["sensitive_word"] = "sensitive_word:" + ",".join(generic)

    hyphens = domain.count("-")
    if hyphens > t["max_hyphens"]:
        hits["excessive_hyphens"] = "excessive_hyphens:%d" % hyphens

    digits = sum(ch.isdigit() for ch in domain)
    alnum = sum(ch.isalnum() for ch in domain) or 1
    if digits / alnum > t["max_digit_ratio"]:
        hits["excessive_digits"] = "excessive_digits:%.2f" % (digits / alnum)

    if len(domain) > t["max_domain_length"]:
        hits["long_domain"] = "long_domain:%d" % len(domain)

    if any(label.startswith("xn--") for label in labels):
        hits["punycode"] = "punycode"

    prov = on_free_subdomain_provider(domain, cfg)
    if prov:
        hits["free_subdomain_provider"] = "free_subdomain_provider:" + prov

    return hits


def triage_score(domain: str, cfg: dict = None):
    """Cheap local risk score for a domain.

    Returns (score, reasons): score in [0, 1], reasons is a list of
    per-signal strings explaining what fired. The score is the sum of the
    weights of the rules that fired, capped at 1. A rule with weight 0 still
    appears in `reasons` (it fired, it just carries no evidence) so the
    explanation stays complete even when fitting zeroes a rule out.
    """
    cfg = cfg or load_config()
    w = cfg["triage"]["weights"]
    hits = rule_hits(domain, cfg)
    score = sum(w.get(rule, 0.0) for rule in hits)
    reasons = [hits[rule] for rule in RULES if rule in hits]
    return min(max(score, 0.0), 1.0), reasons


# ---------- intake routing ----------

FORWARD, SPOOL, DROP = "forward", "spool", "drop"


def route_domain(domain: str, cfg: dict = None):
    """Decide what the forwarder does with one CT domain.

    Returns (decision, score, reasons), decision in {FORWARD, SPOOL, DROP}:
      score >= pass_threshold  -> FORWARD (always -- never sampled away)
      below, and sampled       -> SPOOL   (low-priority jsonl, not enriched)
      below, and not sampled   -> DROP

    Scoring runs BEFORE sampling. The previous order sampled first, so a
    domain that would have scored well above the bar was still discarded 90%
    of the time unless it hit one of the two sampling bypasses (brand word,
    suspicious TLD). Measured on 5,000 OpenPhish/URLHaus domains: 60% of the
    malicious domains triage correctly scored >= the bar were thrown away
    that way (e.g. sp0ct-gorqax-biz-belrem-larnok.pages.dev, score 0.60).
    Scoring is pure string work, so running it on every domain is cheap;
    sampling exists to bound the volume of LOW-value domains and now only
    applies to those.
    """
    cfg = cfg or load_config()
    score, reasons = triage_score(domain, cfg)
    if score >= float(cfg["triage"]["pass_threshold"]):
        return FORWARD, score, reasons
    # Both brand rules come from the same brand_matches() call, so a reason
    # for either one means it matched -- no need to run the match again.
    brand_hit = any(r.startswith(("brand_match:", "sensitive_word:")) for r in reasons)
    if should_sample(domain, cfg, brand_hit=brand_hit):
        return SPOOL, score, reasons
    return DROP, score, reasons

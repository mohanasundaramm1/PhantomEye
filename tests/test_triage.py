import copy
import zlib

from ct.ingest.triage import (
    DROP,
    FORWARD,
    RULES,
    SPOOL,
    route_domain,
    rule_hits,
    load_config,
    shannon_entropy,
    levenshtein,
    brand_matches,
    has_suspicious_tld,
    on_free_subdomain_provider,
    should_sample,
    triage_score,
)

CFG = load_config()


# ---------- entropy ----------

def test_entropy_empty_string_is_zero():
    assert shannon_entropy("") == 0.0

def test_entropy_single_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0

def test_entropy_two_symbols_is_one_bit():
    assert abs(shannon_entropy("abababab") - 1.0) < 1e-9

def test_entropy_random_looking_is_high():
    assert shannon_entropy("x7f9q2kz8vw3") > 3.0


# ---------- levenshtein ----------

def test_levenshtein_identical():
    assert levenshtein("paypal", "paypal") == 0

def test_levenshtein_substitution():
    assert levenshtein("paypa1", "paypal") == 1

def test_levenshtein_insert_delete():
    assert levenshtein("papal", "paypal") == 1
    assert levenshtein("payypall", "paypal") == 2

def test_levenshtein_empty():
    assert levenshtein("", "abc") == 3
    assert levenshtein("abc", "") == 3


# ---------- brand matching ----------

def test_brand_substring_match():
    assert "paypal" in brand_matches("secure-paypal.example.com", CFG)

def test_brand_levenshtein_match():
    # 'paypa1' -> 'paypal' within distance 2, digit strips to 'paypa'
    assert "paypal" in brand_matches("paypai-login.top", CFG)

def test_brand_no_match_benign():
    assert brand_matches("wikipedia.org", CFG) == []


def test_brand_rejects_coincidental_substrings_found_live():
    """Regression test: raw-substring matching (`kw in domain`) on "apple"
    flagged a produce association, a Wisconsin VW dealer, and a pineapple
    company as brand_match:apple in the live product -- inflating their
    triage_score with a fabricated signal. Token-boundary matching must
    reject these while still catching genuine impersonation."""
    for host in ["nzapplesandpears.com", "rappleyplumbingandheating.com",
                 "bergstromvolkswagenappleton.com", "test.pineapplecostarica.com"]:
        assert "apple" not in brand_matches(host, CFG), f"{host} should NOT brand_match apple"
    assert "apple" in brand_matches("secure-apple-id.tk", CFG)


def test_brand_rejects_short_name_fuzzy_collisions_found_live():
    """Regression test: fixing the raw-substring bug above wasn't enough --
    the remaining bounded-Levenshtein fuzzy match (distance<=2, uniform
    across all keyword lengths) still let ordinary English words within
    distance 2 of "apple" through: apps.curdil.com, box.wappl.com, and
    applied-pedagogy.com were all live 100%-confidence "apple" campaign
    members. "apple" is 5 chars -> exact-token-only budget now (see
    _brand_match_distance_budget); none of these tokenize to "apple"
    exactly, so none should match."""
    for host in ["apps.curdil.com", "box.wappl.com", "applied-pedagogy.com",
                 "corp.n-able.com", "www.mapleleafplumbing.com", "www.example-ample.com"]:
        assert "apple" not in brand_matches(host, CFG), f"{host} should NOT brand_match apple"


def test_brand_matches_long_names_still_catch_single_edit_typosquats():
    """Names >=6 chars keep their distance-1 fuzzy budget (with a first-char
    anchor) -- confirms the length-based tightening didn't collapse to
    exact-only matching everywhere, only where collisions were observed.
    Note: standard Levenshtein (no transposition op) scores a swapped-letter
    typo like "binance"->"binnace" as distance 2, not 1 -- these use plain
    single-character substitutions instead, which are genuinely distance 1."""
    assert "binance" in brand_matches("binanse-exchange-login.com", CFG)  # c->s substitution
    assert "microsoft" in brand_matches("micros0ft-support.tk", CFG)      # digit strips to a 1-char deletion


# ---------- provider-context suppression (legit-infra false positives) ----------

def test_provider_own_infra_not_brand_matched():
    # The exact bug: a brand's own infrastructure must not flag as impersonation.
    assert "amazon" not in brand_matches("s3.amazonaws.com", CFG)
    assert "amazon" not in brand_matches(
        "bucket.vpce-029ec9ec13b648d4b-k0um8now-mx-central-1c.s3.mx-central-1.amazonaws.com", CFG)
    assert "google" not in brand_matches("storage.googleapis.com", CFG)
    assert "microsoft" not in brand_matches("login.microsoftonline.com", CFG)

def test_generic_words_suppressed_on_legit_infra():
    # Generic sensitive words are legitimate on a provider's own infra.
    assert brand_matches("accounts.google.com", CFG) == []       # 'account' + 'google'
    assert brand_matches("login.microsoftonline.com", CFG) == [] # 'login' + 'microsoft'
    assert brand_matches("support.apple.com", CFG) == []         # 'support' + 'apple'

def test_impersonation_still_flags_off_provider_infra():
    # A brand keyword on a domain that is NOT the brand's own infra must still flag.
    assert "paypal" in brand_matches("secure-paypal.example.com", CFG)
    assert "paypal" in brand_matches("paypal-secure-login.tk", CFG)
    # "appleid" is its own curated keyword (config/triage.json), not a fuzzy
    # match on "apple" -- "appleid" is distance 2 from "apple", the same
    # collision class as "apps"/"able"/"maple" (see
    # test_brand_rejects_coincidental_substrings_found_live), so it can't be
    # caught safely via fuzzy distance on the shorter root without
    # reintroducing that exact bug.
    assert "appleid" in brand_matches("appleid-account-update.xyz", CFG)

def test_phish_hosted_on_legit_cloud_still_flags_other_brand():
    # A phish for brand X HOSTED on provider Y's infra: X still flags, only Y is
    # exempt on its own infra. This is why real brands are suppressed only on
    # their OWN domains, never blanket-suppressed across a whole cloud.
    hits = brand_matches("paypal-login.s3.amazonaws.com", CFG)
    assert "paypal" in hits          # the impersonated brand still fires
    assert "amazon" not in hits      # the hosting provider is exempt on its own infra
    hits2 = brand_matches("coinbase-verify.web.app", CFG)
    assert "coinbase" in hits2       # phish on a free provider still flags
    assert "verify" in hits2         # free providers are NOT allowlisted infra

def test_lookalike_subdomain_trick_not_treated_as_legit():
    # a.paypal.com.evil.tk is registered under evil.tk, NOT paypal.com -- the
    # label-boundary anchoring must not treat it as paypal's own infra.
    assert "paypal" in brand_matches("login.paypal.com.evil.tk", CFG)

def test_provider_infra_drops_below_threshold():
    # A short legit provider host with no other signals should no longer be a
    # candidate now that the spurious brand_match is gone.
    score, reasons = triage_score("s3.amazonaws.com", CFG)
    assert score < CFG["triage"]["pass_threshold"], (score, reasons)
    assert not any(r.startswith("brand_match") for r in reasons)


# ---------- TLD flagging ----------

def test_suspicious_tld_flagged():
    assert has_suspicious_tld("evil.tk", CFG)
    assert has_suspicious_tld("foo.xyz", CFG)

def test_benign_tld_not_flagged():
    assert not has_suspicious_tld("example.com", CFG)


# ---------- free subdomain providers ----------

def test_free_provider_detected():
    assert on_free_subdomain_provider("phish.duckdns.org", CFG) == "duckdns.org"
    assert on_free_subdomain_provider("example.com", CFG) is None


# ---------- deterministic sampling ----------

def test_sampling_is_deterministic():
    for d in ["alpha.com", "beta.net", "gamma.org"]:
        first = should_sample(d, CFG)
        assert all(should_sample(d, CFG) == first for _ in range(5))

def test_sampling_matches_crc32_bucket():
    cfg = dict(CFG)
    cfg["sampling"] = {
        "sample_rate": 0.10,
        "always_include_brand_match": False,
        "always_include_suspicious_tld": False,
    }
    d = "some-random-neutral-domain.net"
    expected = (zlib.crc32(d.encode()) % 10000) < 1000
    assert should_sample(d, cfg) == expected

def test_sampling_bypass_for_brand_and_tld():
    cfg = dict(CFG)
    cfg["sampling"] = dict(CFG["sampling"], sample_rate=0.0)
    assert should_sample("paypal-verify.com", cfg)   # brand bypass
    assert should_sample("whatever.tk", cfg)         # suspicious TLD bypass

def test_sampling_rate_one_keeps_everything():
    cfg = dict(CFG)
    cfg["sampling"] = dict(CFG["sampling"], sample_rate=1.0)
    assert should_sample("anything.example", cfg)


# ---------- end-to-end triage_score ----------

THRESHOLD = CFG["triage"]["pass_threshold"]

def test_clearly_bad_domains_pass_threshold():
    bad = [
        "secure-paypal-login-verify.tk",
        "appleid-account-update.xyz",
        "microsoft-support-billing.duckdns.org",
        "xn--pypal-4ve.com",
    ]
    for d in bad:
        score, reasons = triage_score(d, CFG)
        assert score >= THRESHOLD, (d, score, reasons)
        assert reasons

def test_random_looking_suspicious_tld_ranks_above_benign_but_is_not_guaranteed_to_pass():
    # Deliberate tradeoff of the fitted weights (ml/core/fit_triage_weights.py),
    # not an oversight. Against real CT traffic, random-looking .top/.xyz names
    # with no brand word are extremely common and rarely appear in the
    # OpenPhish/URLHaus labels the weights were fit on, so suspicious_tld got a
    # small weight and this shape no longer clears the pass bar on its own.
    # What must still hold: it outranks ordinary benign names, so if the
    # scoring budget has room it's taken before them.
    dga_like, _ = triage_score("x7f9q2kz8vw3hj5m.top", CFG)
    for benign in ["example.com", "wikipedia.org", "cnn.com"]:
        assert dga_like > triage_score(benign, CFG)[0], benign

def test_clearly_benign_domains_below_threshold():
    benign = [
        "example.com",
        "wikipedia.org",
        "cnn.com",
        "mit.edu",
        "shop.example.co.uk",
    ]
    for d in benign:
        score, reasons = triage_score(d, CFG)
        assert score < THRESHOLD, (d, score, reasons)

def test_triage_score_bounds_and_empty():
    assert triage_score("", CFG) == (0.0, [])
    score, _ = triage_score("secure-paypal-login-verify-account-wallet.xn--e1afmkfd.tk", CFG)
    assert 0.0 <= score <= 1.0

def test_triage_reasons_labelled():
    score, reasons = triage_score("verify-paypal.tk", CFG)
    joined = " ".join(reasons)
    assert "brand_match" in joined
    assert "suspicious_tld:tk" in joined


# ---------- intake routing: score first, then sample ----------

def _cfg_with_sample_rate(rate):
    cfg = copy.deepcopy(CFG)
    cfg["sampling"]["sample_rate"] = rate
    return cfg

def test_high_scorer_is_forwarded_even_when_sampling_would_drop_it():
    # The bug this fixes: sampling ran first, so this real OpenPhish domain
    # (no brand word, not a watched TLD -> no sampling bypass) was discarded
    # 90% of the time despite scoring well above the bar.
    d = "sp0ct-gorqax-biz-belrem-larnok.pages.dev"
    cfg = _cfg_with_sample_rate(0.0)          # sampling keeps nothing
    assert not should_sample(d, cfg)
    decision, score, _ = route_domain(d, cfg)
    assert score >= cfg["triage"]["pass_threshold"]
    assert decision == FORWARD

def test_low_scorer_is_spooled_when_sampled_and_dropped_when_not():
    assert route_domain("example.com", _cfg_with_sample_rate(1.0))[0] == SPOOL
    assert route_domain("example.com", _cfg_with_sample_rate(0.0))[0] == DROP


# ---------- rule split + score arithmetic ----------

def test_real_brand_and_generic_word_are_separate_rules():
    hits = rule_hits("verify-paypal.tk", CFG)
    assert hits["brand_match"] == "brand_match:paypal"
    assert hits["sensitive_word"] == "sensitive_word:verify"

def test_score_is_sum_of_fired_rule_weights():
    w = CFG["triage"]["weights"]
    for d in ["verify-paypal.tk", "coinbase-wallet-support.pages.dev", "84991894.xyz"]:
        score, reasons = triage_score(d, CFG)
        expected = min(sum(w[r] for r in rule_hits(d, CFG)), 1.0)
        assert abs(score - expected) < 1e-9, d
        assert len(reasons) == len(rule_hits(d, CFG))

def test_every_rule_has_a_configured_weight():
    assert set(RULES) <= set(CFG["triage"]["weights"])


# ---------- allowlist additions (ownership checked via RDAP) ----------

def test_brand_own_infrastructure_added_from_ct_volume_is_not_flagged():
    for d in ["node-7.eastus.microsoft-falcon.net", "x.ppe-microsoft-falcon.net",
              "dev.microsoft", "api.twitch.advertising.amazon.dev",
              "instagram.floo1-2.fna.fbcdn.net"]:
        assert "brand_match" not in rule_hits(d, CFG), d

def test_lookalike_of_new_allowlisted_domain_still_flags():
    assert "brand_match" in rule_hits("microsoft-falcon.net.login-check.tk", CFG)


# ---------- second brand-list expansion: shipping, named banks, wallets, MS products ----------
# Added after measuring OpenPhish/URLHaus for brand-shaped tokens the original 24-word list
# missed entirely (fedex, chase, metamask, outlook, ... found live as real impersonation
# targets, e.g. "dhl-express-ppd.infanion.com", "outlook-office365.mgamt.com"). Ownership of
# each self-domain was checked via RDAP before allowlisting (corporate brand-protection
# registrars: CSC Corporate Domains, MarkMonitor, Network Solutions).

def test_new_brands_detected_when_impersonated():
    cases = [
        ("dhl-express-ppd.infanion.com", "dhl"),
        ("sign-in-to-xfinity-101765.weebly.com", None),  # xfinity NOT added (out of scope)
        ("chase-secure-login.tk", "chase"),
        ("metamask-wallet-verify.xyz", "metamask"),
        ("ledger-live-update.com", "ledger"),
        ("outlook-office365-signin.net", "outlook"),
        ("teams-microsoft-alert.com", "teams"),
        ("usps-redelivery-fee.top", "usps"),
    ]
    for d, expect in cases:
        hits = rule_hits(d, CFG)
        joined = hits.get("brand_match", "") + " " + hits.get("sensitive_word", "")
        if expect:
            assert expect in joined, (d, hits)

def test_new_brands_own_infrastructure_not_flagged():
    for d in ["www.fedex.com", "track.ups.com", "www.dhl.com", "informeddelivery.usps.com",
              "secure.chase.com", "www.wellsfargo.com", "www.hsbc.co.uk",
              "www.bankofamerica.com", "www.santander.com", "metamask.io",
              "www.ledger.com", "outlook.com", "www.office365.com",
              "onedrive.live.com", "teams.microsoft.com"]:
        assert "brand_match" not in rule_hits(d, CFG), d

def test_new_brands_lookalike_off_infra_still_flags():
    assert "brand_match" in rule_hits("fedex.com.tracking-alert.tk", CFG)
    assert "brand_match" in rule_hits("chase-bank.verify-account.xyz", CFG)

def test_generic_crypto_words_added():
    hits = rule_hits("free-crypto-airdrop-claim.top", CFG)
    assert "sensitive_word" in hits and "crypto" in hits["sensitive_word"]


# ---------- performance refactor must not change behavior ----------
# brand_matches() / route_domain() were optimized (per-config precompute, homoglyph
# collapse hoisted out of the keyword loop, edit distance skipped when the length
# gap alone rules a match out, brand match computed once per domain). The forwarder
# was CPU-saturated and CertStream was dropping certificates, but a faster matcher
# that matches different things would be worse than a slow one. The reference below
# is the straightforward algorithm; these must agree on every input.

from ct.ingest import triage as _T

_PARITY_DOMAINS = [
    "www.google.com", "accounts.google.com", "secure-apple-id.tk", "paypai-login.xyz",
    "pypal-verify.com", "paypal-login.s3.amazonaws.com", "nzapplesandpears.com",
    "apps.curdil.com", "www.rnicrosoft.com", "rnetamask.io", "coinbase-wallet-support.pages.dev",
    "dhl-express-ppd.infanion.com", "chase-bank.verify-account.xyz", "outlook-office365.mgamt.com",
    "paypall.com", "paypa.com", "paypaal-login.top", "binanse.xyz", "ledger-live-update.com",
    "teams.microsoft.com", "node.microsoft-falcon.net", "x7f9q2kz8vw3hj5m.top",
    "84991894.xyz", "medical-expense-loans-hjk.sbs", "a", "a.b", "...", "",
]


def _ref_brand_matches(domain, cfg):
    keywords = cfg.get("brand_keywords", [])
    sd = cfg.get("brand_self_domains", {})
    allow = set(cfg.get("infra_suffixes", []))
    for d in sd.values():
        allow.update(d)
    hits, toks = [], _T._tokens(domain)
    for kw in keywords:
        matched, budget = False, _T._brand_match_distance_budget(kw)
        for tok in toks:
            if tok == kw or _T._homoglyph_collapsed(tok) == kw:
                matched = True
                break
            if budget > 0 and len(tok) >= 4 and tok[0] == kw[0] and levenshtein(tok, kw) <= budget:
                matched = True
                break
        if not matched:
            continue
        own = sd.get(kw)
        if own is not None:
            if _T._domain_under(domain, own):
                continue
        elif _T._domain_under(domain, allow):
            continue
        hits.append(kw)
    return hits


def test_optimized_brand_matches_agrees_with_reference():
    for d in _PARITY_DOMAINS:
        assert brand_matches(d, CFG) == _ref_brand_matches(d, CFG), d

def test_route_domain_equals_score_then_sample():
    thr = float(CFG["triage"]["pass_threshold"])
    for rate in (0.0, 0.1, 1.0):
        cfg = _cfg_with_sample_rate(rate)
        for d in _PARITY_DOMAINS:
            decision, score, reasons = route_domain(d, cfg)
            s2, r2 = triage_score(d, cfg)
            assert (score, reasons) == (s2, r2), d
            expected = FORWARD if s2 >= thr else (SPOOL if should_sample(d, cfg) else DROP)
            assert decision == expected, (d, rate)

def test_should_sample_brand_hit_hint_matches_computing_it():
    cfg = _cfg_with_sample_rate(0.0)       # nothing sampled except bypasses, so the hint decides
    for d in _PARITY_DOMAINS:
        truth = bool(brand_matches(d, cfg))
        assert should_sample(d, cfg, brand_hit=truth) == should_sample(d, cfg), d

def test_config_cache_does_not_leak_between_configs():
    # per-config precompute is keyed on the config's own objects: a different
    # config (here: one that knows no brands) must not see another's cache.
    empty = copy.deepcopy(CFG)
    empty["brand_keywords"] = []
    assert brand_matches("secure-paypal-login.tk", CFG)
    assert brand_matches("secure-paypal-login.tk", empty) == []
    assert brand_matches("secure-paypal-login.tk", CFG)         # and back again

def test_length_gap_shortcut_never_hides_a_real_typosquat():
    # single-edit typosquats of long brands must still match after the shortcut
    for typo in ["paypai", "pypal", "paypall", "paypa1", "binanse", "coinbas", "metamas", "wellsfarg"]:
        d = f"{typo}-login.xyz"
        assert brand_matches(d, CFG) == _ref_brand_matches(d, CFG), d
    assert "paypal" in brand_matches("paypai-login.xyz", CFG)
    assert "paypal" in brand_matches("pypal-verify.com", CFG)

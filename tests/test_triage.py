import zlib

from ct.ingest.triage import (
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
        "x7f9q2kz8vw3hj5m.top",
    ]
    for d in bad:
        score, reasons = triage_score(d, CFG)
        assert score >= THRESHOLD, (d, score, reasons)
        assert reasons

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

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

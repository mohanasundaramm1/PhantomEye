"""MISP ground truth must match at the hostname MISP reported, never at a
shared platform above it.

Regression guard: collapsing both sides to registered_domain turned one
malicious "x.pages.dev" into a hit for every Cloudflare Pages site, and made
all 14 "MISP-confirmed" rows in the 2026-09-23 batch platform artifacts
(e.g. a MongoDB host on cosmos.azure.com). ti_misp_hit also feeds
risk_label_final, so this produced false "confirmed" calls in production.
"""
import pandas as pd

from ct.score.score_ct_with_latest import _misp_indicator_host, misp_host_hit
from ml.core.eval_precision_at_k import recompute_misp_ground_truth

MISP = {"evil-bank.com", "867633801.pages.dev", "mansablive.kinsta.cloud",
        "dvdhvbh.s3.us-east-1.amazonaws.com"}


def test_exact_listed_host_hits():
    assert misp_host_hit("867633801.pages.dev", MISP)


def test_sibling_on_same_platform_does_not_hit():
    assert not misp_host_hit("some-other-site.pages.dev", MISP)
    assert not misp_host_hit("someone-else.kinsta.cloud", MISP)
    assert not misp_host_hit("other-bucket.s3.us-east-1.amazonaws.com", MISP)


def test_subdomain_of_listed_host_hits():
    assert misp_host_hit("login.evil-bank.com", MISP)
    assert misp_host_hit("a.b.mansablive.kinsta.cloud", MISP)


def test_bare_platform_indicator_never_matches_everything():
    # even if a feed lists "pages.dev" itself, a public (incl. private) suffix
    # is never a valid match target
    assert not misp_host_hit("anything.pages.dev", {"pages.dev"})


def test_unrelated_cloud_host_does_not_hit():
    assert not misp_host_hit("pgmongo-synth.data.mongocluster.cosmos.azure.com", MISP)


def test_indicator_normalization():
    assert _misp_indicator_host("https://Login.Evil-Bank.com/path?x=1") == "login.evil-bank.com"
    assert _misp_indicator_host("www.evil-bank.com") == "evil-bank.com"
    assert _misp_indicator_host("*.evil-bank.com.") == "evil-bank.com"
    assert _misp_indicator_host("45.225.135.54") == "45.225.135.54"  # IP kept, harmless
    assert _misp_indicator_host(None) == ""


def test_eval_recomputes_instead_of_trusting_stored_labels():
    df = pd.DataFrame([
        {"domain_sample": "random.pages.dev", "registered_domain": "pages.dev", "ti_misp_hit": 1},
        {"domain_sample": "login.evil-bank.com", "registered_domain": "evil-bank.com", "ti_misp_hit": 0},
    ])
    gt = recompute_misp_ground_truth(df, MISP)
    assert gt.tolist() == [0, 1]

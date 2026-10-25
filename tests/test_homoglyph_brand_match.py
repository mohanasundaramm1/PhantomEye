"""The rn->m homoglyph trick and the drilldown's blindness to brand matches.

Regression guard for two stacked bugs found live via the single-domain
drilldown scoring www.rnicrosoft.com as 0.8% risk with no brand flag:

1. brand_matches() missed it even when called directly: distance("rnicrosoft",
   "microsoft") is 2, one over the distance-1 budget for long keywords, and
   the first-char anchor (r != m) blocked the fuzzy branch too.
2. api/main.py's /threats/score never called brand_matches() at all -- it
   only ran the ML model plus four generic lexical heuristics, so even an
   EXACT brand-keyword match would never surface there.
"""
from ct.ingest.triage import _homoglyph_collapsed, brand_matches


def test_homoglyph_collapse_turns_rn_into_m():
    assert _homoglyph_collapsed("rnicrosoft") == "microsoft"
    assert _homoglyph_collapsed("rnetamask") == "metamask"


def test_homoglyph_collapse_is_a_noop_when_absent():
    assert _homoglyph_collapsed("paypal") == "paypal"


def test_rnicrosoft_now_matches_microsoft():
    assert "microsoft" in brand_matches("rnicrosoft.com")


def test_real_microsoft_infra_still_exonerated_not_reopened_by_the_fix():
    # microsoft-falcon.net is in brand_self_domains -- the homoglyph collapse
    # must not bypass the existing provider-context suppression.
    assert brand_matches("login.microsoftonline.com") == []
    assert brand_matches("microsoft-falcon.net") == []


def test_unrelated_word_containing_rn_does_not_false_positive():
    # "corn" collapses to "com" via the same rule -- must not match any
    # brand keyword just because a substring happens to collapse usefully.
    assert brand_matches("popcorn-recipes.com") == []

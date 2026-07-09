"""Tests for ml/core/seed_benign_feedback.py -- pure logic against small
synthetic DataFrames, no dependency on the real 1M-row Tranco file."""
import pandas as pd

from ml.core.seed_benign_feedback import build_benign_sets, stratified_sample


def _tranco_df(domains):
    return pd.DataFrame({"rank": range(1, len(domains) + 1), "domain": domains})


def test_stratified_sample_respects_bucket_shares():
    # 100 domains per bucket, way more than needed
    short = [f"s{i}.com" for i in range(100)]            # len ~6-8
    mid = [f"midlength{i}.com" for i in range(100)]       # len ~14-17
    long_ = [f"averylongdomainname{i}.com" for i in range(100)]  # len ~26-28
    xlong = [f"anextremelylongdomainnameindeed{i}.com" for i in range(100)]  # len ~38-40
    df = _tranco_df(short + mid + long_ + xlong)
    buckets = [(0, 10, 0.25), (10, 20, 0.25), (20, 35, 0.25), (35, 1000, 0.25)]
    out = stratified_sample(df, n=40, buckets=buckets, seed=1)
    lengths = out["domain"].str.len()
    # each bucket should contribute close to its 25% share (10 of 40)
    assert ((lengths >= 0) & (lengths < 10)).sum() == 10
    assert ((lengths >= 10) & (lengths < 20)).sum() == 10
    assert ((lengths >= 20) & (lengths < 35)).sum() == 10
    assert (lengths >= 35).sum() == 10


def test_stratified_sample_handles_bucket_shortfall_gracefully():
    # only 2 domains available in the long bucket, but share wants more
    df = _tranco_df(["s1.com", "s2.com", "s3.com"] + ["averylongdomainname.com", "anotherverylongone.com"])
    buckets = [(0, 10, 0.5), (10, 1000, 0.5)]
    out = stratified_sample(df, n=20, buckets=buckets, seed=1)
    # short bucket: wants 10, only 3 available -> takes 3
    # long bucket: wants 10, only 2 available -> takes 2
    assert len(out) == 5
    assert not out["domain"].duplicated().any()


def test_stratified_sample_deterministic_with_fixed_seed():
    df = _tranco_df([f"domain{i}.com" for i in range(200)])
    buckets = [(0, 100, 1.0)]
    out1 = stratified_sample(df, n=20, buckets=buckets, seed=7)
    out2 = stratified_sample(df, n=20, buckets=buckets, seed=7)
    assert list(out1["domain"]) == list(out2["domain"])


def test_build_benign_sets_feedback_and_holdout_are_disjoint(tmp_path):
    # spans all 4 default length buckets ([0,12) [12,20) [20,30) [30,+)) so
    # the default stratification has enough rows in every bucket to fill it
    domains = (
        [f"s{i}.com" for i in range(150)]                                  # ~6-9 chars
        + [f"midsize{i}.com" for i in range(150)]                          # ~14-17 chars
        + [f"averylongdomainname{i}.com" for i in range(150)]              # ~26-29 chars
        + [f"anextremelylongdomainnameindeed{i}.com" for i in range(150)]  # ~38-41 chars
    )
    csv_path = tmp_path / "tranco.csv"
    pd.DataFrame({"rank": range(1, len(domains) + 1), "domain": domains}).to_csv(
        csv_path, header=False, index=False
    )

    feedback, holdout = build_benign_sets(
        tranco_path=str(csv_path), n_sample=100, holdout_fraction=0.2,
        seed=3, malicious_domains=set(),
    )
    assert len(feedback) == 80
    assert len(holdout) == 20
    assert set(feedback["domain"]).isdisjoint(set(holdout["domain"]))


def test_build_benign_sets_excludes_malicious_overlap(tmp_path):
    domains = [f"clean-{i}.com" for i in range(50)] + ["actually-phishing.com"]
    csv_path = tmp_path / "tranco.csv"
    pd.DataFrame({"rank": range(1, 52), "domain": domains}).to_csv(csv_path, header=False, index=False)

    feedback, holdout = build_benign_sets(
        tranco_path=str(csv_path), n_sample=40, holdout_fraction=0.2,
        seed=1, malicious_domains={"actually-phishing.com"},
    )
    all_sampled = set(feedback["domain"]) | set(holdout["domain"])
    assert "actually-phishing.com" not in all_sampled


def test_build_benign_sets_lowercases_and_dedupes(tmp_path):
    csv_path = tmp_path / "tranco.csv"
    pd.DataFrame({"rank": [1, 2, 3], "domain": ["Example.COM", "example.com", "other.com"]}).to_csv(
        csv_path, header=False, index=False
    )
    # n_sample=20 so bucket (0,12,0.10)'s share (round(20*0.10)=2) can fit
    # both unique post-dedup candidates ("example.com","other.com", 9-11
    # chars) -- not testing stratification math here, just lowercase+dedup.
    feedback, holdout = build_benign_sets(
        tranco_path=str(csv_path), n_sample=20, holdout_fraction=0.0,
        seed=1, malicious_domains=set(),
    )
    combined = pd.concat([feedback, holdout])
    assert not combined["domain"].duplicated().any()          # no dupes survive
    assert (combined["domain"] == combined["domain"].str.lower()).all()  # everything lowercase
    assert len(combined) == 2  # "Example.COM"/"example.com" deduped to one, plus "other.com"
    assert "example.com" in set(combined["domain"])

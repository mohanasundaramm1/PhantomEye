import numpy as np

from ml.core.fit_triage_weights import budget_recall, threshold_for_volume


def test_threshold_for_volume_lands_at_or_under_target():
    s = np.array([0.9, 0.5, 0.5, 0.2, 0.0])
    w = np.array([10.0, 20.0, 20.0, 100.0, 1000.0])
    # >=0.9 -> 10, >=0.5 -> 50, >=0.2 -> 150
    assert threshold_for_volume(s, w, 50) == 0.5
    assert threshold_for_volume(s, w, 49) == 0.9
    assert threshold_for_volume(s, w, 10_000) == 0.0


def test_budget_recall_ranks_above_cutoff_and_shares_ties():
    bg_s = np.array([0.9, 0.5, 0.1])
    bg_w = np.array([10.0, 20.0, 100.0])
    admit = np.ones(3, dtype=bool)
    # budget 20: all 10 at 0.9 fit, 10 of the 20 at 0.5 fit -> tie share 0.5
    pos_s = np.array([0.95, 0.5, 0.1])
    pos_admit = np.ones(3, dtype=bool)
    r = budget_recall(pos_s, pos_admit, bg_s, bg_w, admit, budget=20)
    assert abs(r - (1.0 + 0.5 + 0.0) / 3) < 1e-9


def test_budget_recall_counts_only_positives_that_reached_the_candidates():
    bg_s, bg_w, admit = np.array([0.5]), np.array([5.0]), np.array([True])
    pos_s, pos_admit = np.array([0.9, 0.9]), np.array([True, False])
    # budget exceeds all candidates -> recall is just the share admitted
    assert budget_recall(pos_s, pos_admit, bg_s, bg_w, admit, budget=100) == 0.5

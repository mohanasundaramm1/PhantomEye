"""api/main.py::load_model() -- mtime-based hot-reload. Mocks os.path.* and
lgb.Booster so the test never touches the real model registry files, and
resets api.main's module-level cache globals before/after so this test
can't leak state into other tests (or the real running API) that also
import api.main.
"""
from unittest.mock import MagicMock, patch

import api.main as api_main


def _reset_cache():
    api_main.MODEL = None
    api_main.MODEL_KIND = None
    api_main.MODEL_MTIME = None


def test_load_model_caches_across_calls_when_mtime_unchanged():
    _reset_cache()
    try:
        fake_booster = MagicMock()
        with patch.object(api_main, "lgb") as mock_lgb, \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getmtime", return_value=1000.0):
            mock_lgb.Booster.return_value = fake_booster

            model1, kind1 = api_main.load_model()
            model2, kind2 = api_main.load_model()

            assert model1 is fake_booster
            assert kind1 == kind2 == "lgbm_full"
            assert model1 is model2  # second call returned the cache, not a fresh load
            mock_lgb.Booster.assert_called_once()  # only loaded from disk once
    finally:
        _reset_cache()


def test_load_model_reloads_when_mtime_changes():
    _reset_cache()
    try:
        old_booster, new_booster = MagicMock(), MagicMock()
        with patch.object(api_main, "lgb") as mock_lgb, \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getmtime", side_effect=[1000.0, 2000.0]):
            mock_lgb.Booster.side_effect = [old_booster, new_booster]

            model1, _ = api_main.load_model()  # mtime=1000.0 -> loads old_booster
            model2, _ = api_main.load_model()  # mtime=2000.0 (changed) -> reloads

            assert model1 is old_booster
            assert model2 is new_booster
            assert mock_lgb.Booster.call_count == 2  # a freshly-promoted model gets picked up
    finally:
        _reset_cache()


def test_load_model_falls_back_to_logreg_when_lgbm_file_absent():
    _reset_cache()
    try:
        fake_logreg = MagicMock()
        with patch.object(api_main, "lgb", None), \
             patch("os.path.exists", side_effect=lambda p: p == api_main.LOGREG_MODEL_PATH), \
             patch.object(api_main, "joblib") as mock_joblib:
            mock_joblib.load.return_value = fake_logreg

            model, kind = api_main.load_model()

            assert model is fake_logreg
            assert kind == "logreg_full"
    finally:
        _reset_cache()

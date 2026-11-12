"""60-second detection finalization defaults; existing state must not be overwritten."""
from inspect import signature

import pytest

from cloud_soc.deployment.contract import defaults
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.retrospective import run_retrospective


@pytest.mark.parametrize("name", (
    "detector", "detector-priority", "detector-additional", "detector-retrospective"))
def test_new_detector_worker_finalization_is_sixty_seconds(name):
    options = defaults(name, "2026-11-12T00:00:00+00:00",
                       ["AUTH-001", "WEB-404-001"])
    assert options["--lateness-seconds"] == "60"
    assert options["--interval"] == "10"


def test_fast_default_and_historical_review_use_same_allowance():
    assert signature(run_incremental).parameters["lateness_seconds"].default == 60
    assert signature(run_retrospective).parameters["lateness_seconds"].default == 60


def test_old_state_identity_not_rewritten_by_code_default():
    from cloud_soc.deployment.contract import build_contract
    from pathlib import Path
    from unittest.mock import patch

    # Existing active contract remains authoritative. The new code must not
    # silently switch a pinned 900-second SQLite state to the 60-second identity.
    existing = {"version": 2, "policy_sha256": "fixed",
                "workers": {"detector": {"options": {
                    "--lateness-seconds": "900", "--interval": "10"}}}}
    policy = {"version": 2}
    with patch("cloud_soc.deployment.contract.digest", return_value="fixed"):
        unchanged, adopted = build_contract(policy, {}, Path("/state/unused"), existing=existing)
    assert unchanged == existing
    assert adopted == {}
    assert unchanged["workers"]["detector"]["options"]["--lateness-seconds"] == "900"

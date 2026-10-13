"""Provisional worker failure must not be hidden by successful final polling."""
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from cloud_soc.portal.operations import Operations, analysis_coverage


def reader(counts, **changes):
    stamp = datetime.now(timezone.utc).isoformat()
    status = {"@timestamp": stamp, "state": "success", "checkpoint": stamp,
              "last_success": stamp, "health": "warning", "counts": {"events": 0, **counts},
              "late_total": 0, "legacy_excluded": 0, "excluded_total": 0, "history_pending": 0, **changes}
    before = deepcopy(status)
    operations = Operations(None)
    operations.get = Mock(return_value=status)
    return operations, status, before


def test_current_early_failure_is_visible_when_final_detector_succeeded():
    operations, status, before = reader({"early_failed": 1})
    result = operations.worker_status("detector")
    assert result["state"] == "success"
    assert result["health"] == "warning"
    assert result["early"]["state"] == "failed"
    assert analysis_coverage({"state": "success", "health": "healthy"}, result) == {
        "state": "warning", "reason": "initial_notice_failed"}
    assert status == before


@pytest.mark.parametrize("flag,expected", [("early_final_reconcile_required", "reconcile_required"),
    ("early_final_link_pending", "pending"), ("early_delivery_pending", "pending"), ("early_scan_pending", "pending")])
def test_reconciliation_and_unfinished_initial_work_are_not_healthy(flag, expected):
    operations, _, _ = reader({flag: 1})
    result = operations.worker_status("detector")
    assert result["health"] == "warning" and result["early"]["state"] == expected


@pytest.mark.parametrize("bad", ["PRIVATE_CANARY", True, -1, 1.5])
def test_malformed_initial_counter_is_unknown_not_zero(bad):
    operations, _, _ = reader({"early_failed": bad})
    result = operations.worker_status("detector")
    assert result["early"]["state"] == "unknown" and result["health"] == "warning"
    assert "PRIVATE_CANARY" not in str(result)


def test_absent_early_counts_keep_old_workers_and_failed_stage_precedence():
    operations, _, _ = reader({})
    result = operations.worker_status("detector")
    assert "early" not in result and result["health"] == "healthy"
    operations, _, _ = reader({"early_failed": 1}, state="failed")
    result = operations.worker_status("detector")
    assert result["health"] == "failed"
    assert analysis_coverage({"state": "success"}, result)["state"] == "blocked"

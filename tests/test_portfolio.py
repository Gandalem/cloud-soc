"""Portfolio artifacts must exercise the production engine and preserve evidence."""
import importlib.util
from pathlib import Path

from cloud_soc.detection.worker import approved_rules
from cloud_soc.pipeline.alerts import make_alert_id

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('portfolio_eval', ROOT / 'tools/portfolio_eval.py')
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


def test_all_enabled_rule_profiles_have_structured_mitre():
    rules = approved_rules(include_cloud=True, include_sequence=True)
    assert len(rules) == 6
    for rule in rules:
        assert rule['mitre']['tactic']
        assert all(t['id'].startswith('T') and t['name'] for t in rule['mitre']['technique'])


def test_labeled_evaluation_has_positive_and_negative_controls():
    result = evaluation.evaluate()
    assert len(result['cases']) == 17
    assert all(not row['unexpected_rules'] for row in result['cases'])
    for counts in result['metrics'].values():
        assert counts['TP'] > 0 and counts['TN'] > 0
        assert counts['FP'] == counts['FN'] == 0


def test_demo_has_real_detection_and_replay_stable_exact_evidence():
    first, second = evaluation.demo(), evaluation.demo()
    assert len(first) == 3
    assert [r['alert_id'] for r in first] == [r['alert_id'] for r in second]
    for row in first:
        alert = row['alert']
        refs = alert['cloud_soc']['provenance']['evidence']
        assert len(refs) == 1 and refs[0]['complete']
        assert refs[0]['raw']['id'] == row['raw']['_id']
        assert alert['mitre']['technique']
        matches = evaluation.detect_events([row['normalized']], evaluation.approved_rules(include_cloud=True))
        assert make_alert_id(matches[0]) == row['alert_id']

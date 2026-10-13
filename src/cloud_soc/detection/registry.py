"""Code-owned detector registry. Rule files never import/execute arbitrary code."""
from typing import Protocol


class Detector(Protocol):
    def detect(self, events, rule, runtime): ...


class ThresholdDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.engine import _detect_threshold
        return _detect_threshold(events, rule, runtime=runtime)


class SingleDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.engine import _detect_threshold
        return [match for event in events for match in _detect_threshold([event], rule)]


class SequenceDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.sequence import detect_sequence
        return detect_sequence(events, rule, runtime if runtime is not None else {})


class BehaviorDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.behavior import detect_behavior
        return detect_behavior(events, rule, runtime)


class PatternDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.patterns import detect_pattern
        return detect_pattern(events, rule, runtime)


DETECTORS: dict[str, Detector] = {
    "threshold": ThresholdDetector(), "single": SingleDetector(), "sequence": SequenceDetector(),
    "ordered": BehaviorDetector(), "diversity": BehaviorDetector(),
    "cardinality": PatternDetector(),
}


def detect(events, rule, *, runtime=None):
    kind = rule.get("type", "threshold")
    if kind not in DETECTORS:
        raise ValueError("Unsupported detector type")
    return DETECTORS[kind].detect(events, rule, runtime)

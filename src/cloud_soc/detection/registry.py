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


DETECTORS: dict[str, Detector] = {
    "threshold": ThresholdDetector(), "single": SingleDetector(), "sequence": SequenceDetector(),
}


def detect(events, rule, *, runtime=None):
    kind = rule.get("type", "threshold")
    if kind not in DETECTORS:
        raise ValueError("Unsupported detector type")
    return DETECTORS[kind].detect(events, rule, runtime)

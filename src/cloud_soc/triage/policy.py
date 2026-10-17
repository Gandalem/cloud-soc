"""All 7-B weights, bands and timing limits live here, independent of rule risk."""
from dataclasses import dataclass, asdict
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.correlation.security_mall import require

VERSION = 'mall-triage-v1'


@dataclass(frozen=True)
class Policy:
    repeated_request_threshold: int = 3
    repetition_window_seconds: int = 300
    repeated_request_points: int = 5
    max_repetition_bonus: int = 15
    late_evidence_seconds: int = 120
    critical_min: int = 80
    high_min: int = 60
    medium_min: int = 30
    max_range_days: int = 30
    max_queue_frames: int = 128

    def __post_init__(self):
        require(all(type(value) is int for value in asdict(self).values()), 'triage_policy_invalid')
        require(2 <= self.repeated_request_threshold <= 100 and 1 <= self.repetition_window_seconds <= 3600 and
                0 <= self.repeated_request_points <= 20 and 0 <= self.max_repetition_bonus <= 30 and
                0 <= self.late_evidence_seconds <= 86400 and
                0 < self.medium_min < self.high_min < self.critical_min <= 100 and 1 <= self.max_range_days <= 30,
                'triage_policy_invalid')
        require(1 <= self.max_queue_frames <= 4096, 'triage_policy_invalid')

    @property
    def identity(self):
        return event_fingerprint({'version': VERSION, 'policy': asdict(self)})

    def priority(self, score):
        return ('critical' if score >= self.critical_min else 'high' if score >= self.high_min else
                'medium' if score >= self.medium_min else 'low')

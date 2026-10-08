from dataclasses import dataclass


@dataclass
class ProcessingStats:
    created: int = 0
    existing: int = 0
    unsupported: int = 0
    invalid: int = 0


@dataclass
class PipelineStats:
    raw: ProcessingStats
    alerts_created: int = 0
    normalized_invalid: int = 0

    @property
    def has_errors(self) -> bool:
        return bool(self.raw.invalid or self.normalized_invalid)

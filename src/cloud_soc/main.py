"""Compatibility entry point; implementation lives in pipeline and cli."""
import sys
from cloud_soc.pipeline import runtime

if __name__ == "__main__":
    raise SystemExit(runtime.main())
else:
    # Preserve existing imports and monkeypatch integrations during migration.
    sys.modules[__name__] = runtime

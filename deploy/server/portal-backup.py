"""Run on the server with Python 3.10+; standard library only, no credentials."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from cloud_soc.portal.backup import main

if __name__ == "__main__":
    raise SystemExit(main())

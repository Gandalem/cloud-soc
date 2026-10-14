"""Inspect the named existing deployment; never starts services or mutates state."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from cloud_soc.runtime_audit import inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--project", default="cloud-soc-central")
    parser.add_argument('--managed', action='store_true', help='Require all versioned runtime workers')
    args = parser.parse_args()
    print(json.dumps(inventory(args.workspace, args.project, managed=args.managed)))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Runtime audit unavailable; check read permissions and exact deployment identity. Details withheld.") from None

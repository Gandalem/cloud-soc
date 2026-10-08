"""P2-02 offline preparation / read-only checks. No apply or delete command."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.backup_readiness import (
    backup_health, balanced_capacity, expected_collection_indices, next_measurement, plan,
)

# Reuse the independent capacity CLI's existing TLS, key-file and bounded JSON guards.
spec = importlib.util.spec_from_file_location("p2_capacity_io", Path(__file__).with_name("capacity-report.py"))
io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(io)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Backup preparation only; no activation, writes or deletion")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("plan")
    prepare.add_argument("--repository", default="cloud-soc-p2-backup")
    prepare.add_argument("--storage-config", type=Path)
    capacity = sub.add_parser("capacity")
    capacity.add_argument("--previous", type=Path, required=True)
    capacity.add_argument("--current", type=Path, required=True)
    due = sub.add_parser("next-sample")
    due.add_argument("--report", type=Path, required=True)
    health = sub.add_parser("health")
    health.add_argument("--repository", required=True)
    health.add_argument("--inventory", type=Path, required=True)
    health.add_argument("--endpoint", required=True)
    health.add_argument("--ca-file", type=Path, required=True)
    health.add_argument("--api-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "plan":
        result = plan(io.read_json(args.storage_config) if args.storage_config else None, repository=args.repository)
    elif args.command == "capacity":
        result = balanced_capacity(io.read_json(args.previous), io.read_json(args.current))
    elif args.command == "next-sample":
        result = next_measurement(io.read_json(args.report))
    else:
        names = expected_collection_indices(io.read_json(args.inventory))
        # Validate names before any credentials are read or a connection is opened.
        from cloud_soc.backup_readiness import exact_repository
        exact_repository(args.repository)
        with io.connect(args) as es:
            result = backup_health(es, repository=args.repository, expected_indices=names)
    print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    return 2 if result.get("status") in ("attention", "unknown", "incomplete") else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("P2-02 backup check failed; verify inputs, TLS, permissions and server availability. Details withheld.", file=sys.stderr)
        raise SystemExit(1) from None

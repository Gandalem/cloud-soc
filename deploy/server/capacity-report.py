"""Standalone read-only P2-02 command; no portal, Compose or image changes."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from cloud_soc.capacity import collect, compare
from cloud_soc.snapshot_checks import inspect_snapshot, verify_fixture_restore


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Invalid report file")
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Report limit exceeded")
    return json.loads(raw.decode("utf-8-sig"))


def read_private_key(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Regular key file required")
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if ((info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 4096):
            raise ValueError("Invalid key file")
        if os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.geteuid()):
            raise ValueError("Key file must be private and owned")
        raw = stream.read(4097)
    key = raw.decode("ascii").strip()
    if len(raw) > 4096 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", key):
        raise ValueError("Invalid encoded key")
    return key


def connect(args):
    from elasticsearch import Elasticsearch

    url = urlsplit(args.endpoint)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")
            or any(ord(char) < 33 for char in args.endpoint)):
        raise ValueError("HTTPS origin required")
    key = read_private_key(args.api_key_file)
    if args.ca_file.is_symlink() or not args.ca_file.is_file():
        raise ValueError("CA file required")
    return Elasticsearch(args.endpoint, ca_certs=str(args.ca_file), api_key=key,
                         verify_certs=True, request_timeout=5, max_retries=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description="P2-02 read-only measurements; no deletion, ILM or restore writes")
    sub = parser.add_subparsers(dest="command", required=True)
    measure = sub.add_parser("measure")
    measure.add_argument("--hours", type=int, default=24)
    measure.add_argument("--warning", type=int, default=75)
    measure.add_argument("--critical", type=int, default=85)
    offline = sub.add_parser("compare")
    offline.add_argument("--previous", type=Path, required=True)
    offline.add_argument("--current", type=Path, required=True)
    offline.add_argument("--proposed-days", type=int, default=30)
    backup = sub.add_parser("snapshot")
    backup.add_argument("--repository", required=True)
    backup.add_argument("--snapshot", required=True)
    backup.add_argument("--expected-index", action="append", required=True)
    backup.add_argument("--max-age-hours", type=int, default=48)
    restore = sub.add_parser("restore-check")
    restore.add_argument("--restored-index", required=True)
    restore.add_argument("--fixture-id", required=True)
    for command in (measure, backup, restore):
        command.add_argument("--endpoint", required=True)
        command.add_argument("--ca-file", type=Path, required=True)
        command.add_argument("--api-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "compare":
        result = compare(read_json(args.previous), read_json(args.current), proposed_days=args.proposed_days)
    else:
        with connect(args) as es:
            if args.command == "measure":
                result = collect(es, hours=args.hours, warning=args.warning, critical=args.critical)
            elif args.command == "snapshot":
                result = inspect_snapshot(es, repository=args.repository, snapshot=args.snapshot,
                                          expected_indices=args.expected_index, max_age_hours=args.max_age_hours)
            else:
                result = verify_fixture_restore(es, restored_index=args.restored_index, fixture_id=args.fixture_id)
    print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    return 2 if result.get("status") in ("attention", "unknown") else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("P2-02 check failed; verify inputs, TLS, permissions and server availability. Details withheld.", file=sys.stderr)
        raise SystemExit(1) from None

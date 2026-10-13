"""Explicit reader repair; plan is read-only and apply requires a reviewed role hash."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.portal.reader_maintenance import ROLE, history_plan, restore_history_reader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-before-sha256")
    args = parser.parse_args()
    if args.apply and (not args.expected_before_sha256 or len(args.expected_before_sha256) != 64
                       or any(char not in "0123456789abcdef" for char in args.expected_before_sha256)):
        parser.error("Apply requires the exact SHA256 from a reviewed plan")
    with Elasticsearch(endpoint(args.es_url), basic_auth=(args.username, protected_key(args.password_file)),
                       ca_certs=args.ca_file, max_retries=0) as client:
        if args.apply:
            result = restore_history_reader(client, args.expected_before_sha256)
        else:
            result = {key: value for key, value in history_plan(client.security.get_role(name=ROLE)[ROLE]).items() if key != "role"}
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Reader history check failed; no credentials or upstream body disclosed.") from None

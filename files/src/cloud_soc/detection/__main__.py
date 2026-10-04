"""Default is offline validation. --run explicitly enables the bridge."""

import argparse
import json
from pathlib import Path
import time

from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.detection.worker import approved_rules, run_once
from cloud_soc.detection.incremental import run_incremental, utc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Existing SSH rule on soc-normalized-v1")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--max-documents", type=int, default=20000)
    parser.add_argument("--state", default="state/detection/runtime.sqlite")
    parser.add_argument("--start", help="Required explicit UTC normalization start on first run; keep unchanged on restart")
    parser.add_argument("--lateness-seconds", type=int, default=900)
    parser.add_argument("--snapshot", action="store_true", help="Explicit legacy offline/replay mode")
    parser.add_argument("--accept-legacy-exclusion", action="store_true", help="Explicitly exclude old documents missing normalized_at; original documents remain unchanged")
    parser.add_argument("--include-cloud", action="store_true", help="Opt in to the reviewed AWS/OCI cloud rule profile")
    parser.add_argument("--include-sequence", action="store_true", help="Opt in to SSH repeated-failure then success detection")
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    try:
        if (not 10 <= args.interval <= 3600 or not 1 <= args.max_documents <= 100000
                or args.once and not args.run):
            raise ValueError("Invalid options")
        selected_rules = approved_rules(include_cloud=args.include_cloud, include_sequence=args.include_sequence)
        if args.run and not args.snapshot:
            utc(args.start)
            if not 60 <= args.lateness_seconds <= 86400:
                raise ValueError("Invalid lateness")
        if not args.run:
            print(','.join(rule['id'] for rule in selected_rules) + " valid; source=soc-normalized-v1; offline; no writes")
            return 0
        url = endpoint(args.es_url)
        key = protected_key(args.api_key_file)
        ca = Path(args.ca_file)
        if not ca.is_file():
            raise ValueError("Missing CA")
        with Elasticsearch(url, api_key=key, ca_certs=str(ca),
                           request_timeout=30, max_retries=0) as client:
            while True:
                failed = False
                try:
                    result = (run_once(client, max_documents=args.max_documents, include_cloud=args.include_cloud, include_sequence=args.include_sequence) if args.snapshot else
                              run_incremental(client, state_path=args.state, start=args.start,
                                              max_documents=args.max_documents, lateness_seconds=args.lateness_seconds, source_id=url,
                                              accept_legacy_exclusion=args.accept_legacy_exclusion, include_cloud=args.include_cloud, include_sequence=args.include_sequence))
                    print(json.dumps(result), flush=True)
                except Exception:
                    failed = True
                    print("detection_cycle_failed; checkpoint retained; check portal health, state and permissions", flush=True)
                if args.once:
                    return int(failed)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("detector_configuration_or_connection_failed; credentials and payloads omitted")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

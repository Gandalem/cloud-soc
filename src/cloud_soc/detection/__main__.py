"""Default is offline validation. --run explicitly enables the bridge."""

import argparse
import json
from pathlib import Path
import time

from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.detection.worker import approved_rules, run_once


def main(argv=None):
    parser = argparse.ArgumentParser(description="Existing SSH rule on soc-normalized-v1")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--max-documents", type=int, default=20000)
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    try:
        if (not 10 <= args.interval <= 3600 or not 1 <= args.max_documents <= 100000
                or args.once and not args.run):
            raise ValueError("Invalid options")
        approved_rules()
        if not args.run:
            print("AUTH-001 valid; source=soc-normalized-v1; offline; no writes")
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
                    print(json.dumps(run_once(client, max_documents=args.max_documents)), flush=True)
                except Exception:
                    failed = True
                    print("detection_cycle_failed; check status, permissions and snapshot limit", flush=True)
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

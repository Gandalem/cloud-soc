"""Explicit execution only; default command performs offline validation."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import time
from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.processing.worker import run_once


def main(argv=None):
    parser = argparse.ArgumentParser(description="Metadata normalizer; detection is disabled")
    parser.add_argument("--start", required=True, help="Initial receipt-time floor, ISO8601 with zone")
    parser.add_argument("--state", default="state/processing/checkpoint.sqlite")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    try:
        start = parse_time(args.start)
        if start is None or start >= datetime.now(timezone.utc) or (args.once and not args.run):
            raise ValueError()
        if not args.run:
            print("Configuration valid. No network access. Detection disabled pending approval.")
            return 0
        url = endpoint(args.es_url)
        key = protected_key(args.api_key_file)
        ca = Path(args.ca_file)
        if not ca.is_file():
            raise ValueError()
        state = Path(args.state)
        state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with Elasticsearch(url, api_key=key, ca_certs=str(ca), request_timeout=15, max_retries=0) as client:
            while True:
                try:
                    result = run_once(client, state, args.start)
                    print("normalization_" + result["state"] + " checkpoint=" + result["checkpoint"], flush=True)
                except Exception:
                    print("normalization_failed; checkpoint retained; inspect permissions and service status", flush=True)
                    if args.once:
                        return 1
                if args.once:
                    return 0
                time.sleep(60)
    except Exception:
        print("normalizer_configuration_or_connection_failed; no credentials or payloads printed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

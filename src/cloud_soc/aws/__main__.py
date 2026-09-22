"""Opt-in CLI: validate only by default; no implicit AWS or Elasticsearch calls."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
import time
from urllib.parse import urlsplit

from cloud_soc.aws.collector import CollectionError, ElasticsearchSink, Settings, State, run_cycle


def protected_key(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise CollectionError("invalid_key_file")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o440, 0o600, 0o640):
        raise CollectionError("unsafe_key_file_permissions")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(c.isspace() for c in value):
        raise CollectionError("invalid_key_file")
    return value


def endpoint(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        if any(c.isspace() for c in value):
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise CollectionError("invalid_https_endpoint") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="CloudTrail management events; default: offline configuration validation")
    parser.add_argument("--config", required=True)
    parser.add_argument("--state", default="state/aws-cloudtrail.sqlite")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--run", action="store_true")
    modes.add_argument("--status", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    state = None
    try:
        config = Path(args.config)
        if config.stat().st_size > 16384:
            raise CollectionError("invalid_config")
        settings = Settings.parse(json.loads(config.read_text(encoding="utf-8")))
        if not 60 <= args.interval <= 3600 or (args.once and not args.run):
            raise CollectionError("invalid_run_options")
        if not args.run and not args.status:
            print(json.dumps({"status": "config_valid", "regions": settings.regions, "aws_contacted": False, "es_contacted": False}))
            return 0
        if args.status:
            if not Path(args.state).is_file():
                raise CollectionError("state_not_initialized")
            state = State(args.state, settings, now=datetime.now(timezone.utc))
            print(json.dumps({"regions": state.status(), "data_events": "not_collected"}))
            return 0
        url = endpoint(args.es_url)
        if not args.ca_file or not Path(args.ca_file).is_file() or not args.api_key_file:
            raise CollectionError("missing_tls_or_key_file")
        key = protected_key(args.api_key_file)
        # Optional dependency is loaded only for explicit collection, never at portal startup.
        import boto3
        from botocore.config import Config
        from elasticsearch import Elasticsearch
        sdk_config = Config(connect_timeout=5, read_timeout=20, retries={"mode": "standard", "total_max_attempts": 3},
                            ignore_configured_endpoint_urls=True)
        session = boto3.Session()
        sts = session.client("sts", region_name=settings.regions[0], config=sdk_config)
        clients = {region: session.client("cloudtrail", region_name=region, config=sdk_config) for region in settings.regions}
        state = State(args.state, settings, now=datetime.now(timezone.utc))
        with Elasticsearch(url, ca_certs=args.ca_file, api_key=key, request_timeout=20, max_retries=0) as es:
            sink = ElasticsearchSink(es)
            while True:
                try:
                    result = run_cycle(settings, state, sts, clients, sink)
                except CollectionError as error:
                    result = [{"status": "error", "code": str(error)}]
                print(json.dumps({"regions": result, "data_events": "not_collected"}), flush=True)
                if args.once:
                    return 1 if any(item["status"] == "error" for item in result) else 0
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        code = str(error) if isinstance(error, CollectionError) else "configuration_or_runtime_failed"
        print(json.dumps({"status": "error", "code": code}), file=sys.stderr)
        return 1
    finally:
        if state is not None:
            state.close()


if __name__ == "__main__":
    raise SystemExit(main())

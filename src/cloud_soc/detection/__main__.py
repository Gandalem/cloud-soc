"""Default is offline validation. --run explicitly enables the bridge."""

import argparse
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.detection.worker import approved_rules, run_once
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.detection.retrospective import run_retrospective
from cloud_soc.processing.errors import error_code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Existing SSH rule on soc-normalized-v1")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=None, help="Default 60s; explicit early AUTH mode defaults to 10s")
    parser.add_argument("--max-documents", type=int, default=20000, help="Incremental new-input budget per cycle; snapshot total limit")
    parser.add_argument("--max-active-events", type=int, default=20000, help="Explicit incremental pending/window state capacity")
    parser.add_argument("--state", default="state/detection/runtime.sqlite")
    parser.add_argument("--start", help="Required explicit UTC normalization start on first run; keep unchanged on restart")
    parser.add_argument("--lateness-seconds", type=int, default=900)
    parser.add_argument("--snapshot", action="store_true", help="Explicit legacy offline/replay mode")
    parser.add_argument("--accept-legacy-exclusion", action="store_true", help="Explicitly exclude old documents missing normalized_at; original documents remain unchanged")
    parser.add_argument("--include-cloud", action="store_true", help="Opt in to the reviewed AWS/OCI cloud rule profile")
    parser.add_argument("--include-sequence", action="store_true", help="Opt in to SSH repeated-failure then success detection")
    parser.add_argument("--include-attacks", action="store_true", help="Opt in to experimental metadata attack correlations; thresholds require real-data validation")
    parser.add_argument("--include-patterns", action="store_true", help="Opt in to enabled experimental metadata patterns; unverified candidates remain disabled")
    parser.add_argument("--isolated-all", action="store_true", help="All catalog rules including optional application extensions; writes require loopback HTTPS ES and separate state")
    parser.add_argument("--rules", help="Explicit comma-separated enabled rule IDs; AUTH-001 is retained; disabled candidates are refused")
    parser.add_argument("--additional-rules", help="Enabled rules excluding AUTH-001, in separate state/status; preserve existing AUTH worker")
    parser.add_argument("--retrospective", action="store_true",
                        help="Separate-state historical-context review for events normalized beyond the lateness allowance")
    parser.add_argument("--early-auth", action="store_true", help="Opt in to separate AUTH-001 provisional notices; needs explicit notice setup/permissions")
    parser.add_argument('--status-id', choices=('detector', 'detector-priority', 'detector-mall-login'), default=None,
                        help='Independent priority AUTH telemetry; state and alert IDs stay unchanged')
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    if args.interval is None:
        args.interval = 10 if args.early_auth else 60
    try:
        if (not 10 <= args.interval <= 3600 or not 1 <= args.max_documents <= 100000
                or not 1 <= args.max_active_events <= 1_000_000 or args.once and not args.run
                or args.early_auth and args.snapshot
                or args.status_id and (args.retrospective or args.snapshot
                                      or args.additional_rules is not None and args.status_id != 'detector-mall-login')
                or args.status_id == 'detector-mall-login' and (args.additional_rules != 'WEB-AUTH-01' or args.early_auth)
                or args.status_id == 'detector-priority' and args.early_auth):
            raise ValueError("Invalid options")
        selection = dict(include_cloud=args.include_cloud, include_sequence=args.include_sequence,
                         include_attacks=args.include_attacks, include_patterns=args.include_patterns,
                         isolated_all=args.isolated_all, rule_ids=args.rules.split(',') if args.rules is not None else None)
        if args.additional_rules is not None:
            if (args.snapshot or args.early_auth
                    or Path(args.state).resolve() == Path('state/detection/runtime.sqlite').resolve()):
                raise ValueError('Additional profile requires separate explicit state and no AUTH early/snapshot mode')
            selection['additional_rule_ids'] = args.additional_rules.split(',')
        if args.retrospective and (args.snapshot or args.early_auth or args.isolated_all
                or Path(args.state).resolve() == Path('state/detection/runtime.sqlite').resolve()):
            raise ValueError('Retrospective review requires separate explicit state, no early/snapshot/isolated mode')
        selected_rules = approved_rules(**selection)
        if args.isolated_all and args.run:
            target = urlsplit(args.es_url or '')
            if (target.scheme != 'https' or target.hostname not in ('127.0.0.1', '::1', 'localhost')
                    or Path(args.state).resolve() == Path('state/detection/runtime.sqlite').resolve() or target.username or target.password
                    or target.path or target.query or target.fragment):
                raise ValueError('Isolated profile requires explicit loopback HTTPS and separate state')
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
                    result = (run_retrospective(client, state_path=args.state, start=args.start,
                              lateness_seconds=args.lateness_seconds, max_documents=args.max_documents,
                              source_id=url, **selection) if args.retrospective else
                              run_once(client, max_documents=args.max_documents, **selection) if args.snapshot else
                              run_incremental(client, state_path=args.state, start=args.start,
                                              max_documents=args.max_documents, max_active_events=args.max_active_events,
                                              lateness_seconds=args.lateness_seconds, source_id=url,
                                              accept_legacy_exclusion=args.accept_legacy_exclusion, **selection, early_auth=args.early_auth,
                                              status_id=args.status_id))
                    print(json.dumps(result), flush=True)
                except Exception as error:
                    failed = True
                    print("detection_cycle_failed reason=" + error_code(error, "incremental_cycle_failed") + "; checkpoint retained", flush=True)
                if args.once:
                    return int(failed)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print("detector_configuration_or_connection_failed reason=" + error_code(error, "configuration_failed") + "; credentials omitted")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Explicit execution only; default command performs offline validation."""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import random
import signal
import tempfile
import threading
import time

from elasticsearch import Elasticsearch

from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.health.watchdog import WorkerHeartbeat
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.processing.errors import error_code
from cloud_soc.processing.worker import run_once
from cloud_soc.storage_backend import get_state_backend_type


class _GracefulShutdown(Exception):
    """Internal signal used to wake up immediately during cycle sleep."""


def _default_heartbeat_dir() -> str:
    return os.getenv(
        "CLOUD_SOC_HEALTH_DIR",
        str(Path(tempfile.gettempdir()) / "cloud-soc-health"),
    )


def page_limit(value):
    try:
        limit = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Page limit must be an integer") from None
    if not 1 <= limit <= 10000:
        raise argparse.ArgumentTypeError("Page limit must be between 1 and 10000")
    return limit


def main(argv=None):
    parser = argparse.ArgumentParser(description="Metadata normalizer; detection runs in a separate worker")
    parser.add_argument("--start", required=True, help="Initial receipt-time floor, ISO8601 with zone")
    parser.add_argument("--state", default="state/processing/checkpoint.sqlite")
    parser.add_argument(
        "--priority",
        action="store_true",
        help="Separate explicit state/receipt floor/status for recent intake; original backlog remains visible",
    )
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between cycles; 10..3600, default 60")
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Receipt window advance; 1..60, default 5. Existing partial windows finish first; "
        "the 15-minute overlap and page budget are preserved.",
    )
    parser.add_argument(
        "--linux-ssh-v2-start",
        help="Pinned receipt-time floor for new SSH formats; preserve earlier processing records",
    )
    parser.add_argument(
        "--web-site-v2-start",
        help="Opt-in site-preserving web normalization receipt floor; requires new explicit state",
    )
    parser.add_argument(
        "--max-pages",
        type=page_limit,
        default=1000,
        help="Input page budget per cycle (200 documents/page); default 1000. "
        "Larger receipt windows resume on the next cycle without skipping documents.",
    )
    args = parser.parse_args(argv)

    heartbeat = None
    previous_handlers = {}
    can_register_signal = threading.current_thread() is threading.main_thread()

    try:
        start = parse_time(args.start)
        if (
            start is None
            or start >= datetime.now(timezone.utc)
            or (args.once and not args.run)
            or not 10 <= args.interval <= 3600
            or not 1 <= args.window_minutes <= 60
        ):
            raise ValueError()
        if args.priority and Path(args.state).resolve() == Path("state/processing/checkpoint.sqlite").resolve():
            raise ValueError("Priority processing requires separate explicit state")
        if args.linux_ssh_v2_start is not None:
            ssh_start = parse_time(args.linux_ssh_v2_start)
            if ssh_start is None or not start <= ssh_start <= datetime.now(timezone.utc):
                raise ValueError()
        if args.web_site_v2_start is not None:
            web_start = parse_time(args.web_site_v2_start)
            if web_start is None or not start <= web_start <= datetime.now(timezone.utc):
                raise ValueError()
            if Path(args.state).resolve() == Path("state/processing/checkpoint.sqlite").resolve():
                raise ValueError("Site normalization requires separate explicit state")
        if not args.run:
            print("Configuration valid. No network access. Detection requires a separate worker.")
            return 0

        url = endpoint(args.es_url)
        key = protected_key(args.api_key_file)
        ca = Path(args.ca_file)
        if not ca.is_file():
            raise ValueError()

        state = Path(args.state)
        if get_state_backend_type() != "redis":
            state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        status_id = "normalizer-priority" if args.priority else "normalizer"
        if not args.once:
            heartbeat = WorkerHeartbeat(worker_name=status_id, base_dir=_default_heartbeat_dir())

        stop_requested = False
        in_sleep = False

        def _handle_shutdown(_signum, _frame):
            nonlocal stop_requested
            stop_requested = True
            if heartbeat is not None:
                heartbeat.mark_unready()
            if in_sleep:
                raise _GracefulShutdown()

        def _sleep_or_stop(seconds):
            nonlocal in_sleep
            if stop_requested:
                raise _GracefulShutdown()
            in_sleep = True
            try:
                # 기존 테스트의 time.sleep 몽키패치 호환성 유지
                time.sleep(seconds)
            finally:
                in_sleep = False
            if stop_requested:
                raise _GracefulShutdown()

        if can_register_signal and not args.once:
            for sig in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[sig] = signal.signal(sig, _handle_shutdown)

        with Elasticsearch(url, api_key=key, ca_certs=str(ca), request_timeout=15, max_retries=0) as client:
            if heartbeat is not None:
                heartbeat.mark_ready()
            while not stop_requested:
                delay = args.interval
                try:
                    result = run_once(
                        client,
                        state,
                        args.start,
                        max_pages=args.max_pages,
                        ssh_v2_start=args.linux_ssh_v2_start,
                        web_site_v2_start=args.web_site_v2_start,
                        window_minutes=args.window_minutes,
                        status_id=status_id,
                    )
                    if heartbeat is not None:
                        heartbeat.beat()
                    print("normalization_" + result["state"] + " checkpoint=" + result["checkpoint"], flush=True)
                    if result.get("progress", {}).get("state") == "catching_up":
                        delay = 0.1
                except TimeoutError:
                    # 다른 파드가 Redis Lease 점유 중: 정상 대기 상태로 처리하며 Liveness 유지
                    if heartbeat is not None:
                        heartbeat.beat()
                    print("normalization_lease_busy; waiting_for_peer", flush=True)
                    if args.once:
                        return 0
                    delay = min(args.interval, 2.0 + random.uniform(0.5, 2.0))
                except _GracefulShutdown:
                    return 0
                except Exception as failure:
                    if heartbeat is not None:
                        heartbeat.beat()
                    print("normalization_failed code=" + error_code(failure) + "; checkpoint retained", flush=True)
                    if args.once:
                        return 1

                if args.once:
                    return 0
                if stop_requested:
                    return 0
                try:
                    _sleep_or_stop(delay)
                except _GracefulShutdown:
                    return 0
            return 0
    except _GracefulShutdown:
        return 0
    except Exception:
        print("normalizer_configuration_or_connection_failed; no credentials or payloads printed")
        return 1
    finally:
        if heartbeat is not None:
            heartbeat.mark_unready()
        if can_register_signal:
            for sig, prev in previous_handlers.items():
                signal.signal(sig, prev)


if __name__ == "__main__":
    raise SystemExit(main())
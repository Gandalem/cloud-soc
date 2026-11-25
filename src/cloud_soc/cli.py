"""Command-line lifecycle, validation and retry policy."""

import argparse
import os
from pathlib import Path
import signal
import tempfile
import threading

from cloud_soc.health.watchdog import WorkerHeartbeat
from cloud_soc.logging_config import configure_logging
from cloud_soc.pipeline import runtime as pipeline


class _GracefulShutdown(Exception):
    """Internal signal used to wake up immediately during watch sleep."""


def _default_heartbeat_dir() -> str:
    return os.getenv(
        "CLOUD_SOC_HEALTH_DIR",
        str(Path(tempfile.gettempdir()) / "cloud-soc-health"),
    )


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", action="store_true", help="Repeat pipeline batches")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between batches")
    parser.add_argument(
        "--source-timezone",
        default="UTC",
        help="Fallback syslog timezone: UTC or +09:00",
    )
    parser.add_argument(
        "--prepare-lineage-mappings",
        action="store_true",
        help="Explicitly add provenance mappings, then exit without processing logs",
    )
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be positive")
    if args.watch and args.prepare_lineage_mappings:
        parser.error("--prepare-lineage-mappings cannot be combined with --watch")
    try:
        pipeline.parse_utc_offset(args.source_timezone)
    except ValueError as error:
        parser.error(str(error))

    client = None
    exit_code = 0
    heartbeat = (
        WorkerHeartbeat(worker_name="pipeline-worker", base_dir=_default_heartbeat_dir())
        if args.watch
        else None
    )
    stop_requested = False
    in_sleep = False
    previous_sigterm = None
    can_register_signal = threading.current_thread() is threading.main_thread()

    def _handle_sigterm(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True
        if heartbeat is not None:
            heartbeat.mark_unready()
        pipeline.LOGGER.info("SIGTERM received; shutting down gracefully after current batch")
        if in_sleep:
            raise _GracefulShutdown()

    def _sleep_or_stop(seconds: float) -> None:
        nonlocal in_sleep
        if stop_requested:
            raise _GracefulShutdown()
        in_sleep = True
        try:
            # 기존 테스트의 pipeline.time.sleep 몽키패치 호환성 유지
            pipeline.time.sleep(seconds)
        finally:
            in_sleep = False
        if stop_requested:
            raise _GracefulShutdown()

    if can_register_signal:
        previous_sigterm = signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        client = pipeline.create_elasticsearch_client()
        if args.prepare_lineage_mappings:
            pipeline.prepare_indices(client, apply_mappings=True)
            print("Provenance mappings prepared; no log documents were processed.")
        else:
            if heartbeat is not None:
                heartbeat.mark_ready()
            consecutive_failures = 0
            while not stop_requested:
                try:
                    stats = pipeline.run_pipeline_once(client, source_timezone=args.source_timezone)
                except _GracefulShutdown:
                    break
                except Exception as error:
                    consecutive_failures += 1
                    if (
                        not args.watch
                        or not pipeline.is_transient_error(error)
                        or consecutive_failures >= 3
                    ):
                        raise
                    if heartbeat is not None:
                        heartbeat.beat()
                    delay = min(args.interval * (2 ** (consecutive_failures - 1)), 60)
                    pipeline.LOGGER.warning(
                        "Transient %s; retry %d/2 in %ds",
                        type(error).__name__,
                        consecutive_failures,
                        delay,
                    )
                    _sleep_or_stop(delay)
                    continue

                consecutive_failures = 0
                if heartbeat is not None:
                    heartbeat.beat()
                if not args.watch:
                    exit_code = 2 if stats.has_errors else 0
                    break
                if stats.has_errors:
                    pipeline.LOGGER.error(
                        "Batch degraded; rejected documents remain in raw/normalized indices"
                    )
                if stop_requested:
                    break
                _sleep_or_stop(args.interval)
    except _GracefulShutdown:
        exit_code = 0
    except KeyboardInterrupt:
        exit_code = 130
    except Exception as error:
        if isinstance(error, pipeline.ProvenanceMappingError):
            pipeline.LOGGER.error("%s", error)
        # Avoid dumping ES request bodies, which may contain sensitive source logs.
        pipeline.LOGGER.error(
            "Pipeline failed (%s). Check connectivity, index permissions, rules, "
            "and docs/pipeline_reliability.md before retrying.",
            type(error).__name__,
        )
        exit_code = 1
    finally:
        if heartbeat is not None:
            heartbeat.mark_unready()
        if can_register_signal and previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)
        if client is not None:
            try:
                client.close()
            except Exception:
                pipeline.LOGGER.error("Elasticsearch client cleanup failed")
                exit_code = 1
    return exit_code
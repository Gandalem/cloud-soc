"""Command-line lifecycle, validation and retry policy."""
import argparse
from cloud_soc.pipeline import runtime as pipeline
from cloud_soc.logging_config import configure_logging


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", action="store_true", help="Repeat pipeline batches")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between batches")
    parser.add_argument("--source-timezone", default="UTC", help="Fallback syslog timezone: UTC or +09:00")
    parser.add_argument("--prepare-lineage-mappings", action="store_true",
                        help="Explicitly add provenance mappings, then exit without processing logs")
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
    try:
        client = pipeline.create_elasticsearch_client()
        if args.prepare_lineage_mappings:
            pipeline.prepare_indices(client, apply_mappings=True)
            print("Provenance mappings prepared; no log documents were processed.")
        else:
            consecutive_failures = 0
            while True:
                try:
                    stats = pipeline.run_pipeline_once(client, source_timezone=args.source_timezone)
                except Exception as error:
                    consecutive_failures += 1
                    if (not args.watch or not pipeline.is_transient_error(error)
                            or consecutive_failures >= 3):
                        raise
                    delay = min(args.interval * (2 ** (consecutive_failures - 1)), 60)
                    pipeline.LOGGER.warning("Transient %s; retry %d/2 in %ds",
                                   type(error).__name__, consecutive_failures, delay)
                    pipeline.time.sleep(delay)
                    continue
                consecutive_failures = 0
                if not args.watch:
                    exit_code = 2 if stats.has_errors else 0
                    break
                if stats.has_errors:
                    pipeline.LOGGER.error("Batch degraded; rejected documents remain in raw/normalized indices")
                pipeline.time.sleep(args.interval)
    except KeyboardInterrupt:
        exit_code = 130
    except Exception as error:
        if isinstance(error, pipeline.ProvenanceMappingError):
            pipeline.LOGGER.error("%s", error)
        # Avoid dumping ES request bodies, which may contain sensitive source logs.
        pipeline.LOGGER.error("Pipeline failed (%s). Check connectivity, index permissions, rules, "
                     "and docs/pipeline_reliability.md before retrying.", type(error).__name__)
        exit_code = 1
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pipeline.LOGGER.error("Elasticsearch client cleanup failed")
                exit_code = 1
    return exit_code



"""One-time explicit administrator command; never run by the detector."""

import argparse
import os
from pathlib import Path

from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.elastic.repository import ensure_security_alerts_index, ensure_provenance_mapping
from cloud_soc.processing.contract import NORMALIZED, STATUS
from cloud_soc.processing.setup import ROLE as NORMALIZER_ROLE
from cloud_soc.processing.setup import prepare as prepare_processing
from cloud_soc.detection.telemetry import RUNS, EXCLUSIONS

ROLE = {"cluster": [], "indices": [
    {"names": [NORMALIZED], "privileges": ["read", "view_index_metadata"]},
    {"names": ["security-alerts"], "privileges": ["create_doc", "view_index_metadata"]},
    {"names": [STATUS], "privileges": ["index"]},
    {"names": [RUNS, EXCLUSIONS], "privileges": ["create_doc"]},
]}


def prepare(client):
    for name in (NORMALIZED, STATUS):
        mapping = client.indices.get_mapping(index=name)
        if (set(mapping) != {name}
                or mapping[name]["mappings"].get("_meta", {}).get("contract") != name):
            raise ValueError("Run existing processing bootstrap first")
    ensure_security_alerts_index(client)
    if set(client.indices.get_mapping(index="security-alerts")) != {"security-alerts"}:
        raise ValueError("Expected concrete alert index")
    ensure_provenance_mapping(client, "security-alerts", apply=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare alert mapping and issue a dedicated detector key")
    parser.add_argument("--es-url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--worker", choices=("detector", "normalizer"), default="detector")
    parser.add_argument("--prepare-processing", action="store_true",
                        help="Explicitly prepare missing processing indices and the normalizer role")
    args = parser.parse_args(argv)
    key_path = Path(args.key_file)
    key_id = None
    try:
        url = endpoint(args.es_url)
        password = protected_key(args.password_file)
        if not Path(args.ca_file).is_file() or key_path.exists() or key_path.is_symlink():
            raise ValueError("Missing CA or existing output")
        # Reserve exclusively before issuing a key; never overwrite an old key.
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            with Elasticsearch(url, basic_auth=(args.username, password), ca_certs=args.ca_file,
                               request_timeout=30, max_retries=0) as client:
                try:
                    if args.prepare_processing:
                        prepare_processing(client)
                    prepare(client)
                    result = client.security.create_api_key(name="cloud-soc-intake-" + args.worker,
                        expiration="30d", role_descriptors={"intake_" + args.worker:
                            ROLE if args.worker == "detector" else NORMALIZER_ROLE})
                    key_id = result["id"]
                    output.write(result["encoded"] + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                except Exception:
                    if key_id:
                        client.security.invalidate_api_key(ids=[key_id])
                    raise
        print(args.worker + " prepared; protected key written; expires in 30 days; worker not started")
        return 0
    except Exception:
        print("detector_setup_failed; inspect reserved key file before retry; secrets omitted")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

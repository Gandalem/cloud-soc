"""Dedicated opt-in cleanup worker. No agent services or collected data changes."""

import os
from pathlib import Path
import time

from elasticsearch import Elasticsearch
from cloud_soc.portal.enrollment import Enrollments
from cloud_soc.portal.packages import PackageStore


def main():
    if os.environ.get("SOC_ENROLLMENT_ENABLED") != "1":
        raise SystemExit("Enrollment cleanup requires explicit SOC_ENROLLMENT_ENABLED=1.")
    ca = Path(os.environ["SOC_CA_FILE"])
    issuer = Elasticsearch(os.environ["SOC_INTERNAL_ES_URL"], ca_certs=str(ca),
        basic_auth=("cloud_soc_issuer", Path(os.environ["SOC_ISSUER_PASSWORD_FILE"]).read_text().strip()),
        request_timeout=5, max_retries=0)
    store = PackageStore(Path(os.environ["SOC_STATE_DIR"]), Path("/app/deploy/agents"), ca.read_bytes(),
                         os.environ.get("SOC_AGENT_ENDPOINT") or os.environ["SOC_ELASTIC_ENDPOINT"])
    service = Enrollments(store, issuer, None)
    while True:
        try:
            report = service.sweep()
            if report["cleanup_pending"]:
                print("Enrollment key cleanup pending; retrying next interval.", flush=True)
        except Exception:
            # Upstream bodies and local variables can contain secrets.
            print("Enrollment cleanup unavailable; retrying next interval.", flush=True)
        time.sleep(60)


if __name__ == "__main__":
    main()

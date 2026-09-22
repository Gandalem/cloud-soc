"""OCI collection is opt-in; default invocation validates config offline."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.oci.collector import CollectionError, ElasticsearchSink, Settings, State, run_cycle


class AuditPages:
    def __init__(self, sdk, client):
        self.sdk, self.client = sdk, client

    def page(self, compartment, start, end, token):
        args = {"page": token} if token is not None else {}
        response = self.client.list_events(compartment, start, end, **args)
        if response.status != 200 or not isinstance(response.data, list):
            raise CollectionError("invalid_oci_response")
        return [self.sdk.util.to_dict(event) for event in response.data], response.headers.get("opc-next-page")


def build_clients(settings, auth, config_file, profile):
    import oci
    # Only OC1 regions known to the pinned SDK, with explicit official endpoints.
    if any(oci.regions.REGION_REALMS.get(region) != "oc1" for region in settings.regions):
        raise CollectionError("unsupported_oci_region")
    if auth == "instance-principal":
        if os.environ.get("OCI_METADATA_BASE_URL"):
            raise CollectionError("metadata_override_not_allowed")
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        if signer.tenancy_id != settings.tenancy_id:
            raise CollectionError("oci_tenancy_mismatch")
        config = {}
    else:
        loaded = oci.config.from_file(str(Path(config_file).expanduser()), profile_name=profile)
        if loaded.get("tenancy") != settings.tenancy_id:
            raise CollectionError("oci_tenancy_mismatch")
        # Ignore endpoint/auth overrides; use only the standard API-key profile fields.
        config = {key: loaded[key] for key in ("tenancy", "user", "fingerprint", "key_file", "pass_phrase") if key in loaded}
        oci.config.validate_config({**config, "region": settings.regions[0]})
        signer = oci.signer.Signer(config["tenancy"], config["user"], config["fingerprint"], config.get("key_file"), pass_phrase=config.get("pass_phrase"))
    result = {}
    try:
        for region in settings.regions:
            client = oci.audit.AuditClient({**config, "region": region}, signer=signer,
                                         service_endpoint=f"https://audit.{region}.oraclecloud.com",
                                         timeout=(5, 20), retry_strategy=oci.retry.NoneRetryStrategy())
            result[region] = AuditPages(oci, client)
    except Exception:
        for wrapper in result.values():
            wrapper.client.base_client.session.close()
        raise
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="OCI Audit: offline validation unless --run is supplied")
    parser.add_argument("--config", required=True)
    parser.add_argument("--state", default="state/oci-audit.sqlite")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--run", action="store_true")
    modes.add_argument("--status", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--auth", choices=("config", "instance-principal"), default="config")
    parser.add_argument("--oci-config", default="~/.oci/config")
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--es-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--api-key-file")
    args = parser.parse_args(argv)
    state, clients = None, {}
    try:
        path = Path(args.config)
        if path.stat().st_size > 32768:
            raise CollectionError("invalid_config")
        settings = Settings.parse(json.loads(path.read_text(encoding="utf-8")))
        if not 60 <= args.interval <= 3600 or (args.once and not args.run):
            raise CollectionError("invalid_run_options")
        if not args.run and not args.status:
            print(json.dumps({"status": "config_valid", "scopes": len(settings.regions) * len(settings.compartments), "oci_contacted": False, "es_contacted": False}))
            return 0
        if args.status:
            if not Path(args.state).is_file():
                raise CollectionError("state_not_initialized")
            state = State(args.state, settings, now=datetime.now(timezone.utc))
            print(json.dumps({"scopes": state.status(), "object_access": "not_collected"}))
            return 0
        url = endpoint(args.es_url)
        if not args.ca_file or not Path(args.ca_file).is_file() or not args.api_key_file:
            raise CollectionError("missing_tls_or_key_file")
        key = protected_key(args.api_key_file)
        # Commit the initial floor before any credential or network work.
        state = State(args.state, settings, now=datetime.now(timezone.utc))
        clients = build_clients(settings, args.auth, args.oci_config, args.profile)
        from elasticsearch import Elasticsearch
        with Elasticsearch(url, ca_certs=args.ca_file, api_key=key, request_timeout=20, max_retries=0) as es:
            while True:
                result = run_cycle(settings, state, clients, ElasticsearchSink(es))
                print(json.dumps({"scopes": result, "object_access": "not_collected"}), flush=True)
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
        for wrapper in clients.values():
            wrapper.client.base_client.session.close()
        if state is not None:
            state.close()


if __name__ == "__main__":
    raise SystemExit(main())

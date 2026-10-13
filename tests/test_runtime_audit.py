from copy import deepcopy
import json

import pytest

from cloud_soc.runtime_audit import inventory, service_report, public_value


def container(service="detector"):
    return {"Id": "container-fixture", "Image": "sha256:fixture", "Config": {
        "Labels": {"com.docker.compose.service": service, "com.docker.compose.project": "cloud-soc-central", "cloud_soc.source": "a" * 40,
                   "private-label": "PRIVATE_CANARY"},
        "Env": ["SOC_PUBLIC_URL=https://soc.example.test", "PASSWORD=PRIVATE_CANARY",
                "SOC_API_KEY=PRIVATE_CANARY", "SOC_INTERNAL_ES_URL=https://user:PRIVATE_CANARY@soc.test"],
        "Cmd": ["python", "-m", "cloud_soc.detection", "--run", "--start", "2026-10-13T00:00:00Z",
                "--early-auth", "--interval", "10", "--api-key", "PRIVATE_CANARY"]},
        "State": {"Status": "running", "StartedAt": "2026-10-13T00:00:00Z"},
        "NetworkSettings": {"Networks": {"synthetic_network": {"private": "PRIVATE_CANARY"}}}}


def test_allowlist_never_exports_keys_labels_credentials_or_original_command():
    obj = container();before = deepcopy(obj);result = service_report([obj])
    assert "PRIVATE_CANARY" not in json.dumps(result)
    assert result["detector"]["options"]["--early-auth"] is True
    assert result["detector"]["options"]["--interval"] == "10"
    assert result["detector"]["public_environment"]["SOC_INTERNAL_ES_URL"] == "[withheld]"
    assert result["detector"]["source_labels"] == {"cloud_soc.source": "a" * 40}
    assert obj == before


def test_same_service_twice_is_not_silently_selected():
    with pytest.raises(ValueError):service_report([container(), container()])


@pytest.mark.parametrize("value", ["http://soc.test", "https://soc.test/?token=PRIVATE_CANARY", "https://user:pass@soc.test", "https://soc.test/#secret"])
def test_urls_with_credentials_or_query_data_are_withheld(value):
    assert public_value("SOC_PUBLIC_URL", value) == "[withheld]"


def test_missing_service_and_configuration_hash_are_observations_not_health(tmp_path):
    path = tmp_path / "active.json";path.write_text('{}')
    obj = container();obj["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(path)
    calls = []
    def inspect(args):calls.append(args);return [obj]
    result = inventory(tmp_path, inspect=inspect)
    assert result["read_only"] and "portal" in result["missing_services"]
    assert result["source_equivalence"] == "not_verified_by_image_label"
    assert "active.json" in result["active_config_sha256"]
    assert calls[0][:2] == ["docker", "inspect"]
    assert path.read_text() == '{}'


def test_configuration_outside_named_workspace_is_not_read(tmp_path):
    obj = container();obj["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(tmp_path.parent / "secret.env")
    with pytest.raises(ValueError):inventory(tmp_path, inspect=lambda _: [obj])


def test_invalid_known_option_values_and_other_project_are_not_disclosed(tmp_path):
    obj = container();obj["Config"]["Cmd"] += ["--start", "PRIVATE_CANARY", "--interval", "PRIVATE_CANARY", "--state", "PRIVATE_CANARY"]
    assert "PRIVATE_CANARY" not in json.dumps(service_report([obj]))
    obj["Config"]["Labels"]["com.docker.compose.project"] = "other-project"
    with pytest.raises(ValueError):inventory(tmp_path, inspect=lambda _: [obj])

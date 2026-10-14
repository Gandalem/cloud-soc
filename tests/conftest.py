"""Explicit opt-in doubles; real ownership integration never requests this fixture."""
import pytest

from deployment_ownership import DeploymentOS, OwnershipCalls


@pytest.fixture
def ownership_calls(tmp_path, monkeypatch):
    from cloud_soc.deployment import host, migrations
    calls = OwnershipCalls(tmp_path)
    for module in (host, migrations):
        monkeypatch.setattr(module, 'os', DeploymentOS(calls.chown))
    return calls

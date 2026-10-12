"""Local guard tests; these never create containers or connect to a server."""
from io import BytesIO
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tools import verify_p5_disposable as runner
from p5_03_live_checks import guarded_admin


def archive(tmp_path, name, *, kind=None):
    path = tmp_path / 'public.tar.gz'
    with tarfile.open(path, 'w:gz') as bundle:
        member = tarfile.TarInfo(name)
        if kind is not None:
            member.type = kind
            member.linkname = '/outside'
            bundle.addfile(member)
        else:
            member.size = 2
            bundle.addfile(member, BytesIO(b'ok'))
    target = tmp_path / 'target'
    target.mkdir()
    return path, target


@pytest.mark.parametrize('name', ['../outside', '/outside', 'src/../../outside'])
def test_archive_rejects_escape(tmp_path, name):
    source, target = archive(tmp_path, name)
    with pytest.raises(ValueError, match='Unsafe fixture'):
        runner.extract(source, target)
    assert list(target.iterdir()) == []


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_archive_rejects_nonregular(tmp_path, kind):
    source, target = archive(tmp_path, 'src/member', kind=kind)
    with pytest.raises(ValueError, match='Unsafe fixture'):
        runner.extract(source, target)
    assert list(target.iterdir()) == []


def test_archive_extracts_regular_fixture(tmp_path):
    source, target = archive(tmp_path, 'src/member.py')
    runner.extract(source, target)
    assert (target / 'src/member.py').read_bytes() == b'ok'


def test_launcher_requires_explicit_optin_before_docker():
    with patch.object(runner, 'os', SimpleNamespace(name='posix', geteuid=lambda: 0)), \
            patch('sys.argv', ['verify', '--archive', 'unused', '--sha256', 'unused']), \
            patch.object(runner, 'command') as command:
        with pytest.raises(ValueError, match='Explicit root'):
            runner.main()
        command.assert_not_called()


@pytest.mark.parametrize('enabled,cluster', [('', ''), ('1', 'docker-cluster'), ('1', 'p5-fixture-short')])
def test_es_identity_guard_precedes_network(monkeypatch, enabled, cluster):
    monkeypatch.setenv('SOC_P5_DISPOSABLE_FIXTURE', enabled)
    monkeypatch.setenv('SOC_P5_FIXTURE_CLUSTER', cluster)
    with patch('p5_03_live_checks.Elasticsearch') as client:
        with pytest.raises(ValueError, match='Explicit disposable'):
            guarded_admin()
        client.assert_not_called()

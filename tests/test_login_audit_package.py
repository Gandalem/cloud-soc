"""Validate the merged deployment package without touching a mall or ES service."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'deploy/security-mall/login-audit'


def test_packaged_assets_preserve_the_tested_intake_contract():
    assert (PACKAGE / 'security-mall-audit.js').read_bytes() == (
        ROOT / 'filebeat/security-mall/security-mall-audit.js').read_bytes()
    assert yaml.safe_load((PACKAGE / 'filebeat.example.yml').read_text()) == yaml.safe_load(
        (ROOT / 'filebeat/security-mall/filebeat.example.yml').read_text())
    assert json.loads((PACKAGE / 'pipeline.json').read_text()) == yaml.safe_load(
        (ROOT / 'deploy/security-mall/ingest-pipeline.yml').read_text())
    assert json.loads((PACKAGE / 'index-template.json').read_text()) == json.loads(
        (ROOT / 'deploy/security-mall/index-template.json').read_text())


@pytest.fixture
def patcher():
    spec = importlib.util.spec_from_file_location('login_audit_apply', PACKAGE / 'apply.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.apply


@pytest.fixture
def mall(tmp_path):
    """Reconstruct the exact patch preimage from unchanged/deleted hunk lines."""
    repo = tmp_path / 'mall'
    repo.mkdir()
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    files = {}
    current = None
    in_hunk = False
    # Preserve CRLF in the controller: the reviewed patch contains mixed EOLs.
    for line in (PACKAGE / 'security-mall-login.patch').read_bytes().splitlines(keepends=True):
        if line.startswith(b'diff --git '):
            current = None
            in_hunk = False
        elif line.startswith(b'--- a/'):
            current = line[6:].strip().decode()
            files.setdefault(current, [])
        elif line.startswith(b'\\ No newline') and current and files[current]:
            files[current][-1] = files[current][-1].rstrip(b'\r\n')
        elif line.startswith(b'@@ '):
            in_hunk = True
        elif in_hunk and current and line[:1] in (b' ', b'-'):
            files[current].append(line[1:])
    for name, lines in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b''.join(lines))
    return repo


def test_patch_applies_and_repeated_application_is_idempotent(patcher, mall):
    patcher(mall)
    java = mall / 'src/main/java/com/security/securitymall/audit/LoginAudit.java'
    controller = mall / 'src/main/java/com/security/securitymall/controller/HomeController.java'
    before = {p: p.read_bytes() for p in (java, controller, mall / '.gitignore')}
    assert b'loginAudit.record(username, request.getRemoteAddr(), authenticated)' in before[controller]
    assert b'HmacSHA256' in before[java]
    patcher(mall)
    assert all(p.read_bytes() == data for p, data in before.items())


def test_patch_mismatch_preserves_existing_local_changes(patcher, mall):
    controller = mall / 'src/main/java/com/security/securitymall/controller/HomeController.java'
    controller.write_bytes(b'local changes must survive\n')
    before = {p: p.read_bytes() for p in mall.rglob('*') if p.is_file() and '.git' not in p.parts}
    with pytest.raises(SystemExit, match='로컬 변경을 보존'):
        patcher(mall)
    after = {p: p.read_bytes() for p in mall.rglob('*') if p.is_file() and '.git' not in p.parts}
    assert before == after

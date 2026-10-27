"""Validate the merged deployment package without touching a mall or ES service."""
import importlib.util
import json
from pathlib import Path
import subprocess
import runpy
import sys
from unittest.mock import Mock, patch

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
        if name.endswith('/HomeController.java'):
            # Signup was outside the original login-only patch's context.
            signup = ('    public String signupForm() { return "signup"; }\r\n\r\n'
                      '    @PostMapping("/signup")\r\n'
                      '    public String signup(User user) {\r\n'
                      '        user.setRole("USER");\r\n'
                      '        userRepository.save(user);\r\n'
                      '        return "redirect:/login";\r\n'
                      '    }\r\n\r\n').encode()
            target.write_bytes(target.read_bytes().replace(
                b'    public String loginForm()', signup + b'    public String loginForm()', 1))
    return repo


def test_patch_applies_and_repeated_application_is_idempotent(patcher, mall):
    patcher(mall)
    java = mall / 'src/main/java/com/security/securitymall/audit/LoginAudit.java'
    controller = mall / 'src/main/java/com/security/securitymall/controller/HomeController.java'
    before = {p: p.read_bytes() for p in (java, controller, mall / '.gitignore')}
    assert b'loginAudit.record(username, request.getRemoteAddr(), authenticated)' in before[controller]
    assert b'HmacSHA256' in before[java]
    assert b'IncorrectResultSizeDataAccessException duplicate' in before[controller]
    assert b'public synchronized String signup(User user)' in before[controller]
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


def test_manual_actions_starts_real_jar_without_creating_login_or_collector(tmp_path):
    mall = tmp_path / 'prepared-mall'
    jar = mall / 'build/libs/mall.jar'
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b'isolated jar placeholder')
    child = Mock(pid=424242)
    child.poll.return_value = None
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch.object(sys, 'argv', ['start-and-connect.py', '--mall', str(mall), '--manual-actions', '--sudo-docker']), \
            patch('os.getuid', return_value=1000), \
            patch('os.kill') as kill, \
            patch('subprocess.run', return_value=Mock(returncode=0)) as run, \
            patch('subprocess.Popen', return_value=child) as start, \
            patch('urllib.request.urlopen', return_value=response) as http:
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(PACKAGE / 'start-and-connect.py'), run_name='__main__')
    assert stopped.value.code == 0
    assert run.call_args_list[0].args[0] == ['sudo', '-n', 'docker', 'info']
    assert len(run.call_args_list) == 2  # Docker readiness and actual bootJar command only.
    assert 'bootJar' in run.call_args_list[1].args[0]
    assert '--server.address=127.0.0.1' in start.call_args.args[0]
    assert str(jar.resolve()) in start.call_args.args[0]
    assert http.call_count == 1
    assert http.call_args.args[0] == 'http://127.0.0.1:8080/login'
    kill.assert_not_called()
    assert not (mall / 'audit/security-audit.jsonl').exists()


def test_connect_help_exposes_custom_mall_and_sudo_without_touching_docker():
    result = subprocess.run([sys.executable, str(PACKAGE / 'connect.py'), '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    assert '--mall' in result.stdout and '--sudo-docker' in result.stdout and '--verify' in result.stdout

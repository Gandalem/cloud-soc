"""First-install only: generate protected local state and a private lab CA on Ubuntu."""

import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import warnings

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/server'))
from server_cli import KoreanParser
from enrollment_pki import repair as prepare_enrollment_pki


class PreparationError(ValueError):
    """A static, user-safe validation message; never include credentials here."""


def validate_host(host):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
        raise PreparationError("DNS 이름 또는 IPv4를 입력하세요. https://, 포트, 경로는 빼세요")
    try:
        ipaddress.IPv4Address(host)
        return "IP:" + host
    except ValueError:
        if all(char in "0123456789." for char in host) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
            raise PreparationError("DNS 이름 또는 IPv4 형식이 올바르지 않습니다")
        return "DNS:" + host


def validate_password(password):
    if not password:
        raise PreparationError("Portal 관리자 비밀번호는 비워 둘 수 없습니다")


def read_admin_password():
    # getpass must not fall back to echoing the password through piped stdin.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        for _ in range(3):
            password = getpass.getpass("Portal 관리자 비밀번호 (입력 내용은 표시되지 않습니다): ")
            try:
                validate_password(password)
            except PreparationError as error:
                print(f"{error}. 다시 입력하세요.", file=sys.stderr)
                continue
            if password == getpass.getpass("비밀번호 확인: "):
                return password
            print("비밀번호가 일치하지 않습니다. 두 값을 다시 입력하세요.", file=sys.stderr)
    raise PreparationError("비밀번호 입력에 3회 실패했습니다. 이번 시도로 서버 상태를 생성하지 않았습니다")


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return f"pbkdf2:sha256:600000${salt}${digest}"


def prepare(host, bind_ip, state, password, *, agent_host=None):
    san = validate_host(host)
    agent_host = agent_host or host
    agent_san = validate_host(agent_host)
    try:
        ipaddress.IPv4Address(bind_ip)
    except ValueError:
        raise PreparationError("--bind-ip에는 서버에 할당된 IPv4를 입력하세요") from None
    if state.is_symlink():
        raise PreparationError("서버 설정 경로가 심볼릭 링크입니다. 원래 경로를 확인하세요")
    state = state.resolve()
    if state.exists():
        raise PreparationError("기존 서버 설정이 있습니다. 덮어쓰지 않았습니다")
    validate_password(password)
    if not shutil.which("openssl"):
        raise PreparationError("인증서를 만들려면 OpenSSL이 필요합니다")
    # A hashing failure should not leave an empty state directory blocking a retry.
    admin_hash = password_hash(password)
    os.umask(0o077)
    state.mkdir(parents=True, mode=0o700)
    for name in ("tls", "private", "secrets", "portal"):
        (state / name).mkdir(mode=0o700)
    credentials = {name: secrets.token_urlsafe(36) for name in ("elastic_password", "kibana_password", "issuer_password", "analyst_password", "monitor_password")}
    for name, value in {**credentials, "admin_hash": admin_hash}.items():
        path = state / "secrets" / name
        path.write_text(value, encoding="utf-8")
        if name in ("elastic_password", "monitor_password"):
            # ES rejects world-readable password files. ES and bootstrap share uid
            # 1000 (but not their primary gid), so owner-only read works for both.
            os.chown(path, 1000, 0)
            path.chmod(0o400)
        else:
            # Only required files mount; the host parent remains root-only (0700).
            path.chmod(0o644)

    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    ca_key, ca_crt = state / "private/ca.key", state / "tls/ca.crt"
    key, csr, cert = state / "tls/server.key", state / "private/server.csr", state / "tls/server.crt"
    openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650", "-subj", "/CN=Cloud SOC Lab CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", ca_key, "-out", ca_crt)
    openssl("req", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", f"/CN={host}", "-keyout", key, "-out", csr)
    extensions = state / "private/server.ext"
    sans = list(dict.fromkeys([san, agent_san, "DNS:elasticsearch", "DNS:localhost", "IP:127.0.0.1"]))
    extensions.write_text(f"subjectAltName={','.join(sans)}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n", encoding="ascii")
    openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-out", cert, "-days", "365", "-sha256", "-extfile", extensions)
    for file in (ca_crt, cert):
        file.chmod(0o644)
    key.chmod(0o640)
    prepare_enrollment_pki(state, f'https://{host}')
    (state / "tls").chmod(0o750)
    # Elasticsearch runs as uid 1000, gid 0; the portal runs as 1000:1000.
    os.chown(state / "portal", 1000, 1000)
    kibana = {
        "server.name": "cloud-soc", "server.host": "0.0.0.0", "server.publicBaseUrl": f"https://{host}:5601",
        "elasticsearch.hosts": ["https://elasticsearch:9200"], "elasticsearch.username": "kibana_system",
        "elasticsearch.password": credentials["kibana_password"], "elasticsearch.ssl.certificateAuthorities": ["/run/certs/ca.crt"],
        "xpack.security.encryptionKey": secrets.token_hex(32), "xpack.encryptedSavedObjects.encryptionKey": secrets.token_hex(32),
        "xpack.reporting.encryptionKey": secrets.token_hex(32), "xpack.security.secureCookies": True,
    }
    (state / "kibana.yml").write_text(json.dumps(kibana, indent=2), encoding="utf-8")
    (state / "kibana.yml").chmod(0o644)
    (state / "compose.env").write_text(f"SOC_PUBLIC_HOST={host}\nSOC_AGENT_ENDPOINT=https://{agent_host}:9200\nSOC_BIND_IP={bind_ip}\nSOC_STATE_DIR={state.as_posix()}\nSOC_ENROLLMENT_ENABLED=1\n", encoding="utf-8")
    print(f"서버 인증서와 보호 설정을 생성했습니다: {state}")
    print(f"공개 CA 파일 SHA256: {hashlib.sha256(ca_crt.read_bytes()).hexdigest()}")
    print("private/와 secrets/는 외부에 전달하지 마세요.")


def main():
    parser = KoreanParser(description="신규 서버 인증서와 자격 증명 생성")
    parser.add_argument("--host", required=True, help="포털 접속 DNS 또는 IPv4")
    parser.add_argument("--agent-host", help="장치가 접속할 DNS 또는 IPv4 (기본: --host)")
    parser.add_argument("--bind-ip", default="127.0.0.1", help="포트를 열 서버 IPv4 (기본: 127.0.0.1)")
    parser.add_argument("--state", type=Path, default=ROOT / "state" / "server")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Ubuntu 중앙 서버에서 sudo로 실행하세요")
    try:
        password = read_admin_password()
        options = {"agent_host": args.agent_host} if args.agent_host else {}
        prepare(args.host, args.bind_ip, args.state, password, **options)
    except PreparationError as error:
        parser.exit(1, f"인증서 준비 실패: {error}. 기존 설정과 부분 설치 상태는 보존됐습니다.\n")
    except getpass.GetPassWarning:
        parser.exit(1, "안전한 비밀번호 입력을 사용할 수 없습니다. 대화형 SSH 터미널에서 직접 입력하세요.\n")
    except EOFError:
        parser.exit(1, "비밀번호 입력이 종료됐습니다. 이번 시도로 서버 상태를 생성하지 않았습니다.\n")
    except KeyboardInterrupt:
        parser.exit(130, "인증서 준비를 중단했습니다. 기존 설정과 부분 설치 상태는 보존됐습니다.\n")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"인증서 준비 실패 ({type(error).__name__}). 부분 설치 상태를 보존했으며 덮어쓰지 않았습니다.\n")


if __name__ == "__main__":
    main()

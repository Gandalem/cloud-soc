"""First-install only: generate protected local state and a private lab CA on Ubuntu."""

import argparse
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


class PreparationError(ValueError):
    """A static, user-safe validation message; never include credentials here."""


def validate_host(host):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
        raise PreparationError("Use a DNS hostname or IPv4 address, without a scheme, port or path")
    try:
        ipaddress.IPv4Address(host)
        return "IP:" + host
    except ValueError:
        if all(char in "0123456789." for char in host) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
            raise PreparationError("Invalid DNS hostname or IPv4 address")
        return "DNS:" + host


def validate_password(password):
    if not password:
        raise PreparationError("Portal administrator password must not be empty")


def read_admin_password():
    # getpass must not fall back to echoing the password through piped stdin.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        for _ in range(3):
            password = getpass.getpass("Portal admin password: ")
            try:
                validate_password(password)
            except PreparationError as error:
                print(f"{error}. Please try again.", file=sys.stderr)
                continue
            if password == getpass.getpass("Confirm password: "):
                return password
            print("Passwords do not match. Please enter both again.", file=sys.stderr)
    raise PreparationError("Password entry failed after 3 attempts; no server state was created by this attempt")


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return f"pbkdf2:sha256:600000${salt}${digest}"


def prepare(host, bind_ip, state, password):
    san = validate_host(host)
    try:
        ipaddress.IPv4Address(bind_ip)
    except ValueError:
        raise PreparationError("Use a valid server-local IPv4 for --bind-ip") from None
    if state.is_symlink():
        raise PreparationError("Server state must not be a symlink; review it manually")
    state = state.resolve()
    if state.exists():
        raise PreparationError("Existing server state is never overwritten; review it manually")
    validate_password(password)
    if not shutil.which("openssl"):
        raise PreparationError("Install OpenSSL before preparing certificates")
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
    extensions.write_text(f"subjectAltName={san},DNS:elasticsearch,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n", encoding="ascii")
    openssl("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-out", cert, "-days", "365", "-sha256", "-extfile", extensions)
    for file in (ca_crt, cert):
        file.chmod(0o644)
    key.chmod(0o640)
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
    (state / "compose.env").write_text(f"SOC_PUBLIC_HOST={host}\nSOC_BIND_IP={bind_ip}\nSOC_STATE_DIR={state.as_posix()}\n", encoding="utf-8")
    print(f"Protected server state created: {state}")
    print(f"CA SHA256: {hashlib.sha256(ca_crt.read_bytes()).hexdigest()}")
    print("No services started. Trust the public CA via an authenticated channel; never distribute private/ or secrets/.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="DNS name or IPv4 reachable by agents")
    parser.add_argument("--bind-ip", default="127.0.0.1", help="Publish ports only on this server-local IP; default is loopback")
    parser.add_argument("--state", type=Path, default=ROOT / "state" / "server")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run with sudo on the Ubuntu central server")
    try:
        password = read_admin_password()
        prepare(args.host, args.bind_ip, args.state, password)
    except PreparationError as error:
        parser.exit(1, f"Preparation failed: {error}. Existing/partial state was not removed.\n")
    except getpass.GetPassWarning:
        parser.exit(1, "Secure password input is unavailable. Use an interactive SSH terminal; do not pipe passwords.\n")
    except EOFError:
        parser.exit(1, "Password input ended. No server state was created by this attempt.\n")
    except KeyboardInterrupt:
        parser.exit(130, "Preparation interrupted. Existing/partial state was not removed.\n")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Preparation failed ({type(error).__name__}). Protected partial state is retained; no automatic overwrite.\n")


if __name__ == "__main__":
    main()

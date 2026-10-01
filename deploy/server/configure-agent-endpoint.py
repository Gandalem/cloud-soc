"""Check a receiver with the existing CA; explicitly update only future bundles."""

import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[2]


class EndpointError(ValueError):
    """Static diagnostics without secrets or upstream response bodies."""


def validate_receiver(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"https://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?/?", value
    ):
        raise EndpointError("Use an HTTPS DNS/IPv4 origin without credentials, path or query")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise EndpointError("Invalid receiver port") from None
    if port == 0:
        raise EndpointError("Invalid receiver port")
    host = parsed.hostname
    if len(host) > 253:
        raise EndpointError("Invalid receiver hostname")
    if all(c in "0123456789." for c in host):
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            raise EndpointError("Invalid receiver IPv4") from None
        if address.is_unspecified or address.is_multicast:
            raise EndpointError("Receiver must identify a concrete server")
    elif any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
             for label in host.split(".")):
        raise EndpointError("Invalid receiver hostname")
    return value.rstrip("/")


def updated_environment(original, endpoint):
    endpoint = validate_receiver(endpoint)
    try:
        lines = original.decode("utf-8").splitlines(keepends=True)
    except UnicodeError:
        raise EndpointError("compose.env must be UTF-8") from None
    keys = set()
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            result.append(line)
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\r\n\x00]*)", line.rstrip("\r\n"))
        if not match or match[1] in keys:
            raise EndpointError("Ambiguous compose.env syntax/duplicate key; state retained")
        keys.add(match[1])
        result.append(f"SOC_AGENT_ENDPOINT={endpoint}\n" if match[1] == "SOC_AGENT_ENDPOINT" else line)
    if not {"SOC_PUBLIC_HOST", "SOC_BIND_IP", "SOC_STATE_DIR"}.issubset(keys):
        raise EndpointError("Incomplete server environment; do not reinitialize existing state")
    if "SOC_AGENT_ENDPOINT" not in keys:
        if result and not result[-1].endswith("\n"):
            result[-1] += "\n"
        result.append(f"SOC_AGENT_ENDPOINT={endpoint}\n")
    return "".join(result).encode("utf-8")


def probe_receiver(endpoint, ca_file):
    parsed = urlsplit(validate_receiver(endpoint))
    context = ssl.create_default_context(cafile=str(ca_file))
    # http.client neither follows redirects nor inherits proxy/credential settings.
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10, context=context)
    try:
        connection.request("GET", "/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        data = response.read(16385)
        if response.status != 401 or len(data) > 16384:
            raise EndpointError("Expected Elasticsearch authentication-required response; endpoint not applied")
        try:
            body = json.loads(data)
        except (ValueError, UnicodeError):
            raise EndpointError("Receiver is not a recognized Elasticsearch endpoint") from None
        if not isinstance(body, dict) or not isinstance(body.get("error"), dict) or body["error"].get("type") != "security_exception":
            raise EndpointError("Receiver is not a recognized Elasticsearch endpoint")
    finally:
        connection.close()


def protected_path(path, *, directory=False):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise EndpointError("Linked server state is not supported; state retained")
    info = path.stat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or (not directory and info.st_nlink != 1):
        raise EndpointError("Expected root-owned private server state; permissions were not changed")
    return info


def configure(state, endpoint, *, apply=False):
    import fcntl

    state = Path(os.path.abspath(state))
    protected_path(state, directory=True)
    endpoint = validate_receiver(endpoint)
    directory_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = None
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        env = state / "compose.env"
        before = protected_path(env)
        with env.open("rb") as handle:
            original = handle.read(65537)
        if len(original) > 65536:
            raise EndpointError("Server environment exceeds the supported size")
        replacement = updated_environment(original, endpoint)
        ca = state / "tls/ca.crt"
        for path in (ca, *ca.parents):
            if path.is_symlink():
                raise EndpointError("Linked CA path is not supported")
        probe_receiver(endpoint, ca)
        if not apply:
            return "CHECK passed: CA/hostname/expiry and Elasticsearch response verified. No writes or credentials sent."
        current = protected_path(env)
        if (before.st_ino, before.st_dev) != (current.st_ino, current.st_dev) or env.read_bytes() != original:
            raise EndpointError("Server environment changed during validation; no replacement attempted")
        if replacement == original:
            return "Receiver already matches. No files or services changed."
        token = uuid.uuid4().hex
        backup = "compose.env.before-agent-" + token
        with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd), "wb") as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        temporary = ".compose.env.agent-" + token
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd), "wb") as handle:
            handle.write(replacement)
            handle.flush()
            os.fsync(handle.fileno())
        current = protected_path(env)
        if (before.st_ino, before.st_dev) != (current.st_ino, current.st_dev) or env.read_bytes() != original:
            raise EndpointError("Server environment changed before commit; backup retained")
        os.replace(temporary, "compose.env", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
        return f"Receiver setting saved. Backup: {backup}. Portal recreation and a NEW bundle are still required; services were not changed."
    finally:
        if temporary:
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--state", type=Path, default=ROOT / "state/server")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Validate without writing server state")
    mode.add_argument("--apply", action="store_true", help="Validate, back up and update only compose.env")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run with sudo on the Ubuntu central server")
    try:
        print(configure(args.state, args.endpoint, apply=args.apply))
    except EndpointError as error:
        parser.exit(1, f"Receiver configuration stopped: {error}. Existing state retained.\n")
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        parser.exit(1, "Receiver configuration stopped: TLS/connectivity, state access or concurrent update failed. No credentials sent; do not regenerate the CA. Review retained state.\n")


if __name__ == "__main__":
    main()

"""Build configuration bundles from an explicit, reviewed file allowlist."""

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import tarfile
from urllib.parse import urlsplit
import uuid
import zipfile

VERSION = "9.5.2"
FILES = {
    "windows": ["install-windows.ps1", "discover-windows.ps1", "download-windows.ps1", "privacy.js", "policy.py"],
    "ubuntu": ["install-ubuntu.sh", "discover-linux.sh", "privacy.js", "policy.py"],
}
NETWORK_FILES = {
    "windows": ["install-network-windows.ps1", "packetbeat.base.json"],
    "ubuntu": ["install-network-ubuntu.sh", "packetbeat.base.json"],
}


def validate_endpoint(value):
    if not isinstance(value, str) or not re.fullmatch(r"https://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?/?", value):
        raise ValueError("HTTPS DNS/IPv4 서버 주소만 허용합니다. 경로·계정·쿼리는 넣지 마세요.")
    parsed = urlsplit(value)
    if parsed.port == 0:
        raise ValueError("서버 포트가 올바르지 않습니다.")
    return value.rstrip("/")


def validate_spec(data, endpoint):
    if not isinstance(data, dict) or set(data) - {"name", "os", "organization", "network", "description"}:
        raise ValueError("지원하지 않는 패키지 설정입니다.")
    for field in ("name", "organization"):
        if not isinstance(data.get(field), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", data[field]):
            raise ValueError(f"{field}: 영문·숫자·밑줄·하이픈 1~64자로 입력하세요.")
    if not isinstance(data.get("os"), str) or data["os"] not in FILES or type(data.get("network")) is not bool:
        raise ValueError("운영체제와 네트워크 수집 여부를 선택하세요.")
    description = data.get("description", "")
    if not isinstance(description, str) or len(description) > 500 or "\x00" in description:
        raise ValueError("설명은 500자 이내로 입력하세요.")
    return {**data, "description": description, "endpoint": validate_endpoint(endpoint), "version": VERSION}


def launch_script(spec):
    endpoint, org = spec["endpoint"], spec["organization"]
    if spec["os"] == "ubuntu":
        text = f'''#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" && pwd)
ARGS=(--endpoint '{endpoint}' --ca "$HERE/ca.crt" --organization '{org}')
DRY=()
DEVICE=
while (($#)); do
    case "$1" in
        --dry-run) DRY=(--dry-run); shift ;;
        --interface) (($# >= 2)) || exit 2; DEVICE=$2; shift 2 ;;
        *) printf 'Unknown option: %s\\n' "$1" >&2; exit 2 ;;
    esac
done
'''
        if spec["network"]:
            text += '''[[ -n $DEVICE ]] || { printf 'Specify --interface eth0 (or any explicitly).\\n' >&2; exit 2; }
bash "$HERE/install-network-ubuntu.sh" "${ARGS[@]}" --interface "$DEVICE" --dry-run >/dev/null
'''
        text += 'bash "$HERE/install-ubuntu.sh" "${ARGS[@]}" "${DRY[@]}"\n'
        if spec["network"]:
            text += 'bash "$HERE/install-network-ubuntu.sh" "${ARGS[@]}" --interface "$DEVICE" "${DRY[@]}"\n'
        return "install.sh", text
    text = f'''#requires -Version 5.1
param([string]$InterfaceGuid, [switch]$DryRun)
$ErrorActionPreference = 'Stop'
$common = @{{ Endpoint = '{endpoint}'; CaPath = (Join-Path $PSScriptRoot 'ca.crt'); Organization = '{org}' }}
'''
    if spec["network"]:
        text += '''if (-not $InterfaceGuid) { throw 'Supply -InterfaceGuid from Get-NetAdapter; approved Npcap must already be running.' }
$networkInstaller = Join-Path $PSScriptRoot 'install-network-windows.ps1'
& $networkInstaller @common -InterfaceGuid $InterfaceGuid -DryRun | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
'''
    text += '''& (Join-Path $PSScriptRoot 'install-windows.ps1') @common -DryRun:$DryRun
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
'''
    if spec["network"]:
        text += '''& $networkInstaller @common -InterfaceGuid $InterfaceGuid -DryRun:$DryRun
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
'''
    return "install.ps1", text


def build_bundle(spec, source, ca):
    names = FILES[spec["os"]] + (NETWORK_FILES[spec["os"]] if spec["network"] else [])
    members = {}
    for name in names:
        data = (source / name).read_bytes()
        members[name] = data.replace(b"\r\n", b"\n") if name.endswith(".sh") else data
    members["ca.crt"] = ca
    launcher, text = launch_script(spec)
    members[launcher] = text.encode("utf-8")
    members["package.json"] = json.dumps(spec, ensure_ascii=False, indent=2).encode("utf-8")
    members["README.txt"] = (
        "Cloud SOC installation configuration bundle.\n"
        f"OS: {spec['os']}; Beats: {VERSION}; endpoint: {spec['endpoint']}\n"
        "This bundle is NOT a signed EXE, an offline Beat distribution or an enrollment token.\n"
        "It contains no API keys, passwords, private keys or collected data.\n"
        "Unpack ALL files. Use an administrator terminal. Follow the portal's commands.\n"
        "Beats are downloaded from Elastic with pinned SHA-512 checks. Internet is required.\n"
        "Use --dry-run (Linux) or -DryRun (Windows) to inspect configuration first.\n"
        "Existing installations are never automatically removed or overwritten.\n"
        "Network collection requires an explicit NIC; Windows also needs approved Npcap.\n"
        "Enter the host key at Filebeat's keystore prompt; enter the separate network key at Packetbeat's prompt.\n"
        "If network installation fails after Filebeat succeeds, Filebeat remains running.\n"
        "Deleting this package does not uninstall an agent or revoke its API keys.\n"
    ).encode("utf-8")
    members["SHA256SUMS"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(members.items())).encode()
    output = io.BytesIO()
    if spec["os"] == "windows":
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        extension = "zip"
    else:
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                archive.addfile(info, io.BytesIO(data))
        extension = "tar.gz"
    return output.getvalue(), f"{spec['name']}-setup.{extension}"


class PackageStore:
    """SQLite holds small bundles atomically; no user-controlled filesystem paths."""

    def __init__(self, root: Path, source: Path, ca: bytes, endpoint: str):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = root / "packages.sqlite3"
        self.source, self.ca, self.endpoint = source, ca, validate_endpoint(endpoint)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS packages (id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT NOT NULL, spec TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL, archive BLOB NOT NULL, UNIQUE(name, os))")
            db.execute("CREATE TABLE IF NOT EXISTS issued_keys (id TEXT PRIMARY KEY, package_id TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.database.chmod(0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def public(row):
        return {**json.loads(row["spec"]), **{key: row[key] for key in ("id", "filename", "sha256", "created_at")}}

    def create(self, data):
        spec = validate_spec(data, self.endpoint)
        archive, filename = build_bundle(spec, self.source, self.ca)
        identifier = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM packages").fetchone()[0] >= 200:
                raise ValueError("패키지는 최대 200개입니다. 사용하지 않는 패키지를 삭제하세요.")
            db.execute("INSERT INTO packages VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
                identifier, spec["name"], spec["os"], json.dumps(spec, ensure_ascii=False), filename,
                hashlib.sha256(archive).hexdigest(), datetime.now(timezone.utc).isoformat(), archive,
            ))
        return self.get(identifier)

    def list(self):
        with self.connect() as db:
            return [self.public(row) for row in db.execute("SELECT id, spec, filename, sha256, created_at FROM packages ORDER BY created_at DESC")]

    def get(self, identifier, *, archive=False):
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise KeyError(identifier)
        with self.connect() as db:
            row = db.execute("SELECT * FROM packages WHERE id = ?", (identifier,)).fetchone()
            if row is None:
                raise KeyError(identifier)
            return (self.public(row), row["archive"]) if archive else self.public(row)

    def delete(self, identifier):
        self.get(identifier)
        with self.connect() as db:
            db.execute("DELETE FROM packages WHERE id = ?", (identifier,))

    def record_keys(self, identifier, keys):
        with self.connect() as db:
            for key in keys:
                db.execute("INSERT INTO issued_keys VALUES (?, ?, ?)", (key["id"], identifier, datetime.now(timezone.utc).isoformat()))

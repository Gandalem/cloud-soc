"""Read-only deployment inventory with an explicit public metadata allowlist."""
import hashlib
import json
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
from urllib.parse import urlsplit

SERVICES = ("portal", "gateway", "normalizer", "detector", "elasticsearch", "kibana")
PUBLIC_ENV = {"SOC_PUBLIC_URL", "SOC_PORTAL_LAN_ORIGIN", "SOC_INTERNAL_ES_URL", "SOC_AGENT_ENDPOINT",
              "SOC_ELASTIC_ENDPOINT", "SOC_PUBLIC_HOST", "SOC_ENROLLMENT_ENABLED"}
VALUE_OPTIONS = {"--es-url", "--start", "--state", "--ca-file", "--api-key-file", "--interval",
                 "--linux-ssh-v2-start", "--max-documents", "--max-active-events", "--lateness-seconds"}
FLAG_OPTIONS = {"--run", "--once", "--early-auth", "--include-cloud", "--include-sequence", "--include-attacks", "--include-patterns", "--isolated-all"}


def public_value(key, value):
    if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 for c in value):
        return "[withheld]"
    if key == "SOC_PUBLIC_HOST":
        return value if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value) else "[withheld]"
    if key == "SOC_ENROLLMENT_ENABLED":
        return value if value in ("0", "1") else "[withheld]"
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme == "https" and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path)
        parsed.port
    except ValueError:
        valid = False
    return value if valid else "[withheld]"


def command_options(command):
    """Never emit the original argv or unknown values that could carry a key."""
    result = {};args = command if isinstance(command, list) else []
    for index, option in enumerate(args):
        if option in FLAG_OPTIONS:
            result[option] = True
        elif option in VALUE_OPTIONS and index + 1 < len(args):
            value = args[index + 1]
            if isinstance(value, str) and not value.startswith("--") and len(value) <= 1024:
                if option == "--es-url":
                    result[option] = public_value("SOC_INTERNAL_ES_URL", value)
                elif option in ("--start", "--linux-ssh-v2-start"):
                    try:
                        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                        valid = stamp.tzinfo is not None and stamp.utcoffset() is not None
                    except ValueError:
                        valid = False
                    result[option] = value if valid else "[withheld]"
                elif option in ("--state", "--ca-file", "--api-key-file"):
                    result[option] = value if (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()) and not any(ord(c) < 32 for c in value) else "[withheld]"
                else:
                    result[option] = value if re.fullmatch(r"[0-9]{1,9}", value) else "[withheld]"
    return result


def service_report(objects):
    result = {}
    for obj in objects:
        configuration = obj.get("Config", {});labels = configuration.get("Labels") or {}
        name = labels.get("com.docker.compose.service")
        if name not in SERVICES:
            continue
        if name in result:
            raise ValueError("Duplicate service identity; deployment requires review")
        env = {}
        for entry in configuration.get("Env") or []:
            key, separator, value = entry.partition("=")
            if separator and key in PUBLIC_ENV:
                env[key] = public_value(key, value)
        state = obj.get("State", {})
        source = {key: value for key, value in labels.items() if key in ("cloud_soc.source", "cloud_soc.base_source", "cloud_soc.portal_patch")
                  and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value)}
        result[name] = {"container_id": obj.get("Id"), "image_id": obj.get("Image"), "state": state.get("Status"),
                        "started_at": state.get("StartedAt"), "restart_count": obj.get("RestartCount"),
                        "public_environment": env, "source_labels": source,
                        "options": command_options(configuration.get("Cmd")) if name in ("normalizer", "detector") else {},
                        "networks": sorted((obj.get("NetworkSettings", {}).get("Networks") or {}).keys())}
    return result


def run_json(args):
    return json.loads(subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=30))


def inventory(workspace, project="cloud-soc-central", *, inspect=run_json):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", project):
        raise ValueError("Invalid project identity")
    names = [project + "-" + service + "-1" for service in SERVICES]
    objects = inspect(["docker", "inspect", *names])
    if any((obj.get("Config", {}).get("Labels") or {}).get("com.docker.compose.project") != project for obj in objects):
        raise ValueError("Unexpected deployment project; no inferred service identity")
    services = service_report(objects)
    workspace = Path(workspace)
    files = {}
    configs = {path for obj in objects for path in (obj.get("Config", {}).get("Labels") or {}).get("com.docker.compose.project.config_files", "").split(",") if path}
    for name in sorted(configs):
        path = Path(name)
        if path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()) or not path.is_file():
            raise ValueError("Active configuration path requires review")
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("Active configuration exceeds audit limit")
        files[str(path.relative_to(workspace))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"read_only": True, "services": services, "missing_services": [name for name in SERVICES if name not in services],
            "active_config_sha256": files, "source_equivalence": "not_verified_by_image_label",
            "notes": ["labels_and_checkout_are_not_file_equivalence", "no_credentials_or_original_argv_disclosed"]}

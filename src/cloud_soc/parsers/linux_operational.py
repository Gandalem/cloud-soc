"""Selected Linux operational metadata; never return command arguments or bodies."""
import json
import re
from ipaddress import ip_address
from pathlib import PurePosixPath

from cloud_soc.portal.log_contract import field
from cloud_soc.privacy import display, REDACTED

VERSION = "linux-operational-v1"
PREFIX = re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<app>[A-Za-z0-9_.@-]+)(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<body>.*)$")
SUDO = re.compile(r"^(?P<actor>[A-Za-z0-9_.@-]{1,128})\s*:\s*TTY=[^;\n]{1,128}\s*;\s*PWD=[^;\n]{1,1024}\s*;\s*USER=(?P<target>[A-Za-z0-9_.@-]{1,128})\s*;\s*(?:GROUP=[^;\n]{1,128}\s*;\s*)?(?:TSID=[^;\n]{1,128}\s*;\s*)?COMMAND=.+$")
SERVICE = re.compile(r"^(Starting|Started|Stopping|Stopped|Failed to start)\s+.{1,1024}$")
ACCESS = re.compile(r'^(?P<ip>\S{1,253})\s+\S+\s+\S+\s+\[(?P<time>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^"\r\n]{1,2048} HTTP/\d(?:\.\d)?"\s+(?P<status>[1-5]\d{2})\s+(?:\d+|-)(?:(?:\s+"[^"\r\n]{0,2048}"\s+"[^"\r\n]{0,2048}")|(?P<extra>\s+[A-Za-z0-9_.-]{1,128}\s+[A-Za-z0-9_.-]{1,128}))?$')
OBSERVED = {"gnome-shell": ("process", "desktop_log_observed"),
    "chrome": ("process", "desktop_log_observed"),
    "dbus-daemon": ("process", "message_bus_log_observed"),
    "chatgpt-desktop-linux_chatgpt-desktop-linux.desktop": ("process", "desktop_log_observed"),
    "google-chrome.desktop": ("process", "desktop_log_observed"),
    "NetworkManager": ("network", "network_service_log_observed"),
    "avahi-daemon": ("network", "network_service_log_observed"),
    "systemd-udevd": ("configuration", "device_service_log_observed"),
    "kernel": ("configuration", "kernel_log_observed")}


def parse_linux_operational(source):
    if field(source, "labels.log_source") not in {"linux_file", "linux_journald", "linux_auth"}:
        return None
    message = source.get("message")
    if not isinstance(message, str) or not message or len(message) > 8192 or "\n" in message or "\r" in message:
        return None
    path = field(source, "log.file.path")
    access = ACCESS.fullmatch(message) if isinstance(path, str) and PurePosixPath(path).name in {"access.log", "access_log"} else None
    if access:
        try:
            address = str(ip_address(access["ip"]))
        except ValueError:
            # A hostname is not an IP address; omit it from source.ip.
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", access["ip"]):
                return None
            address = None
        limitations = ["url_headers_and_body_excluded", "not_a_detection"]
        if address is None:
            limitations.append("client_hostname_not_stored")
        if access["extra"]:
            limitations.append("trailing_fields_uninterpreted")
        code = int(access["status"])
        return {"adapter": "linux_operational_v1", "status": "partial" if address is None or access["extra"] else "recognized",
                "access_time": access["time"], "fields": {"category": "web", "action": "http_access",
                    "outcome": "failure" if code >= 400 else "success" if code < 300 else "unknown",
                    "source_ip": address, "http_method": access["method"], "http_status": code},
                "missing": ["source_ip"] if address is None else [], "limitations": limitations}
    prefix = PREFIX.fullmatch(message)
    if prefix:
        app, body = prefix["app"], prefix["body"]
    elif field(source, "labels.log_source") == "linux_journald":
        app = (field(source, "log.syslog.appname") or field(source, "process.name")
               or field(source, "journald.syslog.identifier"))
        body = message
    else:
        app, body = None, message
    if app is None:
        # No actor/action inference. The collector timestamp is an observation time.
        if (field(source, "labels.log_source") != "linux_journald"
                and path not in {"/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"}):
            return None
        return {"adapter": "linux_unclassified_v1", "status": "partial",
                "fields": {"category": None, "action": "host_log_observed", "outcome": "unknown"},
                "missing": ["source_program", "source_event_time"],
                "limitations": ["metadata_only", "source_event_time_unknown", "message_body_excluded", "not_a_detection"]}
    values = {"category": "process", "outcome": "unknown"}
    if app == "sudo":
        match = SUDO.fullmatch(body)
        if not match:
            session = re.match(r"^pam_[A-Za-z0-9_]+\(sudo:session\): session (opened|closed)\b", body)
            failure = re.match(r"^pam_[A-Za-z0-9_]+\(sudo:auth\): authentication failure(?:;|$)", body)
            if session:
                values.update(category="authentication", action="sudo_session_" + session[1])
            elif failure:
                values.update(category="authentication", action="sudo_authentication_failed", outcome="failure")
            else:
                values.update(action="sudo_log_observed", daemon="sudo")
        else:
            actor, target = display(match["actor"]), display(match["target"])
            if actor in (None, REDACTED) or target in (None, REDACTED):
                return None
            values.update(action="sudo_command_logged", actor=actor, target_user=target)
    elif app == "systemd":
        match = SERVICE.fullmatch(body)
        if not match:
            values.update(action="systemd_log_observed", category="configuration")
        else:
            actions = {"Starting": "service_start_requested", "Started": "service_started",
                       "Stopping": "service_stop_requested", "Stopped": "service_stopped",
                       "Failed to start": "service_start_failed"}
            values.update(action=actions[match[1]], category="configuration",
                          outcome="failure" if match[1] == "Failed to start" else "unknown")
    elif app in {"dockerd", "containerd"}:
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            match = re.fullmatch(r'time="[^"\n]{1,64}"\s+level=(debug|info|warning|warn|error|fatal)\s+msg="[^\n]{0,4096}"(?:\s+[^\n]{0,2048})?', body)
            if not match:
                if body.startswith(("time=", "{")):
                    return None
                data = {"level": "unknown"}
            else:
                data = {"level": match[1]}
        if not isinstance(data, dict) or data.get("level") not in {"debug", "info", "warning", "warn", "error", "fatal", "unknown"}:
            return None
        values.update(action="container_runtime_log_observed", daemon=app, log_level=data["level"])
    elif app in OBSERVED:
        category, action = OBSERVED[app]
        values.update(category=category, action=action, daemon=app)
    else:
        return None
    result = {"adapter": "linux_operational_v1", "status": "recognized", "fields": values,
              "missing": [], "limitations": ["message_body_and_arguments_excluded", "not_a_detection"]}
    if prefix:
        result["time_text"] = prefix["time"]
    return result

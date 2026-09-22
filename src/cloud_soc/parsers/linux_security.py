"""Bounded Linux security adapters for future ingestion-worker integration.

No files, sensors or services are accessed. Audit callers must supply one host's
records with the same full audit ID; PID alone never groups records. Output is
selected, privacy-filtered metadata, never raw text or command arguments.
"""

import re
import shlex

from cloud_soc.parsers.linux_auth import parse_linux_auth_line
from cloud_soc.privacy import display, REDACTED

AUDIT_HEADER = re.compile(r"^type=(SYSCALL|PATH|CWD|EXECVE|PROCTITLE|EOE) msg=audit\((\d{10}(?:\.\d{1,9})?:\d{1,20})\):\s*(.*)$")
# Linux x86_64 syscall numbers only. Unknown architectures are not guessed.
X86_64_SYSCALLS = {
    "0": "read_attempt", "1": "write_attempt", "2": "open_attempt",
    "59": "process_execution_attempt", "87": "unlink_attempt",
    "90": "chmod_attempt", "91": "fchmod_attempt", "257": "open_attempt",
    "263": "unlink_attempt", "268": "chmod_attempt", "322": "process_execution_attempt",
}


def parse_linux_ssh(line):
    """Legacy RFC3164 sshd format, with no year/timezone inference here."""
    if not isinstance(line, str) or len(line) > 8192:
        return None
    try:
        parsed = parse_linux_auth_line(line)
    except (ValueError, OverflowError):
        return None
    if not parsed or not 0 <= parsed["source_port"] <= 65535 or not 0 <= parsed["process_id"] < 2**32:
        return None
    return {"adapter": "linux_ssh_v1", "category": "authentication", "action": parsed["action"],
            "outcome": parsed["outcome"], "target_user": display(parsed["username"]),
            "source_ip": parsed["source_ip"], "source_port": parsed["source_port"],
            "process_pid": parsed["process_id"], "source_host": display(parsed["host"]),
            "time_text": parsed["timestamp_raw"], "time_basis": "year_timezone_required"}


def _fields(body):
    values = {}
    for part in shlex.split(body, posix=True):
        if "=" not in part:
            raise ValueError("Unsupported audit field")
        key, value = part.split("=", 1)
        if key in values:
            raise ValueError("Duplicate audit field")
        values[key] = value
    return values


def _decimal(value):
    return int(value) if isinstance(value, str) and re.fullmatch(r"\d{1,10}", value) else None


def parse_linux_audit(records):
    """Parse a bounded group of {host_id, organization, line} records.

    Grouping across ES pages, provenance retention, time conversion and writing
    normalized documents belong to the worker, not this pure decoder.
    """
    if not isinstance(records, list) or not 1 <= len(records) <= 64:
        return None
    scope, event_id, syscall, paths = None, None, None, {}
    total = 0
    try:
        for record in records:
            if not isinstance(record, dict):
                return None
            identity = (record.get("organization"), record.get("host_id"))
            if any(not isinstance(item, str) or not item or len(item) > 512 for item in identity):
                return None
            line = record.get("line")
            if not isinstance(line, str) or len(line) > 8192:
                return None
            total += len(line.encode("utf-8"))
            if total > 128 * 1024:
                return None
            match = AUDIT_HEADER.fullmatch(line)
            if not match or (scope is not None and (scope != identity or event_id != match[2])):
                return None
            scope, event_id = identity, match[2]
            kind = match[1]
            # Arguments, working directories and encoded process titles are never parsed or returned.
            if kind not in {"SYSCALL", "PATH"}:
                continue
            values = _fields(match[3])
            if kind == "SYSCALL":
                if syscall is not None:
                    return None
                syscall = values
            else:
                item = _decimal(values.get("item"))
                if item is None or item >= 64 or item in paths:
                    return None
                # Do not decode unquoted hex paths, resolve relative paths, or guess target identity.
                name = values.get("name")
                paths[item] = {"path": display(name) if isinstance(name, str) and name.startswith("/") and len(name) <= 512 else None,
                               "name_type": values.get("nametype") if values.get("nametype") in {"NORMAL", "PARENT", "CREATE", "DELETE", "UNKNOWN"} else None}
    except (ValueError, UnicodeError):
        return None
    if syscall is None:
        return None
    action = X86_64_SYSCALLS.get(syscall.get("syscall")) if syscall.get("arch") == "c000003e" else None
    count = _decimal(syscall.get("items"))
    complete_paths = count is not None and count <= 64 and set(paths) == set(range(count))
    usable_paths = complete_paths and all(item["path"] not in (None, REDACTED) for item in paths.values())
    auid = _decimal(syscall.get("auid"))
    executable = syscall.get("exe")
    executable = display(executable) if isinstance(executable, str) and executable.startswith("/") and len(executable) <= 512 else None
    required_present = all(_decimal(syscall.get(key)) is not None for key in ("pid", "ppid", "uid", "euid"))
    required_present = required_present and executable not in (None, REDACTED) and syscall.get("success") in ("yes", "no")
    return {"adapter": "linux_audit_v1", "event_id": event_id,
            "organization": display(scope[0]), "host_id": display(scope[1]),
            "status": "recognized" if action and usable_paths and required_present else "partial",
            "action": action or "unsupported_syscall", "arch": display(syscall.get("arch")),
            "syscall": _decimal(syscall.get("syscall")),
            "outcome": {"yes": "success", "no": "failure"}.get(syscall.get("success"), "unknown"),
            "login_uid": None if auid == 4294967295 else auid,
            "effective_uid": _decimal(syscall.get("euid")), "uid": _decimal(syscall.get("uid")),
            "process_pid": _decimal(syscall.get("pid")), "parent_pid": _decimal(syscall.get("ppid")),
            "process_path": executable,
            "paths": [paths[item] for item in sorted(paths)], "paths_complete": complete_paths,
            "process_identity": None, "file_read_proven": False}

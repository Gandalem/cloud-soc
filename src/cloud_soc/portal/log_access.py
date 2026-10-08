"""Server-owned log principals. These accounts grant no ES or package authority."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os
import re
import secrets
import stat

from werkzeug.security import check_password_hash
from cloud_soc.privacy import sensitive

POLICY_VERSION = "protected-fields-v1"
PURPOSES = frozenset({"investigation", "receipt_validation", "support"})


@dataclass(frozen=True)
class LogPrincipal:
    username: str
    role: str
    organizations: tuple | None
    source_organizations: tuple

    @property
    def cursor_principal(self):
        scope = json.dumps([self.username, self.role, self.organizations], separators=(",", ":"))
        return hashlib.sha256(scope.encode()).hexdigest()

    def can_read_source(self, organization):
        return isinstance(organization, str) and organization in self.source_organizations


def read_policy(path):
    """An optional, read-only secret mount, not browser-supplied role claims."""
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 32768:
        raise ValueError("Invalid log access policy file.")
    if os.name != "nt" and stat.S_IMODE(p.stat().st_mode) & 0o007:
        raise ValueError("Log access policy file must not be world-readable.")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Cannot read log access policy file.") from None


class LogAccessPolicy:
    def __init__(self, admin_user, admin_hash, value=None):
        self.admin_user, self.admin_hash = admin_user, admin_hash
        self.enabled, self.admin_source_organizations, self.users = False, (), {}
        if value is None:
            return
        try:
            if (not isinstance(value, dict) or set(value) != {
                    "version", "protected_source_enabled", "admin_source_organizations", "users"}
                    or type(value["version"]) is not int or value["version"] != 1
                    or type(value["protected_source_enabled"]) is not bool
                    or not isinstance(value["users"], list) or len(value["users"]) > 20):
                raise ValueError()
            self.enabled = value["protected_source_enabled"]
            self.admin_source_organizations = self.orgs(value["admin_source_organizations"], allow_empty=True)
            for item in value["users"]:
                if not isinstance(item, dict) or set(item) != {"username", "password_hash", "role", "organizations"}:
                    raise ValueError()
                name, hashed, role = item["username"], item["password_hash"], item["role"]
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)
                        or sensitive(name) or name == admin_user or name in self.users
                        or role not in {"viewer", "investigator"}
                        or not isinstance(hashed, str) or not 50 <= len(hashed) <= 512
                        or not re.fullmatch(r"(?:scrypt:[0-9]+:[0-9]+:[0-9]+\$[A-Za-z0-9]{8,64}\$[0-9a-f]{128}|pbkdf2:sha256:[0-9]+\$[A-Za-z0-9]{8,64}\$[0-9a-f]{64})", hashed)):
                    raise ValueError()
                # Reject malformed hash algorithms/encodings at startup.
                check_password_hash(hashed, "synthetic-format-check")
                self.users[name] = (hashed, role, self.orgs(item["organizations"]))
        except (KeyError, TypeError, ValueError):
            raise ValueError("Invalid log access policy; roles remain unavailable.") from None

    @staticmethod
    def orgs(value, *, allow_empty=False):
        if (not isinstance(value, list) or len(value) > 20 or (not value and not allow_empty)
                or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", v)
                       or sensitive(v) for v in value) or len(set(value)) != len(value)):
            raise ValueError()
        return tuple(sorted(value))

    def authenticate(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
            return None
        if secrets.compare_digest(username.encode(), self.admin_user.encode()):
            if check_password_hash(self.admin_hash, password):
                return LogPrincipal(username, "admin", None,
                                    self.admin_source_organizations if self.enabled else ())
            return None
        user = self.users.get(username)
        if user and check_password_hash(user[0], password):
            return LogPrincipal(username, user[1], user[2],
                                user[2] if self.enabled and user[1] == "investigator" else ())
        return None

    def capabilities(self, principal):
        return {"policy_version": POLICY_VERSION, "role": principal.role,
                "metadata_organizations": list(principal.organizations) if principal.organizations is not None else None,
                "protected_source_organizations": list(principal.source_organizations),
                "protected_source": bool(principal.source_organizations), "unfiltered_source": False, "export": False}

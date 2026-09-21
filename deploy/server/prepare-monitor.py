"""Add only the monitor secret to an existing protected central-server state."""

import argparse
import os
from pathlib import Path
import secrets
import stat

ROOT = Path(__file__).resolve().parents[2]


def prepare_monitor(state):
    for directory in (state, state / "secrets"):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Expected a root-owned private server state directory; no permissions changed")
    marker = (state / "compose.env").lstat()
    if not stat.S_ISREG(marker.st_mode):
        raise ValueError("Expected existing regular compose.env; do not initialize a new server")
    target = state / "secrets/monitor_password"
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        info = target.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o400 or not 32 <= info.st_size <= 256):
            raise ValueError("Existing monitor secret needs manual review; not overwritten") from None
        return False
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(36))
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 1000, 0)
            os.fchmod(stream.fileno(), 0o400)
    except Exception:
        # Retain protected partial state for inspection; never regenerate on failure.
        raise RuntimeError("Monitor secret preparation failed; inspect protected partial state") from None
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=ROOT / "state/server")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Run with sudo on the Ubuntu central server")
    try:
        created = prepare_monitor(args.state.absolute())
    except (OSError, ValueError, RuntimeError):
        parser.exit(1, "Monitor preparation failed; inspect state ownership, permissions and partial files. Nothing was deleted or overwritten.\n")
    print("Monitor secret created." if created else "Existing monitor secret retained.")
    print("Existing passwords, CA, data and services unchanged. Run the documented bootstrap and portal update next.")


if __name__ == "__main__":
    main()

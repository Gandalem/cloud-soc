#!/usr/bin/env python3
"""Add separate real business source files without changing accounts/DB/keys."""
import argparse
import hashlib
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mall', type=Path, default=Path.home() / 'security-mall')
    a = parser.parse_args()
    mall = a.mall.expanduser().resolve()
    source = Path(__file__).resolve().parent / 'mall-business'
    target = mall / 'src/main/java'
    if os.getuid() == 0 or not (mall / 'build.gradle').is_file():
        raise ValueError('Use the existing user and mall source path')
    if not (mall / 'audit/account-hmac.key').is_file():
        raise ValueError('Existing login audit key required; do not replace it')
    copies = [(path, target / path.relative_to(source)) for path in source.rglob('*.java')]
    # Prepare the whole file list before writing; refuse conflicting local files.
    for src, dst in copies:
        if dst.is_symlink() or (dst.exists() and dst.read_bytes() != src.read_bytes()):
            raise ValueError('Existing business source differs; preserved')
        parent = dst.parent
        while parent != mall:
            if parent.is_symlink():
                raise ValueError('Symlink source path refused')
            parent = parent.parent
    for src, dst in copies:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            with dst.open('xb') as out:
                out.write(src.read_bytes())
    print('Business sources installed; application not rebuilt/restarted; existing DB/accounts/key retained')
    print('Source set: ' + hashlib.sha256(b''.join(src.read_bytes() for src, _ in copies)).hexdigest()[:16])


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Business source install stopped: ' + type(error).__name__ + '; existing material preserved')
        raise SystemExit(1)

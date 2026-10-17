"""Bounded, one-shot private-file extraction; never a daemon or raw log forwarder."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from cloud_soc.parsers.security_mall_edge import (
    EdgeError, BOUNDARY, build_manifest, parse_access, parse_native, envelope,
)

MAX_FILE = 16 * 1024 * 1024


def protected_read(path):
    """No symlinks, special files, cross-user files or group/world readable input."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise EdgeError('edge_file_invalid')
        if os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise EdgeError('edge_file_permission')
        with os.fdopen(fd, 'rb') as source:
            fd = None
            value = source.read(info.st_size)
        if len(value) != info.st_size:
            raise EdgeError('edge_file_changed')
        return value.decode('utf-8')
    except EdgeError:
        raise
    except (OSError, UnicodeError):
        raise EdgeError('edge_file_read_failed') from None
    finally:
        if fd is not None:
            os.close(fd)


def extract(access_texts, native_texts, manifest, organization, host):
    events, rejected = [], Counter()
    for text in access_texts:
        for line in text.splitlines(keepends=True):
            try:
                events.append(envelope(parse_access(line), organization, host))
            except EdgeError as error:
                rejected[error.reason] += 1
    for text in native_texts:
        # Never join a partial record from one file with another rotated file.
        pending = []
        for line in text.splitlines(keepends=True):
            marker = BOUNDARY.fullmatch(line.rstrip('\r\n'))
            if marker and marker[2] == 'A' and pending:
                rejected['edge_native_incomplete'] += 1
                pending = []
            if not pending and not line.strip():
                continue
            pending.append(line)
            if sum(map(len, pending)) > 1024 * 1024:
                raise EdgeError('edge_native_too_large')
            if marker and marker[2] == 'Z':
                try:
                    body = parse_native(''.join(pending), manifest)
                    events.append(envelope(body, organization, host))
                except EdgeError as error:
                    rejected[error.reason] += 1
                pending = []
        if pending:
            rejected['edge_native_incomplete'] += 1
    return events, dict(rejected)


def write_private(path, events):
    parent = Path(path).parent
    if parent.is_symlink() or not parent.is_dir():
        raise EdgeError('edge_output_directory')
    if os.name == 'posix' and (parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077):
        raise EdgeError('edge_output_permission')
    if Path(path).exists():
        raise EdgeError('edge_output_exists')
    fd, name = tempfile.mkstemp(prefix='.project-', dir=parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as output:
            for event in events:
                output.write(json.dumps(event, separators=(',', ':')) + '\n')
            output.flush()
            os.fsync(output.fileno())
        # Exclusive link avoids replacing an existing collector spool.
        os.link(name, path)
    except OSError:
        raise EdgeError('edge_output_failed') from None
    finally:
        os.unlink(name)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Private mall edge allowlist extraction')
    parser.add_argument('--access', action='append', default=[])
    parser.add_argument('--native', action='append', default=[])
    parser.add_argument('--crs-directory', required=True)
    parser.add_argument('--allow-lab-diagnostic-10002', action='store_true')
    parser.add_argument('--organization', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        # CRS sources are trusted configuration, not private request logs.
        files = sorted(Path(args.crs_directory).glob('*.conf'))
        if not files:
            raise EdgeError('edge_manifest_missing')
        manifest = build_manifest([p.read_text() for p in files],
                                  include_lab_diagnostic=args.allow_lab_diagnostic_10002)
        events, rejected = extract([protected_read(p) for p in args.access],
                                  [protected_read(p) for p in args.native], manifest,
                                  args.organization, args.host)
        write_private(args.output, events)
        print(json.dumps({'accepted': len(events), 'streams': dict(Counter(
            e['security_mall_edge']['stream'] for e in events)), 'rejected': rejected}))
        return 0
    except (EdgeError, OSError, UnicodeError):
        print('{"status":"failed","reason":"edge_projection_failed"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

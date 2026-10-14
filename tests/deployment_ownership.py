"""Scoped test doubles for coordinator tests, never loaded by production code."""
import os
from pathlib import Path
import stat
from unittest.mock import Mock


class DeploymentOS:
    # Exercise POSIX ownership branches on both CI platforms without changing global os.name.
    name = 'posix'

    def __init__(self, chown):
        self.chown = chown

    def __getattr__(self, name):
        return getattr(os, name)


class OwnershipCalls:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.chown = Mock(side_effect=self.record)

    def record(self, path, uid, gid):
        path = Path(path)
        assert path.exists() and not path.is_symlink()
        assert path.resolve().is_relative_to(self.root)
        assert (uid, gid) == (1000, 1000)
        if os.name == 'posix':
            assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)

    def expect(self, *paths):
        for path in paths:
            self.chown.assert_any_call(Path(path), 1000, 1000)

    def expect_atomic_contract(self, parent):
        calls = [Path(c.args[0]) for c in self.chown.call_args_list]
        assert any(p.parent == parent and p.name.startswith('contract.json.') and p.suffix == '.next'
                   for p in calls)

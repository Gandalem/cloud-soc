#!/bin/sh
# Local, explicit removal only; never pipe a downloaded script into a shell.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
exec python3 "$ROOT/deploy/server/uninstall.py" "$@"

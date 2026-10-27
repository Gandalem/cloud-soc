#!/usr/bin/env bash
set -euo pipefail
SCRIPT=$(readlink -f -- "${BASH_SOURCE[0]}")
if (( EUID != 0 )); then
  exec sudo -- bash "$SCRIPT"
fi

REPO='/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs/cloud-soc'
STATE='/home/lyn/cloud-soc/state/server'
EXPECTED_TREE='7a60c68a496da362c27992c13336f6dd70890676'
IMAGE='cloud-soc-runtime:ssh-96d2ab8'

cd "$REPO"
test "$(git -c safe.directory="$REPO" rev-parse 'HEAD^{tree}')" = "$EXPECTED_TREE"
git -c safe.directory="$REPO" diff --quiet HEAD --
test -f "$STATE/compose.env"
test -d "$STATE/runtime"
docker info >/dev/null

printf '%s\n' 'Building the published SSH intake and stopped SQLite backup fix (96d2ab8). Existing runtime state is preserved.'
docker build --pull=false -f deploy/server/Dockerfile -t "$IMAGE" .

PLAN="$STATE/runtime/ssh-fix-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 deploy/server/manage.py plan --workspace "$REPO" --state "$STATE" --image "$IMAGE" --plan "$PLAN"

python3 - "$PLAN" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    plan = json.load(source)
if plan.get('fresh') is not False or not plan.get('resources', {}).get('ok'):
    raise SystemExit('Existing-runtime upgrade required; no apply performed.')
print('Existing runtime confirmed; applying the protected upgrade plan.')
PY

python3 deploy/server/manage.py apply --plan "$PLAN"
python3 deploy/server/manage.py verify --workspace "$REPO" --state "$STATE" --startup-only

python3 /home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs/apply-file-timezone.py

printf '%s\n' 'Application deployment complete. Checking detector progress below; startup is not proof of backlog completion.'
for worker in detector detector-priority detector-additional; do
  printf '\n%s\n' "$worker"
  docker logs --since 3m --tail 8 "cloud-soc-central-$worker-1"
done
printf '%s\n' 'Keep existing checkpoint databases. Refresh Cloud SOC analysis status to observe catch-up.'

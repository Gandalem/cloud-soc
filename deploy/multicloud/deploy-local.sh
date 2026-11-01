#!/usr/bin/env bash
# Run from a normal Ubuntu terminal; does not change sandbox or container protections.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this deployment with sudo in the normal Ubuntu terminal.' >&2
  exit 1
fi
if [ "$#" -ne 4 ]; then
  echo 'Usage: sudo bash deploy-local.sh STATE SOURCE_CONFIG AWS_ENV NAVER_ENV' >&2
  exit 2
fi
release_workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
central_state="$(realpath -- "$1")"
source_config="$(realpath -- "$2")"
aws_credentials="$(realpath -- "$3")"
naver_credentials="$(realpath -- "$4")"
cd -- "$release_workspace"
for required_file in "$central_state/runtime/site.json" "$central_state/compose.env" "$source_config" "$aws_credentials" "$naver_credentials"; do
  if [ ! -f "$required_file" ]; then
    echo 'A required existing configuration or credential file is missing; no deployment performed.' >&2
    exit 1
  fi
done
# Preserve operator scope/start values. Never replace a different existing config.
python3 - "$source_config" "$release_workspace/config/multicloud.json" <<'PY'
import json, os, sys
from pathlib import Path
source, target = map(Path, sys.argv[1:])
value = json.loads(source.read_text())
if target.is_symlink():
    raise SystemExit('Refusing a symlink source config')
if target.exists():
    if json.loads(target.read_text()) != value:
        raise SystemExit('Source configurations differ; preserved both files; resolve scope explicitly')
else:
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
    os.chown(target, source.stat().st_uid, source.stat().st_gid)
PY
feature_state="$central_state/multicloud"
if [ ! -d "$feature_state" ]; then
  echo 'Existing multicloud state is required; this is an upgrade, not initial setup.' >&2
  exit 1
fi
release_record="$(mktemp -d "$feature_state/integrated-release-20261101-XXXXXX")"
chmod 700 "$release_record"
for name in aws.compose.json naver.compose.json aws-config.json naver-config.json collectors.json; do
  if [ -f "$feature_state/$name" ]; then
    cp --preserve=mode,ownership,timestamps -- "$feature_state/$name" "$release_record/$name"
  fi
done
stage='image-build'
trap 'echo "Deployment stopped at stage=$stage. Preserved release record: $release_record" >&2' ERR
python3 deploy/server/manage.py build --workspace "$release_workspace" --image cloud-soc-runtime:integrated-20261101
docker build -f deploy/multicloud/Dockerfile -t cloud-soc-multicloud:integrated-20261101 .
stage='central-plan'
python3 deploy/server/manage.py plan --workspace "$release_workspace" --state "$central_state" \
  --image cloud-soc-runtime:integrated-20261101 --plan "$release_record/central-plan.json"
stage='central-apply'
python3 deploy/server/manage.py apply --plan "$release_record/central-plan.json"
stage='aws-prepare'
python3 deploy/multicloud/manage.py prepare --provider aws --workspace "$release_workspace" \
  --state "$central_state" --source aws-audit-oregon --env "$aws_credentials" \
  --image cloud-soc-multicloud:integrated-20261101
stage='naver-prepare'
python3 deploy/multicloud/manage.py prepare --provider naver --workspace "$release_workspace" \
  --state "$central_state" --source naver-audit --env "$naver_credentials" \
  --image cloud-soc-multicloud:integrated-20261101
stage='collector-recreate'
python3 deploy/multicloud/manage.py recreate --provider aws --state "$central_state"
python3 deploy/multicloud/manage.py recreate --provider naver --state "$central_state"
stage='central-startup'
python3 deploy/server/manage.py verify --state "$central_state" --startup-only
printf 'Deployment commands completed. Real log receipt remains a separate result. Release record: %s\n' "$release_record"

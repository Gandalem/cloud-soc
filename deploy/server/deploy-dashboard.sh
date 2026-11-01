#!/usr/bin/env bash
# Dashboard release using the existing backup/preflight/rollback-aware manager.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo '관리자 권한이 필요합니다. 일반 터미널에서 sudo bash로 실행하세요.' >&2
  exit 1
fi
workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
expected_state='/home/lyn/cloud-soc/state/server'
# Pin to the local Docker daemon; never inherit a remote Docker target.
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
unset COMPOSE_FILE COMPOSE_PROJECT_NAME
portal_ids="$(docker --host unix:///var/run/docker.sock ps -q --filter label=com.docker.compose.project=cloud-soc-central --filter label=com.docker.compose.service=portal)"
if [ -z "$portal_ids" ] || [ "$(printf '%s\n' "$portal_ids" | wc -l)" -ne 1 ]; then
  echo '이 PC에서 cloud-soc-central Portal 1개를 확인할 수 없습니다. 운영 서버 위치를 확인하세요. 적용하지 않았습니다.' >&2
  exit 1
fi
mount_source="$(docker --host unix:///var/run/docker.sock inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$portal_ids")"
if [ "$(realpath -- "$mount_source")" != "$(realpath -- "$expected_state/portal")" ]; then
  echo '실행 Portal의 데이터 경로가 확인한 운영 경로와 다릅니다. 적용하지 않았습니다.' >&2
  exit 1
fi
for required in "$expected_state/compose.env" "$expected_state/runtime/current.json" "$expected_state/runtime/site.json"; do
  if [ ! -f "$required" ]; then
    echo '기존 운영 배포 기록이 없습니다. 신규 설치를 실행하지 않고 중단합니다.' >&2
    exit 1
  fi
done
release_dir="$(mktemp -d "$expected_state/dashboard-release-XXXXXXXX")"
chmod 700 "$release_dir"
image="cloud-soc-runtime:dashboard-$(date -u +%Y%m%d%H%M%S)"
stage='build'
trap 'echo "배포 중단 단계: $stage / 기록: $release_dir. 성공으로 간주하지 마세요. 기존 관리자의 복구 기록을 확인하세요." >&2' ERR
cd -- "$workspace"
echo "운영 경로: $expected_state"
echo "배포 기록: $release_dir"
python3 deploy/server/manage.py build --workspace "$workspace" --image "$image"
stage='plan'
python3 deploy/server/manage.py plan --workspace "$workspace" --state "$expected_state" --image "$image" --plan "$release_dir/plan.json"
stage='apply'
# Existing manager rechecks the plan, preserves state/keys and owns recovery.
python3 deploy/server/manage.py apply --state "$expected_state" --plan "$release_dir/plan.json"
stage='startup-verify'
python3 deploy/server/manage.py verify --state "$expected_state" --startup-only
stage='dashboard-artifact-verify'
portal_id="$(docker --host unix:///var/run/docker.sock ps -q --filter label=com.docker.compose.project=cloud-soc-central --filter label=com.docker.compose.service=portal)"
python3 - "$workspace" "$portal_id" "$release_dir/dashboard-result.json" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
workspace, portal_id, receipt = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
files=['prototype/devices.html','prototype/devices.css','prototype/devices.js','prototype/cases.html','prototype/cases.css','prototype/cases.js','prototype/multicloud.css','prototype/operations.html','prototype/operations.css','prototype/operations.js','prototype/multicloud.html','prototype/multicloud.js','prototype/logs.js','src/cloud_soc/multicloud/adapter.py','src/cloud_soc/multicloud/processing.py','src/cloud_soc/multicloud/processing_setup.py','src/cloud_soc/portal/log_contract.py','src/cloud_soc/portal/log_query.py','src/cloud_soc/portal/security_detail.py','src/cloud_soc/portal/operations.py','prototype/soc.html','prototype/soc/app.js','prototype/soc/app.css','src/cloud_soc/portal/overview.py','src/cloud_soc/portal/app.py','src/cloud_soc/portal/auth.py','prototype/shell.js','src/cloud_soc/processing/worker.py','src/cloud_soc/processing/__main__.py','src/cloud_soc/processing/errors.py','src/cloud_soc/processing/contract.py','src/cloud_soc/processing/continuation.py']
script='import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256((Path("/app")/p).read_bytes()).hexdigest() for p in '+repr(files)+'}))'
actual=json.loads(subprocess.check_output(['docker','--host','unix:///var/run/docker.sock','exec',portal_id,'python','-c',script],text=True))
expected={p:hashlib.sha256((workspace/p).read_bytes()).hexdigest() for p in files}
if actual!=expected:raise SystemExit('실행 컨테이너와 검토 소스의 파일 지문이 다릅니다. 배포 인수 실패.')
receipt.write_text(json.dumps({'dashboard_files_match':True,'files':expected,'authenticated_live_api_verified':False},indent=2)+'\n')
receipt.chmod(0o600)
print('실행 컨테이너의 새 대시보드/API 파일 지문 일치 확인 완료.')
PY
stage='complete'
echo '기동 및 배포 파일 검증 완료. 실제 Portal 로그인과 /api/overview 조회 확인은 별도입니다.'
echo "검증 기록: $release_dir/dashboard-result.json"

#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo '일반 터미널에서 sudo bash로 실행하세요.' >&2; exit 1; fi
probe_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ids="$(docker --host unix:///var/run/docker.sock ps -q --filter label=com.docker.compose.project=cloud-soc-central --filter label=com.docker.compose.service=normalizer)"
if [ -z "$ids" ] || [ "$(printf '%s\n' "$ids" | wc -l)" -ne 1 ]; then echo '운영 normalizer 1개를 확인할 수 없습니다.' >&2; exit 1; fi
docker --host unix:///var/run/docker.sock exec -i "$ids" python - < "$probe_dir/probe-normalizer.py"

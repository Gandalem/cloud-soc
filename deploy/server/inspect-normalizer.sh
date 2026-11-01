#!/usr/bin/env bash
# Read-only: no keys/config/env/payloads, restart, or checkpoint changes.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo '일반 터미널에서 sudo bash로 실행하세요.' >&2
  exit 1
fi
for service in normalizer normalizer-priority; do
  echo "[$service]"
  ids="$(docker --host unix:///var/run/docker.sock ps -aq --filter label=com.docker.compose.project=cloud-soc-central --filter "label=com.docker.compose.service=$service")"
  if [ -z "$ids" ]; then
    echo 'container_not_found'
    continue
  fi
  while IFS= read -r cid; do
    docker --host unix:///var/run/docker.sock inspect --format 'name={{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}} image={{.Image}}' "$cid"
    docker --host unix:///var/run/docker.sock logs --timestamps --since 30m --tail 60 "$cid" 2>&1
  done <<< "$ids"
done

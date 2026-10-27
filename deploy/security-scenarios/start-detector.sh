#!/usr/bin/env bash
# Explicit operational startup; no synthetic actions or verification run.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
if (( EUID == 0 )); then
  echo 'Run as the existing Ubuntu user, without sudo.' >&2
  exit 1
fi
umask 077
scenario_state="$HOME/.local/state/cloud-soc/security-scenarios"
scenario_python="$PWD/.venv-mall-detector/bin/python"
scenario_es="${SOC_ES_URL:-https://192.168.1.159:9200}"
mkdir -p "$scenario_state"
chmod 700 "$scenario_state"
if [[ ! -x "$scenario_python" ]]; then
  echo 'Existing .venv-mall-detector is required; see docs/security_scenarios_operations.md.' >&2
  exit 1
fi
# Hold across exec. A second launch must not share the SQLite checkpoint.
exec 9>"$scenario_state/worker.lock"
flock -n 9 || { echo 'Scenario worker already running.' >&2; exit 1; }
if [[ ! -e "$scenario_state/ca.crt" ]]; then
  sudo install -o "$(id -u)" -g "$(id -g)" -m 644 \
    state/server/tls/ca.crt "$scenario_state/ca.crt"
fi
if [[ ! -e "$scenario_state/detector.key" ]]; then
  sudo env PYTHONPATH="$PWD/src" "$scenario_python" -m cloud_soc.detection.setup \
    --es-url "$scenario_es" --ca-file "$scenario_state/ca.crt" \
    --password-file "$PWD/state/server/secrets/elastic_password" \
    --worker detector --key-file "$scenario_state/detector.key"
  sudo chown "$(id -u):$(id -g)" "$scenario_state/detector.key"
  chmod 600 "$scenario_state/detector.key"
fi
# First start only; preserve on every subsequent restart.
if [[ ! -e "$scenario_state/start.txt" ]]; then
  (set -o noclobber; date -u -d '2 minutes ago' +%Y-%m-%dT%H:%M:%SZ > "$scenario_state/start.txt")
fi
scenario_rules='SCENARIO-SERVER-FILE-001,SCENARIO-SERVER-PERSIST-001,SCENARIO-SERVER-DEFENSE-001,SCENARIO-APP-ROLE-001,SCENARIO-APP-EXPORT-001,SCENARIO-APP-UPLOAD-001,SCENARIO-NET-DNS-001,SCENARIO-NET-FIREWALL-001,SCENARIO-NET-IDS-001'
export PYTHONPATH="$PWD/src"
exec "$scenario_python" -m cloud_soc.detection \
  --run --additional-rules "$scenario_rules" --status-id detector-security-scenarios \
  --state "$scenario_state/runtime.sqlite" --start "$(cat "$scenario_state/start.txt")" \
  --interval 10 --lateness-seconds 180 \
  --es-url "$scenario_es" --ca-file "$scenario_state/ca.crt" \
  --api-key-file "$scenario_state/detector.key"

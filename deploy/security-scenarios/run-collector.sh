#!/usr/bin/env bash
# Tail real producer files; only native tail/journalctl use sudo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
if (( EUID == 0 )); then echo 'Run without sudo.' >&2; exit 1; fi
scenario_source="${1:?Usage: bash run-collector.sh auditd|eve|kernel|business}"
scenario_state="$HOME/.local/state/cloud-soc/security-scenarios"
scenario_python="$PWD/.venv-mall-detector/bin/python"
scenario_host="${SOC_SCENARIO_HOST:-ubuntu-192-168-1-159}"
scenario_org="${SOC_SCENARIO_ORGANIZATION:-local-ubuntu}"
scenario_mall="${SOC_MALL_PATH:-$HOME/security-mall}"
scenario_eve="${SOC_EVE_PATH:-$HOME/.local/state/cloud-soc/suricata/eve.json}"
export PYTHONPATH="$PWD/src"
bridge=("$scenario_python" deploy/security-scenarios/collect.py
  --source "$scenario_source" --state "$scenario_state/$scenario_source.sqlite"
  --organization "$scenario_org" --host "$scenario_host" --service security-mall
  --es-url "${SOC_ES_URL:-https://192.168.1.159:9200}"
  --ca-file "$scenario_state/ca.crt" --key-file "$scenario_state/writer.key")
case "$scenario_source" in
  auditd) sudo tail -n +1 -F /var/log/audit/audit.log | "${bridge[@]}" ;;
  eve) sudo tail -n +1 -F "$scenario_eve" | "${bridge[@]}" ;;
  kernel) sudo journalctl -k -f --since '15 minutes ago' -o json --no-pager | "${bridge[@]}" ;;
  business) tail -n +1 -F "$scenario_mall/audit/business-audit.jsonl" | "${bridge[@]}" ;;
  *) echo 'Unknown source' >&2; exit 1 ;;
esac

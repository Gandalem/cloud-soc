#!/usr/bin/env bash
# Append only these explicit watches; no flush (-D), restart or immutable changes.
set -euo pipefail
if (( EUID != 0 )); then echo 'Run this configuration step with sudo.' >&2; exit 1; fi
rules=/etc/audit/rules.d/70-cloud-soc-scenarios.rules
umask 077
(set -o noclobber; : > "$rules")
for audit_target in /etc/hosts /etc/passwd /etc/group; do
  if [[ -e "$audit_target" ]]; then printf '%s\n' "-w $audit_target -p wa -k soc_file" >> "$rules"; fi
done
for audit_target in /etc/systemd/system /etc/cron.d /etc/cron.hourly /var/spool/cron/crontabs; do
  if [[ -d "$audit_target" ]]; then printf '%s\n' "-w $audit_target -p wa -k soc_persist" >> "$rules"; fi
done
for audit_target in /etc/audit /etc/ufw /etc/apparmor.d; do
  if [[ -d "$audit_target" ]]; then printf '%s\n' "-w $audit_target -p wa -k soc_defense" >> "$rules"; fi
done
chmod 600 "$rules"
auditctl -R "$rules"
echo 'Dedicated audit watches applied; existing rules retained. Do not repeat installation.'

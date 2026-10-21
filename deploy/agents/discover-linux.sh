#!/usr/bin/env bash
# Sourced by the installer, or run by the protected discovery timer.
# cloud-soc-policy-format: 1
set -euo pipefail

# BEGIN SECURITY FILES
SECURITY_CORE_FILES='^/var/log/(auth\.log|secure|audit/audit\.log|ufw\.log|fail2ban\.log)(\.[0-9]+)?$'
SECURITY_PACKAGE_FILES='^/var/log/(dpkg\.log|apt/history\.log|dnf\.rpm\.log|yum\.log)(\.[0-9]+)?$'
# END SECURITY FILES
SECURITY_PACKAGES_ENABLED=false

json_string() {
    local value=${1//\\/\\\\} code character escaped octal
    value=${value//\"/\\\"}
    if [[ $value =~ [[:cntrl:]] ]]; then
        for ((code=1; code<32; code++)); do
            printf -v octal '%03o' "$code"
            printf -v character '%b' "\\$octal"
            printf -v escaped '\\u%04x' "$code"
            value=${value//"$character"/"$escaped"}
        done
    fi
    printf '"%s"' "$value"
}

render_discovery_report() {
    local entry separator=
    printf '{"generated_at":"%s","selected_files":%s,"entries":[' "$(date -u +%FT%TZ)" "${#DISCOVERED_PATHS[@]}"
    for entry in "${DISCOVERY_REPORT[@]}"; do printf '%s%s' "$separator" "$entry"; separator=,; done
    printf ']}\n'
}

valid_log_root() {
    [[ $1 =~ ^/[-a-zA-Z0-9_./]+$ && $1 != */../* && $1 != */.. && $1 != */./* ]] || return 1
    case "$1" in
        /|/var|/opt|/srv|/usr|/etc|/etc/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/home|/home/*|/root|/root/*|/opt/cloud-soc-agent|/opt/cloud-soc-agent/*) return 1 ;;
    esac
    [[ $1 == /*/* && $1 != */ ]]
}

discover_linux_logs() {
    DISCOVERED_PATHS=(); DISCOVERY_REPORT=()
    HEALTH_SOURCES=(); HEALTH_SELECTED=0; HEALTH_EXCLUDED=0; HEALTH_ERRORS=0
    local root path encoding status complete
    declare -A seen=()
    for root in "$@"; do
        [[ -d $root && ! -L $root && $(realpath -e -- "$root") == "$root" ]] || { printf 'Unsafe/missing log root: %s\n' "$root" >&2; return 1; }
        complete=false
        # The sentinel preserves find's exit status without a temporary inventory file.
        while IFS= read -r -d '' path; do
            if [[ $path == DISCOVERY_COMPLETE ]]; then complete=true; continue; fi
            [[ -z ${seen[$path]:-} ]] || continue
            seen[$path]=1
            status=selected
            local excluded
            for excluded in "${POLICY_EXCLUSIONS[@]:-}"; do
                if [[ -n $excluded && ( $path == "$excluded" || $path == "$excluded/"* ) ]]; then status=policy_excluded; break; fi
            done
            if [[ $status == policy_excluded ]]; then
                :
            elif [[ $path == *['$*?[]']* || $path =~ [[:cntrl:]] ]]; then
                status=unsafe_path
            elif [[ -L $path ]]; then
                status=symlink
            elif [[ ( ! -f $path || ! -r $path ) && ( $path =~ $SECURITY_CORE_FILES || ( $SECURITY_PACKAGES_ENABLED == true && $path =~ $SECURITY_PACKAGE_FILES ) ) ]]; then
                status=unreadable
            # Provisioning output can embed user-data, configuration and multiline
            # secrets. Exclude the whole source before reading or regex masking.
            elif [[ ${path,,} == /var/log/installer/* || ${path,,} =~ /(autoinstall-user-data|user-data|cloud-init(-output)?\.log)(\.|/|$) ]]; then
                status=binary_archive_or_secret
            elif [[ ${path,,} =~ \.(gz|xz|bz2|zip|zst|journal|journal~|db|sqlite|pem|key|crt|cer|der|p12|pfx|docx?|xlsx?|pdf|kdbx)$ || ${path,,} =~ /(wtmp|btmp|lastlog|faillog|tallylog|\.env|id_rsa|id_ed25519|id_ecdsa|credentials|secrets?)(\.|/|$) ]]; then
                status=binary_archive_or_secret
            elif [[ ! $path =~ $SECURITY_CORE_FILES ]] && { ! $SECURITY_PACKAGES_ENABLED || [[ ! $path =~ $SECURITY_PACKAGE_FILES ]]; }; then
                status=policy_excluded
            else
                encoding=$(file -b --mime-encoding -- "$path") || encoding=unreadable
                case "$encoding" in us-ascii|utf-8) ;; *) status=unsupported_encoding_or_binary ;; esac
                [[ -s $path ]] || status=empty_pending
            fi
            if [[ $status == selected ]]; then DISCOVERED_PATHS+=("$path"); fi
            case "$status" in
                selected) HEALTH_SELECTED=$((HEALTH_SELECTED + 1)) ;;
                unreadable) HEALTH_ERRORS=$((HEALTH_ERRORS + 1)) ;;
                *) HEALTH_EXCLUDED=$((HEALTH_EXCLUDED + 1)) ;;
            esac
            if ((${#HEALTH_SOURCES[@]} < 200)); then
                local digest
                digest=$(printf '%s' "$path" | sha256sum); digest=${digest%% *}
                HEALTH_SOURCES+=("{\"id\":\"$digest\",\"status\":\"$status\"}")
            fi
            DISCOVERY_REPORT+=("$(printf '{"path":%s,"status":%s}' "$(json_string "$path")" "$(json_string "$status")")")
        done < <(find -P "$root" \( -type d ! -path "$root" ! -path /var/log/audit ! -path /var/log/apt -prune \) -o \( -type f -o -type l \) -print0 && printf 'DISCOVERY_COMPLETE\0')
        $complete || { printf 'Discovery failed; previous inputs retained: %s\n' "$root" >&2; return 1; }
    done
    if ((${#DISCOVERED_PATHS[@]})); then
        mapfile -d '' -t DISCOVERED_PATHS < <(printf '%s\0' "${DISCOVERED_PATHS[@]}" | LC_ALL=C sort -z)
    fi
}

publish_health_report() {
    local root=$1 version=0 entry separator= total metrics collection=
    version=${POLICY_VERSION:-0}
    [[ $version =~ ^[0-9]{1,9}$ ]] || return 1
    if [[ -f $root/discovery-report.json && ! -L $root/discovery-report.json ]]; then
        local summary
        summary=$(python3 - "$root/discovery-report.json" <<'PY'
import hashlib,json,sys
rows=json.load(open(sys.argv[1]))['entries']
print(sum(x['status']=='selected' for x in rows))
print(sum(x['status'] not in ('selected','unreadable','enumeration_error') for x in rows))
print(sum(x['status'] in ('unreadable','enumeration_error') for x in rows))
for x in rows[:200]:print(json.dumps({'id':hashlib.sha256(x['path'].encode()).hexdigest(),'status':x['status']}))
PY
        ) || return 1
        local -a summary_lines
        mapfile -t summary_lines <<< "$summary"
        HEALTH_SELECTED=${summary_lines[0]}; HEALTH_EXCLUDED=${summary_lines[1]}; HEALTH_ERRORS=${summary_lines[2]}
        HEALTH_SOURCES=("${summary_lines[@]:3}")
    fi
    [[ ! -L $root/health.ndjson && ! -L $root/health-previous.ndjson ]] || return 1
    # Bounded local spool; prolonged transport outages may lose older reports.
    if [[ -f $root/health.ndjson ]] && (($(stat -c %s "$root/health.ndjson") > 5242880)); then
        mv -f -- "$root/health.ndjson" "$root/health-previous.ndjson"
    fi
    total=$((HEALTH_SELECTED + HEALTH_EXCLUDED + HEALTH_ERRORS))
    metrics='"collector_metrics":{"schema":1,"state":"unavailable","reason":"reader_unavailable"},"network_collector_metrics":{"schema":1,"state":"unavailable","reason":"reader_unavailable"}'
    if [[ -f $root/collector-metrics.py && ! -L $root/collector-metrics.py ]] && command -v python3 >/dev/null; then
        local sampled
        if sampled=$(timeout 15 python3 -I "$root/collector-metrics.py" --root "$root" 2>/dev/null) && [[ $sampled == \{*\} && ${#sampled} -lt 8192 ]]; then
            metrics=${sampled:1:${#sampled}-2}
        fi
    fi
    {
        printf '{"schema":1,"generated_at":"%s","policy_version":%s,"selected":%s,"excluded":%s,"errors":%s,"total":%s,"sources":[' "$(date -u +%FT%TZ)" "$version" "$HEALTH_SELECTED" "$HEALTH_EXCLUDED" "$HEALTH_ERRORS" "$total"
        for entry in "${HEALTH_SOURCES[@]}"; do printf '%s%s' "$separator" "$entry"; separator=,; done
        if [[ -f $root/collection-profile.json ]]; then
            collection=$(python3 - "$root/collection-profile.json" <<'PY'
import json, os, sys, importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('profile_reader',Path(sys.argv[1]).with_name('profile-reader.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);p=module.read(sys.argv[1])
active=[x for x in p['web_inputs'] if x.get('enabled',True)]
errors=sum(not os.path.isfile(x['paths'][0]) or not os.access(x['paths'][0],os.R_OK) or os.path.realpath(x['paths'][0])!=x['paths'][0] for x in active)
print(',"collection":'+json.dumps({'schema':1,'system':p['system'],'web':bool(active),'network':p['network'],'web_errors':errors}))
PY
)
        fi
        printf '],"queue_state":"unknown","transport_state":"unknown",%s%s}\n' "$metrics" "$collection"
    } >> "$root/health.ndjson"
    local candidate
    candidate=$(mktemp "$root/inputs/.health.XXXXXX")
    printf '[{"type":"filestream","id":"cloud-soc-health-v1","paths":["%s/health*.ndjson"],"prospector.scanner.fingerprint.length":64,"parsers":[{"ndjson":{"target":"cloud_soc.discovery"}}],"fields_under_root":true,"fields":{"labels":{"log_source":"agent_health"}},"processors":[{"drop_fields":{"fields":["message"],"ignore_missing":true}}]}]\n' "$root" > "$candidate"
    publish_discovery_file "$candidate" "$root/inputs/health.yml"
}

render_discovered_inputs() {
    printf '['
    if ((${#DISCOVERED_PATHS[@]})); then
        printf '{"type":"filestream","id":"cloud-soc-linux-discovered-v2","paths":['
        local path separator=
        for path in "${DISCOVERED_PATHS[@]}"; do printf '%s%s' "$separator" "$(json_string "$path")"; separator=,; done
        printf '%s' '],"prospector.scanner.symlinks":false,"file_identity.fingerprint":{"growing":true},"fields_under_root":true,"fields":{"labels":{"log_source":"linux_file","collection_mode":"auto_discovery","collection_policy":"security-focused-v1"}}}'
    fi
    printf ']\n'
}

publish_discovery_file() {
    local candidate=$1 destination=$2
    [[ ! -L $destination ]] || { printf 'Refusing symlink output\n' >&2; return 1; }
    if [[ -f $destination ]] && cmp -s -- "$candidate" "$destination"; then
        rm -- "$candidate"
    else
        mv -f -- "$candidate" "$destination"
    fi
}

refresh_linux_inputs() {
    local root=$1; shift
    [[ -d $root/inputs && ! -L $root/inputs ]] || return 1
    umask 077
    # Concurrent timer/manual refreshes must not race configuration publication.
    exec 9>"$root/discovery.lock"
    flock -n 9 || return 0
    POLICY_EXCLUSIONS=(); POLICY_VERSION=0
    local -a roots=("$@")
    if [[ -f $root/collection-policy.txt ]]; then
        [[ ! -L $root/collection-policy.txt ]] || return 1
        roots=()
        local line first=true
        while IFS= read -r line; do
            if $first; then
                [[ $line =~ ^version=([0-9]{1,9})$ ]] || return 1
                POLICY_VERSION=${BASH_REMATCH[1]}; first=false; continue
            fi
            case "$line" in
                root=*) roots+=("${line#root=}") ;;
                exclude=*) valid_log_root "${line#exclude=}" || return 1; POLICY_EXCLUSIONS+=("${line#exclude=}") ;;
                *) return 1 ;;
            esac
        done < "$root/collection-policy.txt"
        $first && return 1
    elif ((${#roots[@]} == 0)); then
        mapfile -t roots < "$root/discovery-roots.txt"
    fi
    ((${#roots[@]} > 0)) || return 1
    local unified=false system_enabled=true
    SECURITY_PACKAGES_ENABLED=$(python3 - "$root/security-roles.json" <<'PY'
import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);roles=[]
if p.exists() or p.is_symlink():
    if p.is_symlink() or p.stat().st_size>8192 or p.stat().st_mode & 0o077:raise ValueError('Invalid security roles')
    value=json.loads(p.read_text())
    if set(value)!={'schema','roles'} or value['schema']!=1 or not isinstance(value['roles'],list):raise ValueError('Invalid security roles')
    roles=value['roles']
    if len(roles)!=len(set(roles)) or set(roles)-{'packages','sysmon_network','directory_service','application'}:raise ValueError('Invalid security roles')
print(str('packages' in roles).lower())
PY
    ) || return 1
    if [[ -f $root/collection-profile.json ]]; then
        [[ ! -L $root/collection-profile.json ]] || return 1
        unified=true
        system_enabled=$(python3 "$root/profile-reader.py" "$root/collection-profile.json" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)["system"]).lower())') || return 1
        while IFS= read -r path; do valid_log_root "$path" || return 1; POLICY_EXCLUSIONS+=("$path"); done < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["web_exclusions"]))' "$root/collection-profile.json")
    fi
    local path
    for path in "${roots[@]}"; do valid_log_root "$path" || return 1; done
    if $system_enabled; then discover_linux_logs "${roots[@]}"; else discover_linux_logs; fi
    local candidate report
    candidate=$(mktemp "$root/inputs/.candidate.XXXXXX")
    render_discovered_inputs > "$candidate"
    python3 - "$root/collection-profile.json" "$candidate" "$system_enabled" <<'PY'
import json, sys, importlib.util, os, re, tempfile
from pathlib import Path
p={'system':sys.argv[3]=='true','web_inputs':[]}
if Path(sys.argv[1]).exists():
    spec=importlib.util.spec_from_file_location('profile_reader',Path(sys.argv[1]).with_name('profile-reader.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);p=module.read(sys.argv[1])
inputs = json.loads(Path(sys.argv[2]).read_text())
if p['system']:
    # Retain the existing input identity/cursor. File authentication/audit sources
    # take precedence; journal covers systems without the corresponding file.
    paths=[x for i in inputs for x in i.get('paths',[])]
    patterns={'auth_file':r'/var/log/(?:auth\.log|secure)(?:\.[0-9]+)?',
              'audit_file':r'/var/log/audit/audit\.log(?:\.[0-9]+)?',
              'firewall_file':r'/var/log/ufw\.log(?:\.[0-9]+)?'}
    available={key:any(re.fullmatch(pattern,x) for x in paths) for key,pattern in patterns.items()}
    preference=Path(sys.argv[1]).with_name('security-source-preference.json')
    pinned={'schema':1,**available}
    if preference.exists() or preference.is_symlink():
        if preference.is_symlink() or preference.stat().st_size>8192 or preference.stat().st_mode & 0o077:raise ValueError('Invalid source preference')
        pinned=json.loads(preference.read_text())
        if set(pinned)!={'schema',*patterns} or pinned['schema']!=1 or any(type(pinned[k]) is not bool for k in patterns):raise ValueError('Invalid source preference')
        if any(pinned[k] and not available[k] for k in patterns):raise ValueError('Pinned required file missing; explicit source cutover required')
    else:
        fd,tmp=tempfile.mkstemp(prefix='.source-preference-',dir=preference.parent)
        try:
            with os.fdopen(fd,'w') as out:json.dump(pinned,out);out.flush();os.fsync(out.fileno())
            os.replace(tmp,preference)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    for entry in inputs:
        if 'paths' in entry:entry['paths']=[x for x in entry['paths'] if not any(not pinned[k] and re.fullmatch(pattern,x) for k,pattern in patterns.items())]
    inputs=[entry for entry in inputs if 'paths' not in entry or entry['paths']]
    auth=pinned['auth_file'];audit=pinned['audit_file'];firewall=pinned['firewall_file']
    identifiers=['polkitd','systemd-logind','cron','CRON','crond','setroubleshoot']
    if not auth:identifiers+=['sshd','sudo','su']
    if not audit:identifiers+=['audit','auditd']
    matches=['SYSLOG_IDENTIFIER='+x for x in identifiers]+['+','_TRANSPORT=kernel']
    if not audit:matches+=['+','_TRANSPORT=audit']
    excluded=[]
    if audit:excluded.append({'regexp':{'message':'^(?:audit: )?type=(?:AVC|USER_AVC|SYSCALL|PATH|CWD|USER_AUTH|USER_LOGIN)\\b'}})
    if firewall:excluded.append({'contains':{'message':'[UFW '}})
    processors=[{'drop_event':{'when':{'equals':{'systemd.unit':'cloud-soc-filebeat.service'}}}},
      {'drop_event':{'when':{'and':[{'equals':{'systemd.transport':'kernel'}},{'not':{'regexp':{'message':'(?i)(apparmor=|avc:|selinux|\\[UFW |IN=.*OUT=|module verification failed|lockdown|audit:)'}}}]}}}]
    if excluded:processors.append({'drop_event':{'when':{'or':excluded}}})
    inputs.append({'type':'journald','id':'cloud-soc-journal-v2','seek':'head','include_matches':{'match':matches},'fields_under_root':True,'fields':{'labels':{'log_source':'linux_journald','collection_mode':'auto_discovery','collection_policy':'security-focused-v1'}},'processors':processors})
inputs.extend(p['web_inputs'])
Path(sys.argv[2]).write_text(json.dumps(inputs))
PY
    if [[ $? != 0 ]]; then rm -f -- "$candidate"; return 1; fi
    report=$(mktemp "$root/.inventory.XXXXXX")
    render_discovery_report > "$report"
    python3 - "$report" "$candidate" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);value=json.loads(p.read_text());inputs=json.loads(Path(sys.argv[2]).read_text());active={x for i in inputs for x in i.get('paths',[])}
for row in value['entries']:
    if row['status']=='selected' and row['path'] not in active:row['status']='policy_excluded'
value['selected_files']=sum(row['status']=='selected' for row in value['entries'])
for entry in inputs:
    if entry.get('type')=='journald':value['entries'].append({'path':'journal:'+entry['id'],'status':'selected','kind':'journal'})
p.write_text(json.dumps(value))
PY
    publish_discovery_file "$candidate" "$root/inputs/discovered.yml"
    publish_discovery_file "$report" "$root/discovery-report.json"
    publish_health_report "$root"
    flock -u 9
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $EUID == 0 ]] || { printf 'Run as root\n' >&2; exit 1; }
    root=/opt/cloud-soc-agent
    refresh_linux_inputs "$root"
fi

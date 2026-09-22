#!/usr/bin/env bash
# Sourced by the installer, or run by the protected discovery timer.
# cloud-soc-policy-format: 1
set -euo pipefail

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
            elif [[ ! -f $path || ! -r $path ]]; then
                status=unreadable
            elif [[ ${path,,} =~ \.(gz|xz|bz2|zip|zst|journal|journal~|db|sqlite|pem|key|crt|cer|der|p12|pfx|docx?|xlsx?|pdf|kdbx)$ || ${path,,} =~ /(wtmp|btmp|lastlog|faillog|tallylog|\.env|id_rsa|id_ed25519|id_ecdsa|credentials|secrets?)(\.|/|$) ]]; then
                status=binary_archive_or_secret
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
        done < <(find -P "$root" \( -type f -o -type l \) -print0 && printf 'DISCOVERY_COMPLETE\0')
        $complete || { printf 'Discovery failed; previous inputs retained: %s\n' "$root" >&2; return 1; }
    done
    if ((${#DISCOVERED_PATHS[@]})); then
        mapfile -d '' -t DISCOVERED_PATHS < <(printf '%s\0' "${DISCOVERED_PATHS[@]}" | LC_ALL=C sort -z)
    fi
}

publish_health_report() {
    local root=$1 version=0 entry separator= total
    version=${POLICY_VERSION:-0}
    [[ $version =~ ^[0-9]{1,9}$ ]] || return 1
    [[ ! -L $root/health.ndjson && ! -L $root/health-previous.ndjson ]] || return 1
    # Bounded local spool; prolonged transport outages may lose older reports.
    if [[ -f $root/health.ndjson ]] && (($(stat -c %s "$root/health.ndjson") > 5242880)); then
        mv -f -- "$root/health.ndjson" "$root/health-previous.ndjson"
    fi
    total=$((HEALTH_SELECTED + HEALTH_EXCLUDED + HEALTH_ERRORS))
    {
        printf '{"schema":1,"generated_at":"%s","policy_version":%s,"selected":%s,"excluded":%s,"errors":%s,"total":%s,"sources":[' "$(date -u +%FT%TZ)" "$version" "$HEALTH_SELECTED" "$HEALTH_EXCLUDED" "$HEALTH_ERRORS" "$total"
        for entry in "${HEALTH_SOURCES[@]}"; do printf '%s%s' "$separator" "$entry"; separator=,; done
        printf '],"queue_state":"unknown","transport_state":"unknown"}\n'
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
        printf '%s' '],"prospector.scanner.symlinks":false,"file_identity.fingerprint":{"growing":true},"fields_under_root":true,"fields":{"labels":{"log_source":"linux_file","collection_mode":"auto_discovery"}}}'
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
    local path
    for path in "${roots[@]}"; do valid_log_root "$path" || return 1; done
    discover_linux_logs "${roots[@]}"
    local candidate report
    candidate=$(mktemp "$root/inputs/.candidate.XXXXXX")
    render_discovered_inputs > "$candidate"
    report=$(mktemp "$root/.inventory.XXXXXX")
    render_discovery_report > "$report"
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

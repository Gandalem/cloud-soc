#!/usr/bin/env bash
# Sourced by the installer, or run by the protected discovery timer.
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
            if [[ $path == *['$*?[]']* || $path =~ [[:cntrl:]] ]]; then
                status=unsafe_path
            elif [[ -L $path ]]; then
                status=symlink
            elif [[ ! -f $path || ! -r $path ]]; then
                status=unreadable
            elif [[ ${path,,} =~ \.(gz|xz|bz2|zip|zst|journal|journal~|db|sqlite|pem|key|crt|cer|der|p12|pfx)$ || ${path,,} =~ /(wtmp|btmp|lastlog|faillog|tallylog|\.env|id_rsa|id_ed25519|id_ecdsa)(\.|$) ]]; then
                status=binary_archive_or_secret
            else
                encoding=$(file -b --mime-encoding -- "$path") || encoding=unreadable
                case "$encoding" in us-ascii|utf-8) ;; *) status=unsupported_encoding_or_binary ;; esac
                [[ -s $path ]] || status=empty_pending
            fi
            if [[ $status == selected ]]; then DISCOVERED_PATHS+=("$path"); fi
            DISCOVERY_REPORT+=("$(printf '{"path":%s,"status":%s}' "$(json_string "$path")" "$(json_string "$status")")")
        done < <(find -P "$root" \( -type f -o -type l \) -print0 && printf 'DISCOVERY_COMPLETE\0')
        $complete || { printf 'Discovery failed; previous inputs retained: %s\n' "$root" >&2; return 1; }
    done
    if ((${#DISCOVERED_PATHS[@]})); then
        mapfile -d '' -t DISCOVERED_PATHS < <(printf '%s\0' "${DISCOVERED_PATHS[@]}" | LC_ALL=C sort -z)
    fi
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
    discover_linux_logs "$@"
    local candidate report
    candidate=$(mktemp "$root/inputs/.candidate.XXXXXX")
    render_discovered_inputs > "$candidate"
    report=$(mktemp "$root/.inventory.XXXXXX")
    render_discovery_report > "$report"
    publish_discovery_file "$candidate" "$root/inputs/discovered.yml"
    publish_discovery_file "$report" "$root/discovery-report.json"
    flock -u 9
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $EUID == 0 ]] || { printf 'Run as root\n' >&2; exit 1; }
    root=/opt/cloud-soc-agent
    mapfile -t roots < "$root/discovery-roots.txt"
    for path in "${roots[@]}"; do valid_log_root "$path" || exit 1; done
    refresh_linux_inputs "$root" "${roots[@]}"
fi

#!/usr/bin/env bash
# First-install only. Use --dry-run to print the configuration without side effects.
set -euo pipefail

BEAT_VERSION=9.5.2
ROOT=/opt/cloud-soc-agent
UNIT=/etc/systemd/system/cloud-soc-filebeat.service
ENDPOINT= CA= ORGANIZATION=
DRY_RUN=false
EXTRA_FILES=()

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    printf '%s\n' 'Usage: sudo bash install-ubuntu.sh --endpoint https://HOST:9200 --ca /path/ca.crt --organization ID [--log-file /absolute/file.log] [--dry-run]'
}

parse_args() {
    while (($#)); do
        case "$1" in
            --endpoint|--ca|--organization|--log-file)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || fail "Missing value for $1"
                case "$1" in
                    --endpoint) ENDPOINT=$2 ;;
                    --ca) CA=$2 ;;
                    --organization) ORGANIZATION=$2 ;;
                    --log-file) EXTRA_FILES+=("$2") ;;
                esac
                shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --help) usage; exit 0 ;;
            *) fail "Unknown option: $1" ;;
        esac
    done
}

validate_args() {
    # Intentionally restrict v1 to DNS/IPv4 authorities, not URL paths or credentials.
    [[ $ENDPOINT =~ ^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?/?$ ]] || fail 'Use an HTTPS DNS/IPv4 endpoint without credentials, path, query or fragment.'
    local port=${BASH_REMATCH[4]:-443}
    ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Invalid endpoint port.'
    ENDPOINT=${ENDPOINT%/}
    [[ $ORGANIZATION =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$ ]] || fail 'Organization must be a 1-64 character identifier (letters, digits, underscore, hyphen).'
    [[ $CA =~ ^/[-a-zA-Z0-9_./]+$ ]] || fail 'CA must be an absolute path without spaces or special characters.'
    local path
    declare -A seen=([/var/log/auth.log]=1 [/var/log/syslog]=1)
    for path in "${EXTRA_FILES[@]}"; do
        [[ $path =~ ^/var/log/[-a-zA-Z0-9_./]+$ && $path != */../* && $path != */.. ]] || fail 'Additional logs must be explicit files under /var/log (no globs, spaces or parent traversal).'
        [[ -z ${seen[$path]:-} ]] || fail "Duplicate log path: $path"
        seen[$path]=1
    done
}

render_input() {
    local path=$1 source=$2 id=$3
    printf '{"type":"filestream","id":"%s","paths":["%s"],"fields_under_root":true,"fields":{"labels":{"log_source":"%s"}}}' "$id" "$path" "$source"
}

render_config() {
    # JSON is a YAML-compatible representation; all interpolated values are validated.
    printf '{"filebeat.inputs":['
    render_input /var/log/auth.log linux_auth cloud-soc-linux-auth
    printf ','
    render_input /var/log/syslog linux_syslog cloud-soc-linux-syslog
    local path id
    for path in "${EXTRA_FILES[@]}"; do
        id=$(printf '%s' "$path" | sha256sum); id=${id%% *}
        printf ','
        render_input "$path" linux_file "cloud-soc-file-$id"
    done
    printf '],"processors":[{"add_host_metadata":{}},{"add_fields":{"target":"organization","fields":{"id":"%s"}}}],' "$ORGANIZATION"
    printf '"output.elasticsearch":{"hosts":["%s"],"api_key":"${CLOUD_SOC_API_KEY}","ssl.certificate_authorities":["%s/ca.crt"],"ssl.verification_mode":"full","index":"soc-host-raw-linux-%s-%%{+yyyy.MM.dd}","timeout":30},' "$ENDPOINT" "$ROOT" "$BEAT_VERSION"
    printf '%s\n' '"setup.ilm.enabled":false,"setup.template.enabled":false,"logging.level":"info","queue.disk":{"max_size":"1GB"}}'
}

check_existing() {
    local path service
    for path in "$ROOT" "$UNIT" /etc/filebeat /var/lib/filebeat /usr/share/filebeat /opt/Elastic/Agent; do
        [[ ! -e $path && ! -L $path ]] || fail "Existing installation or partial state: $path. Review it manually; nothing will be overwritten."
    done
    for service in cloud-soc-filebeat filebeat elastic-agent; do
        [[ $(systemctl show "$service.service" -p LoadState --value) == not-found ]] || fail "Existing service: $service"
    done
    ! pgrep -x filebeat >/dev/null || fail 'A Filebeat process is already running.'
    ! pgrep -x elastic-agent >/dev/null || fail 'An Elastic Agent process is already running.'
}

verify_archive() {
    local archive=$1 expected=$2 actual
    [[ $expected =~ ^[a-f0-9]{128}$ ]] || fail 'Invalid pinned SHA-512.'
    actual=$(sha512sum "$archive"); actual=${actual%% *}
    [[ $actual == "$expected" ]] || fail 'SHA-512 mismatch; refusing to extract or execute the download.'
}

beat() {
    "$ROOT/filebeat/filebeat" --path.home "$ROOT/filebeat" --path.config "$ROOT" \
        --path.data "$ROOT/data" --path.logs "$ROOT/logs" -c "$ROOT/filebeat.yml" "$@"
}

install_agent() {
    [[ $EUID == 0 ]] || fail 'Run with sudo (not required for --dry-run).'
    [[ -f /etc/os-release ]] || fail 'Ubuntu 22.04 is required.'
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 22.04 && -d /run/systemd/system ]] || fail 'Only Ubuntu 22.04 with systemd is supported.'
    local tool path arch hash package member
    for tool in curl tar sha512sum sha256sum systemctl pgrep timeout realpath; do
        command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"
    done
    [[ -t 0 ]] || fail 'An interactive terminal is required for the API key prompt.'
    check_existing
    [[ -f $CA && -r $CA ]] || fail 'CA certificate is not a readable file.'
    declare -A real_paths=()
    for path in /var/log/auth.log /var/log/syslog "${EXTRA_FILES[@]}"; do
        [[ -f $path && -r $path && ! -L $path ]] || fail "Required log file missing/unreadable or symlink: $path. Configure logging first."
        local resolved
        resolved=$(realpath -e "$path")
        [[ $resolved == /var/log/* ]] || fail "Log resolves outside /var/log: $path"
        [[ -z ${real_paths[$resolved]:-} ]] || fail "Duplicate resolved log path: $path"
        real_paths[$resolved]=1
    done
    case "$(uname -m)" in
        x86_64) arch=x86_64; hash=244127495eaca8d4cfa05d002c32e9b89019eb3d67389a118641fc0a4ff923353b0d787fbdd2e609e1b0fd622add39f72906653a26bbca656d8e3502f472e249 ;;
        aarch64) arch=arm64; hash=00cc9a30a347b954d84e2dec08429e8b591c0f47681f713773ba07c3f7bd0805cb167a93a80e5206b76c21fefe18ef9a9f43ab2220df48ebda2f9aa3941fdada ;;
        *) fail 'Only x86_64 and aarch64 are supported.' ;;
    esac
    package="filebeat-$BEAT_VERSION-linux-$arch"
    umask 077
    # Exclusive mkdir also guards concurrent installers. Failures retain protected state.
    mkdir -m 700 "$ROOT"
    trap 'printf "Installation failed; protected partial state remains in %s. No automatic reinstall/cleanup.\n" "$ROOT" >&2' ERR
    mkdir "$ROOT/data" "$ROOT/logs" "$ROOT/staging"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 600 --retry 2 \
        "https://artifacts.elastic.co/downloads/beats/filebeat/$package.tar.gz" -o "$ROOT/package.tar.gz"
    verify_archive "$ROOT/package.tar.gz" "$hash"
    tar -tzf "$ROOT/package.tar.gz" > "$ROOT/archive-members.txt"
    while IFS= read -r member; do
        [[ $member == "$package/"* && $member != */../* && $member != */.. ]] || fail 'Unexpected archive path.'
    done < "$ROOT/archive-members.txt"
    tar -xzf "$ROOT/package.tar.gz" --no-same-owner -C "$ROOT/staging"
    mv "$ROOT/staging/$package" "$ROOT/filebeat"
    cp -- "$CA" "$ROOT/ca.crt"
    printf '{}\n' > "$ROOT/filebeat.yml"
    beat keystore create
    printf 'Enter the restricted Elasticsearch API key as id:api_key (not the encoded value).\n'
    beat keystore add CLOUD_SOC_API_KEY
    render_config > "$ROOT/filebeat.yml"
    beat test config
    timeout 90 "$ROOT/filebeat/filebeat" --path.home "$ROOT/filebeat" --path.config "$ROOT" \
        --path.data "$ROOT/data" --path.logs "$ROOT/logs" -c "$ROOT/filebeat.yml" test output
    # No service is registered until local configuration and TLS/auth checks succeed.
    (
        set -o noclobber
        printf '%s\n' '[Unit]' 'Description=Cloud SOC Filebeat' 'Wants=network-online.target' 'After=network-online.target' \
            '[Service]' 'Type=simple' 'User=root' 'UMask=0077' \
            "ExecStart=$ROOT/filebeat/filebeat --environment=systemd --path.home $ROOT/filebeat --path.config $ROOT --path.data $ROOT/data --path.logs $ROOT/logs -c $ROOT/filebeat.yml" \
            'Restart=on-failure' 'RestartSec=10' 'NoNewPrivileges=true' 'ProtectSystem=strict' 'ProtectHome=true' \
            "ReadWritePaths=$ROOT/data $ROOT/logs" '[Install]' 'WantedBy=multi-user.target' > "$UNIT"
    )
    chmod 644 "$UNIT"
    systemctl daemon-reload
    if ! systemctl enable --now cloud-soc-filebeat.service; then
        systemctl disable --now cloud-soc-filebeat.service || true
        fail 'Service start failed. Inspect journalctl -u cloud-soc-filebeat; partial installation retained.'
    fi
    sleep 3
    if ! systemctl is-active --quiet cloud-soc-filebeat.service; then
        systemctl disable --now cloud-soc-filebeat.service || true
        fail 'Service did not remain active. Inspect its journal before retrying.'
    fi
    printf '%s\n' 'Service active; TLS/auth connection test passed. Document ingestion is NOT yet verified. Check soc-host-raw-linux-* in Kibana.'
}

main() {
    parse_args "$@"
    validate_args
    if $DRY_RUN; then
        render_config
        printf '%s\n' 'DRY RUN: no download, writes, key prompt, OS/source checks, network or service changes.' >&2
        return
    fi
    install_agent
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

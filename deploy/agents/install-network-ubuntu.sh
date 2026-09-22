#!/usr/bin/env bash
# Add-on collector; never changes the existing Filebeat installation.
set -euo pipefail
BEAT_VERSION=9.5.2
ROOT=/opt/cloud-soc-network
UNIT=/etc/systemd/system/cloud-soc-packetbeat.service
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ENDPOINT= CA= ORGANIZATION= DEVICE=
DRY_RUN=false
SERVICE_CREATED=false

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

parse_args() {
    while (($#)); do
        case "$1" in
            --endpoint|--ca|--organization|--interface)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || fail "Missing value for $1"
                case "$1" in
                    --endpoint) ENDPOINT=$2 ;;
                    --ca) CA=$2 ;;
                    --organization) ORGANIZATION=$2 ;;
                    --interface) DEVICE=$2 ;;
                esac
                shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --help)
                printf '%s\n' 'Usage: sudo bash install-network-ubuntu.sh --endpoint https://HOST:9200 --ca /path/ca.crt --organization ID --interface eth0 [--dry-run]' 'Use --interface any explicitly for all local interfaces. No PCAP storage.'
                exit 0 ;;
            *) fail "Unknown option: $1" ;;
        esac
    done
}

validate_args() {
    [[ $ENDPOINT =~ ^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?/?$ ]] || fail 'Use an HTTPS DNS/IPv4 endpoint without credentials, path, query or fragment.'
    local port=${BASH_REMATCH[4]:-443}
    ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Invalid endpoint port.'
    ENDPOINT=${ENDPOINT%/}
    [[ $ORGANIZATION =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$ ]] || fail 'Invalid organization identifier.'
    [[ $CA =~ ^/[-a-zA-Z0-9_./]+$ ]] || fail 'CA must be an absolute path without spaces or special characters.'
    [[ $DEVICE =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$ ]] || fail 'Supply an explicit Linux interface name (1-15 characters) or any.'
    [[ -f $SCRIPT_DIR/packetbeat.base.json ]] || fail 'Keep packetbeat.base.json beside the installer.'
}

render_config() {
    # All replacement values are restricted above; none can inject JSON or sed syntax.
    sed -e "s|__DEVICE__|$DEVICE|g" -e "s|__ORGANIZATION__|$ORGANIZATION|g" \
        -e "s|__PLATFORM__|linux|g" -e "s|__ENDPOINT__|$ENDPOINT|g" \
        -e "s|__CA_PATH__|$ROOT/ca.crt|g" -e 's|"type": "pcap"|"type": "af_packet"|' \
        "$SCRIPT_DIR/packetbeat.base.json"
}

check_existing() {
    local path service
    for path in "$ROOT" "$UNIT" /etc/packetbeat /var/lib/packetbeat /usr/share/packetbeat /opt/Elastic/Agent; do
        [[ ! -e $path && ! -L $path ]] || fail "Existing installation or partial state: $path. Nothing will be overwritten."
    done
    for service in cloud-soc-packetbeat packetbeat elastic-agent; do
        [[ $(systemctl show "$service.service" -p LoadState --value) == not-found ]] || fail "Existing service: $service"
    done
    ! pgrep -x packetbeat >/dev/null || fail 'Packetbeat is already running.'
    ! pgrep -x elastic-agent >/dev/null || fail 'Elastic Agent is already running; review capture ownership first.'
}

verify_archive() {
    local actual
    [[ $2 =~ ^[a-f0-9]{128}$ ]] || fail 'Invalid pinned SHA-512.'
    actual=$(sha512sum "$1"); actual=${actual%% *}
    [[ $actual == "$2" ]] || fail 'SHA-512 mismatch; download will not be executed.'
}

beat() {
    "$ROOT/packetbeat/packetbeat" --path.home "$ROOT/packetbeat" --path.config "$ROOT" \
        --path.data "$ROOT/data" --path.logs "$ROOT/logs" -c "$ROOT/packetbeat.yml" "$@"
}

finish() {
    local status=$?
    if ((status != 0)); then
        if $SERVICE_CREATED; then systemctl disable --now cloud-soc-packetbeat.service || true; fi
        printf 'Installation failed; protected partial state remains in %s. No automatic cleanup.\n' "$ROOT" >&2
    fi
}

install_agent() {
    [[ $EUID == 0 ]] || fail 'Run with sudo (not required for --dry-run).'
    [[ -f /etc/os-release ]] || fail 'Ubuntu 22.04 is required.'
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 22.04 && -d /run/systemd/system ]] || fail 'Only Ubuntu 22.04 with systemd is supported.'
    local tool arch hash package member
    for tool in curl tar sha512sum systemctl pgrep timeout sed; do
        command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"
    done
    [[ -t 0 ]] || fail 'An interactive terminal is required for the API key prompt.'
    check_existing
    [[ -f $CA && -r $CA ]] || fail 'CA is not a readable file.'
    [[ $DEVICE == any || -d /sys/class/net/$DEVICE ]] || fail "Interface not found: $DEVICE"
    case "$(uname -m)" in
        x86_64) arch=x86_64; hash=b7d05725a1c3dd257d9437e3b1026e390ad14d1443701dccbbb7d99c649469fc124f0123d93e0b580bc7edb29a0fa99b27573455e0f282d2d9732f0d6e8589f8 ;;
        aarch64) arch=arm64; hash=fcbbbae7fee76a145150af78c239fdcbe5617e61c431ec8102cddb8c3d8251803cd670ed7a848435df56857daae8621f27bbc2c3cff2adcaf3cb3eb54a428e6e ;;
        *) fail 'Only x86_64 and aarch64 are supported.' ;;
    esac
    package="packetbeat-$BEAT_VERSION-linux-$arch"
    umask 077
    mkdir -m 700 "$ROOT"
    trap finish EXIT
    mkdir "$ROOT/data" "$ROOT/logs" "$ROOT/staging"
    cp -- "$SCRIPT_DIR/privacy.js" "$ROOT/privacy.js"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 600 --retry 2 \
        "https://artifacts.elastic.co/downloads/beats/packetbeat/$package.tar.gz" -o "$ROOT/package.tar.gz"
    verify_archive "$ROOT/package.tar.gz" "$hash"
    tar -tzf "$ROOT/package.tar.gz" > "$ROOT/archive-members.txt"
    while IFS= read -r member; do
        [[ $member == "$package/"* && $member != */../* && $member != */.. ]] || fail 'Unexpected archive path.'
    done < "$ROOT/archive-members.txt"
    tar -xzf "$ROOT/package.tar.gz" --no-same-owner -C "$ROOT/staging"
    mv "$ROOT/staging/$package" "$ROOT/packetbeat"
    cp -- "$CA" "$ROOT/ca.crt"
    printf '{}\n' > "$ROOT/packetbeat.yml"
    beat keystore create
    printf '%s\n' 'Enter the network-only publisher API key as id:api_key (not encoded).'
    beat keystore add CLOUD_SOC_NETWORK_API_KEY
    render_config > "$ROOT/packetbeat.yml"
    beat test config
    timeout 90 "$ROOT/packetbeat/packetbeat" --path.home "$ROOT/packetbeat" --path.config "$ROOT" \
        --path.data "$ROOT/data" --path.logs "$ROOT/logs" -c "$ROOT/packetbeat.yml" test output
    (
        set -o noclobber
        printf '%s\n' '[Unit]' 'Description=Cloud SOC Packetbeat metadata collector' 'Wants=network-online.target' 'After=network-online.target' \
            '[Service]' 'Type=simple' 'User=root' 'UMask=0077' \
            "ExecStart=$ROOT/packetbeat/packetbeat --environment=systemd --path.home $ROOT/packetbeat --path.config $ROOT --path.data $ROOT/data --path.logs $ROOT/logs -c $ROOT/packetbeat.yml" \
            'Restart=on-failure' 'RestartSec=10' 'NoNewPrivileges=true' 'CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN' \
            'ProtectSystem=strict' 'ProtectHome=true' 'PrivateTmp=true' \
            "ReadWritePaths=$ROOT/data $ROOT/logs" '[Install]' 'WantedBy=multi-user.target' > "$UNIT"
    )
    SERVICE_CREATED=true
    chmod 644 "$UNIT"
    systemctl daemon-reload
    systemctl enable --now cloud-soc-packetbeat.service
    sleep 3
    systemctl is-active --quiet cloud-soc-packetbeat.service || fail 'Packetbeat did not remain active; inspect its logs.'
    printf '%s\n' 'Packetbeat is active. Metadata only; no PCAP storage. Verify real documents in soc-network-linux-*; startup/TLS checks do not prove ingestion.'
}

main() {
    parse_args "$@"
    validate_args
    if $DRY_RUN; then
        render_config
        printf '%s\n' 'DRY RUN: no download, writes, interface access, capture, network, keystore or service changes.' >&2
        return
    fi
    install_agent
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

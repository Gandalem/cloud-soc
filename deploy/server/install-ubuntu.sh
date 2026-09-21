#!/bin/sh
# New Ubuntu central server only. Never pipe a remote script into this installer.
set -eu

usage() {
    printf '%s\n' \
        'Usage: sudo sh deploy/server/install-ubuntu.sh [options]' \
        '  --host HOST        Public DNS/IPv4 used by administrators and agents' \
        '  --bind-ip IP       IPv4 on this Ubuntu host (default: prompt / loopback)' \
        '  --dry-run          Print the plan only; no root, writes, downloads or checks' \
        '  --prepare-only     Install dependencies and prepare state; do not start the SOC stack' \
        '  --yes              Confirm host changes (admin password still requires a terminal)' \
        '  --help             Show this help' \
        'Ubuntu Server 22.04, 24.04 and 26.04 LTS (amd64/arm64, systemd).' \
        'Existing server state is never overwritten. No firewall rules are changed.'
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
has_command() { command -v "$1" >/dev/null 2>&1; }
path_exists() { [ -e "$1" ] || [ -L "$1" ]; }
installed() { [ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" = 'install ok installed' ]; }

valid_ipv4() {
    printf '%s\n' "$1" | awk '
        /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            n = split($0, parts, ".")
            for (i = 1; i <= n; i++) {
                if (parts[i] > 255 || length(parts[i]) > 3 || (length(parts[i]) > 1 && substr(parts[i],1,1) == "0")) exit 1
            }
            ok = 1
        }
        END { if (!ok || NR != 1) exit 1 }'
}

validate_addresses() {
    if [ -n "$HOST" ]; then
        case "$HOST" in
            *[!a-zA-Z0-9.-]*|'') die 'Host must be a DNS name or IPv4, without scheme, port or path.' ;;
        esac
        [ "${#HOST}" -le 253 ] || die 'Host name is too long.'
        case "$HOST" in
            *[!0-9.]*)
                printf '%s\n' "$HOST" | awk -F. '{for(i=1;i<=NF;i++) if(length($i)<1 || length($i)>63 || $i !~ /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/) exit 1}' || die 'Invalid DNS name.'
                ;;
            *) valid_ipv4 "$HOST" || die 'Invalid public IPv4.'
               [ "$HOST" != '0.0.0.0' ] || die 'Public host cannot be 0.0.0.0.' ;;
        esac
        HOST=$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')
    fi
    if [ -n "$BIND_IP" ]; then
        valid_ipv4 "$BIND_IP" || die 'Invalid bind IPv4.'
        [ "$BIND_IP" != '0.0.0.0' ] || die 'Specify a concrete local interface IP, not 0.0.0.0.'
    fi
}

show_plan() {
    printf '%s\n' \
        "Public host: ${HOST:-<prompt required>}" \
        "Local bind IP: ${BIND_IP:-<prompt; blank selects 127.0.0.1>}" \
        "State: $STATE" \
        "Ubuntu release/suite: ${UBUNTU_VERSION:-<checked at install>} / ${UBUNTU_SUITE:-<checked at install>}" \
        '1. Require Ubuntu 22.04/24.04/26.04 LTS, systemd, root, >=6 GiB RAM and >=10 GiB free disk.' \
        '2. Reject existing state/stack, occupied TCP 443/5601/9200, nonlocal bind IP.' \
        '3. Install missing ca-certificates, curl, git, python3 and openssl using APT.' \
        '4. Reuse a running local Docker + Compose plugin, or install Docker CE from its official signed APT repository.' \
        '5. Raise vm.max_map_count to 1048576 if needed; never lower a higher value.' \
        '6. Prompt for the admin password; generate CA, secrets and a public CA export.'
    if [ "$PREPARE_ONLY" = yes ]; then
        printf '%s\n' '7. Stop before starting the SOC containers (a newly installed Docker daemon will run).'
    else
        printf '%s\n' '7. Build/start the central Compose stack and check bootstrap plus local HTTPS endpoints.'
    fi
    printf '%s\n' \
        'Restrict AWS security groups to approved source IPs BEFORE installation.' \
        'No agent installation, packet capture, firewall changes, package removal or data deletion.'
}

confirm_installation() {
    [ "$YES" != yes ] || return 0
    printf 'APT packages, Docker and host settings may change. Confirm approved IP restrictions and type y/yes/INSTALL (default: no): '
    read -r CONFIRM || die 'Installation was not confirmed; no changes made.'
    case "$CONFIRM" in
        [Yy]|[Yy][Ee][Ss]|INSTALL) ;;
        *) die 'Installation was not confirmed; no changes made.' ;;
    esac
}

check_ubuntu_release() {
    [ "${ID:-}" = ubuntu ] || die "Ubuntu Server is required (detected ID: ${ID:-unknown}). Derivative distributions are not supported."
    UBUNTU_VERSION=${VERSION_ID:-}
    # Match Docker's supported LTS releases; never use jammy packages on a newer OS.
    # Review this list against https://docs.docker.com/engine/install/ubuntu/ when adding releases.
    case "$UBUNTU_VERSION" in
        22.04) EXPECTED_SUITE=jammy ;;
        24.04) EXPECTED_SUITE=noble ;;
        26.04) EXPECTED_SUITE=resolute ;;
        *) die "Ubuntu ${UBUNTU_VERSION:-unknown} is not supported by this installer. Use Ubuntu 22.04, 24.04 or 26.04 LTS. Older, interim and unvalidated future releases are not automatically installed." ;;
    esac
    UBUNTU_SUITE=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
    [ "$UBUNTU_SUITE" = "$EXPECTED_SUITE" ] || die "Ubuntu $UBUNTU_VERSION must use codename $EXPECTED_SUITE, not '${UBUNTU_SUITE:-missing}'. Check /etc/os-release; no repository was changed."
    if [ -n "${VERSION_CODENAME:-}" ] && [ "$VERSION_CODENAME" != "$EXPECTED_SUITE" ]; then
        die 'Conflicting Ubuntu codenames in /etc/os-release; no repository was changed.'
    fi
}

check_platform() {
    [ "$(id -u)" = 0 ] || die 'Run with sudo on the Ubuntu server.'
    [ -f /etc/os-release ] || die 'Missing /etc/os-release.'
    ID= VERSION_ID= VERSION_CODENAME= UBUNTU_CODENAME=
    # This file is part of the trusted, root-managed operating system.
    . /etc/os-release
    check_ubuntu_release
    [ -d /run/systemd/system ] || die 'A running systemd host is required, not a container/chroot.'
    for tool in apt-get dpkg-query dpkg ip ss sysctl flock awk df stat mktemp systemctl; do
        has_command "$tool" || die "Missing base Ubuntu tool: $tool. Use a standard supported Ubuntu Server image."
    done
    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in amd64|arm64) ;; *) die 'Only amd64 and arm64 are supported.' ;; esac
}

check_fresh_state() {
    [ ! -L "$ROOT/state" ] || die 'state/ must not be a symlink.'
    if path_exists "$STATE"; then
        die 'state/server already exists. Do not rerun or regenerate credentials. Use the documented Compose recovery commands.'
    fi
    for item in deploy/server/prepare.py deploy/server/compose.yaml deploy/server/Dockerfile; do
        [ -f "$ROOT/$item" ] || die "Incomplete checkout: $item"
    done
}

check_resources_and_network() {
    awk '/^MemTotal:/ { found=1; if ($2 < 6291456) exit 1 } END { if (!found) exit 1 }' /proc/meminfo || die 'At least 6 GiB RAM is required; use an 8 GiB or larger instance.'
    FREE_KB=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
    case "$FREE_KB" in ''|*[!0-9]*) die 'Cannot check available disk space.' ;; esac
    [ "$FREE_KB" -ge 10485760 ] || die 'At least 10 GiB free disk is required before downloads.'
    ADDRESSES=$(ip -4 -o address show) || die 'Cannot enumerate local IPv4 addresses.'
    printf '%s\n' "$ADDRESSES" | awk -v wanted="$BIND_IP" '{split($4, address, "/"); if (address[1] == wanted) found=1} END {exit !found}' || die 'Bind IP is not on this server. On EC2 use the private IPv4, not the NAT public IPv4.'
    LISTENERS=$(ss -H -ltn) || die 'Cannot enumerate listening sockets.'
    if printf '%s\n' "$LISTENERS" | awk '$4 ~ /:(443|5601|9200)$/ {found=1} END {exit !found}'; then
        die 'TCP 443, 5601 or 9200 is already in use. Existing services will not be stopped.'
    fi
}

docker_local() { docker --host unix:///var/run/docker.sock "$@"; }
compose() (
    # Shell overrides must not redirect the reviewed stack to a different state/host.
    unset SOC_PUBLIC_HOST SOC_BIND_IP SOC_STATE_DIR COMPOSE_PROFILES COMPOSE_FILE COMPOSE_PROJECT_NAME
    docker_local compose --project-name cloud-soc-central --env-file "$STATE/compose.env" -f "$ROOT/deploy/server/compose.yaml" "$@"
)

check_docker_stack() {
    docker_local info >/dev/null 2>&1 || die 'Existing local Docker must be running and accessible. No remote Docker context is used.'
    docker_local compose version >/dev/null 2>&1 || die 'Existing Docker requires a working Compose v2+ plugin; install it through the approved repository first.'
    EXISTING=$(docker_local ps -aq --filter label=com.docker.compose.project=cloud-soc-central) || die 'Cannot inspect Docker containers.'
    [ -z "$EXISTING" ] || die 'Existing cloud-soc-central containers found; use the recovery/upgrade procedure.'
    VOLUMES=$(docker_local volume ls --format '{{.Name}}') || die 'Cannot inspect Docker volumes.'
    if printf '%s\n' "$VOLUMES" | grep -q '^cloud-soc-central_'; then
        die 'Existing central volumes found. Keep their credentials and data; do not initialize a new CA/password set.'
    fi
}

render_docker_source() {
    case "${UBUNTU_SUITE:-}" in jammy|noble|resolute) ;; *) die 'Validate the Ubuntu release before generating the Docker repository.' ;; esac
    printf '%s\n' 'Types: deb' 'URIs: https://download.docker.com/linux/ubuntu' \
        "Suites: $UBUNTU_SUITE" 'Components: stable' "Architectures: $ARCH" "Signed-By: $KEY_FILE"
}

check_repository() {
    for directory in "$APT_ROOT/keyrings" "$APT_ROOT/sources.list.d"; do
        [ ! -L "$directory" ] || die "APT directory must not be a symlink: $directory"
        if path_exists "$directory"; then
            [ -d "$directory" ] || die "Not an APT directory: $directory"
        fi
    done
    for source in "$APT_ROOT/sources.list" "$APT_ROOT"/sources.list.d/*.list "$APT_ROOT"/sources.list.d/*.sources; do
        [ -f "$source" ] || continue
        [ "$source" = "$SOURCE_FILE" ] && continue
        if grep -q 'download\.docker\.com' "$source"; then
            die "Existing Docker APT source: $source. Review/install Docker from that source manually; it will not be overwritten."
        fi
    done
    if path_exists "$SOURCE_FILE"; then
        [ ! -L "$SOURCE_FILE" ] && [ -f "$SOURCE_FILE" ] || die 'Unsafe existing Docker source file.'
        [ "$(stat -c '%u:%a' "$SOURCE_FILE")" = '0:644' ] || die 'Existing Docker source must be root-owned mode 0644.'
        [ "$(render_docker_source)" = "$(cat "$SOURCE_FILE")" ] || die 'Existing installer-managed Docker source differs; review it manually.'
        [ -f "$KEY_FILE" ] || die 'Docker source exists without its signing key.'
    fi
    if path_exists "$KEY_FILE"; then
        [ ! -L "$KEY_FILE" ] && [ -f "$KEY_FILE" ] && [ -s "$KEY_FILE" ] || die 'Unsafe existing Docker signing key.'
        [ "$(stat -c '%u:%a' "$KEY_FILE")" = '0:644' ] || die 'Existing Docker signing key must be root-owned mode 0644.'
    fi
}

detect_docker() {
    INSTALL_DOCKER=no
    if has_command docker; then
        check_docker_stack
        return
    fi
    for package in docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc docker-ce docker-ce-cli containerd.io; do
        installed "$package" && die "Existing package $package needs manual review; no automatic removal/replacement."
    done
    INSTALL_DOCKER=yes
    check_repository
}

install_packages() {
    MISSING=
    for package in ca-certificates curl git python3 openssl; do
        if ! installed "$package"; then MISSING="$MISSING $package"; fi
    done
    if [ -n "$MISSING" ]; then
        apt-get update
        # MISSING contains only the fixed package names above, never user input.
        apt-get install -y --no-remove --no-upgrade --no-install-recommends $MISSING
    fi
}

install_docker() {
    [ "$INSTALL_DOCKER" = yes ] || return 0
    check_repository
    TEMP=$(mktemp -d /tmp/cloud-soc-server.XXXXXXXX)
    if ! path_exists "$KEY_FILE"; then
        curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 120 \
            https://download.docker.com/linux/ubuntu/gpg -o "$TEMP/docker.asc"
        [ -s "$TEMP/docker.asc" ] || die 'Empty Docker signing key download.'
        grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----' "$TEMP/docker.asc" || die 'Invalid Docker signing key response.'
        if ! path_exists "$APT_ROOT/keyrings"; then install -d -m 0755 "$APT_ROOT/keyrings"; fi
        # Exclusive creation: never truncate an existing path or follow a symlink.
        (set -C; cat "$TEMP/docker.asc" > "$KEY_FILE")
        chmod 0644 "$KEY_FILE"
    fi
    if ! path_exists "$SOURCE_FILE"; then
        (set -C; render_docker_source > "$SOURCE_FILE")
        chmod 0644 "$SOURCE_FILE"
    fi
    apt-get update
    apt-get install -y --no-remove --no-upgrade --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    check_docker_stack
}

check_kernel_config() {
    if path_exists "$SYSCTL_FILE"; then
        [ ! -L "$SYSCTL_FILE" ] && [ -f "$SYSCTL_FILE" ] || die 'Unsafe existing sysctl configuration.'
        [ "$(cat "$SYSCTL_FILE")" = 'vm.max_map_count=1048576' ] || die 'Existing sysctl file differs; it will not be overwritten.'
    fi
}

configure_kernel() {
    check_kernel_config
    MAP_COUNT=$(sysctl -n vm.max_map_count)
    case "$MAP_COUNT" in ''|*[!0-9]*) die 'Cannot read vm.max_map_count.' ;; esac
    if [ "$MAP_COUNT" -lt 1048576 ]; then
        if ! path_exists "$SYSCTL_FILE"; then
            (set -C; printf '%s\n' 'vm.max_map_count=1048576' > "$SYSCTL_FILE")
            chmod 0644 "$SYSCTL_FILE"
        fi
        sysctl -w vm.max_map_count=1048576
    fi
}

prepare_state() {
    check_fresh_state
    python3 "$ROOT/deploy/server/prepare.py" --host "$HOST" --bind-ip "$BIND_IP"
    # The export remains inside protected state; the guide copies only this public file.
    openssl x509 -in "$STATE/tls/ca.crt" -outform DER -out "$STATE/tls/ca.cer"
    chmod 0644 "$STATE/tls/ca.cer"
    printf '%s\n' 'Public DER certificate SHA-256 (not a private key):'
    sha256sum "$STATE/tls/ca.cer"
}

start_stack() {
    compose config --quiet
    compose up -d --build
}

http_status() {
    curl --silent --noproxy '*' --cacert "$STATE/tls/ca.crt" --resolve "$HOST:$1:$BIND_IP" \
        --connect-timeout 2 --max-time 4 --output /dev/null --write-out '%{http_code}' "https://$HOST:$1$2" || true
}

check_ready() {
    BOOTSTRAP_ID=$(compose ps -aq bootstrap)
    [ -n "$BOOTSTRAP_ID" ] || die 'Bootstrap container not found.'
    [ "$(docker_local inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$BOOTSTRAP_ID")" = 'exited:0' ] || die 'Bootstrap did not exit successfully.'
    DEADLINE=$(($(date +%s) + 300))
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        ES_CODE=$(http_status 9200 /)
        PORTAL_CODE=$(http_status 443 /api/portal)
        KIBANA_CODE=$(http_status 5601 /login)
        if [ "$ES_CODE" = 401 ] && [ "$PORTAL_CODE" = 401 ] && [ "$KIBANA_CODE" = 200 ]; then
            printf '%s\n' 'Local TLS/HTTP startup checks passed. Log in to the portal and verify remote ingestion separately.'
            return 0
        fi
        sleep 5
    done
    die 'HTTPS startup checks timed out. State is preserved; inspect Compose logs and do not regenerate credentials.'
}

finish() {
    RESULT=$?
    trap - 0
    if [ -n "${TEMP:-}" ]; then
        rm -f "$TEMP/docker.asc"
        rmdir "$TEMP" 2>/dev/null || true
    fi
    if [ "$RESULT" -ne 0 ]; then
        printf 'Stopped during: %s. Existing/partial state was not removed.\n' "${STAGE:-arguments}" >&2
        printf '%s\n' 'For a prepared server, use the Compose config/up/logs commands in deploy/server/README.md.' >&2
    fi
    exit "$RESULT"
}

main() {
    HOST= BIND_IP= DRY_RUN=no PREPARE_ONLY=no YES=no TEMP= STAGE=arguments
    UBUNTU_VERSION= UBUNTU_SUITE=
    APT_ROOT=/etc/apt
    KEY_FILE=$APT_ROOT/keyrings/cloud-soc-docker.asc
    SOURCE_FILE=$APT_ROOT/sources.list.d/cloud-soc-docker.sources
    SYSCTL_FILE=/etc/sysctl.d/90-cloud-soc.conf
    ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
    STATE=$ROOT/state/server
    trap finish 0
    trap 'exit 130' INT
    trap 'exit 143' TERM
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --host) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$HOST" ] || die 'Provide --host once, with a value.'; HOST=$2; shift 2 ;;
            --bind-ip) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$BIND_IP" ] || die 'Provide --bind-ip once, with a value.'; BIND_IP=$2; shift 2 ;;
            --dry-run) DRY_RUN=yes; shift ;;
            --prepare-only) PREPARE_ONLY=yes; shift ;;
            --yes) YES=yes; shift ;;
            --help|-h) usage; return 0 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    validate_addresses
    if [ "$DRY_RUN" = yes ]; then
        printf '%s\n' 'DRY RUN: plan only; actual OS, addresses, files, ports and dependencies have NOT been checked.'
        show_plan
        return 0
    fi
    # Root operations use system tools, a local Docker socket and no inherited Docker endpoint.
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
    umask 077
    STAGE=preflight
    check_platform
    case "$ROOT" in *[!a-zA-Z0-9_./-]*) die 'Use a repository path without spaces, special characters or non-ASCII text.' ;; esac
    [ -t 0 ] && [ -t 1 ] || die 'Use an interactive SSH terminal; passwords cannot be passed as command-line arguments or piped input.'
    if [ -z "$HOST" ]; then
        printf 'Public DNS/IPv4 reachable by your PC (without https://): '
        read -r HOST
    fi
    if [ -z "$BIND_IP" ]; then
        ip -4 -brief address
        printf 'Local bind IPv4 (EC2 private IPv4; blank = 127.0.0.1): '
        read -r BIND_IP
        BIND_IP=${BIND_IP:-127.0.0.1}
    fi
    [ -n "$HOST" ] || die 'Public host is required.'
    validate_addresses
    check_fresh_state
    check_resources_and_network
    detect_docker
    check_kernel_config
    show_plan
    confirm_installation
    # Serialize this installer, including a retry launched from another checkout.
    exec 9>/run/lock/cloud-soc-central-install.lock
    flock -n 9 || die 'Another central installation is running.'
    check_fresh_state
    check_resources_and_network
    detect_docker
    check_kernel_config
    STAGE=packages
    install_packages
    STAGE=docker
    install_docker
    STAGE=kernel
    configure_kernel
    STAGE=certificates
    prepare_state
    if [ "$PREPARE_ONLY" != yes ]; then
        STAGE=compose
        start_stack
        STAGE=readiness
        check_ready
    fi
    printf '\nPortal: https://%s\nKibana: https://%s:5601\nReceiver: https://%s:9200\n' "$HOST" "$HOST" "$HOST"
    printf '%s\n' 'Trust the verified public CA first. Keep private/ and secrets/ on the server.' \
        'Next: docs/aws_windows_e2e_test.md section 6 (Windows CA trust and agent testing).'
}

# RUN INSTALLER
main "$@"

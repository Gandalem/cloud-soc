#!/bin/sh
# New Ubuntu central server only. Never pipe a remote script into this installer.
set -eu

usage() {
    printf '%s\n' \
        '사용법: sudo sh deploy/server/install-ubuntu.sh [옵션]' \
        '  --host HOST        대시보드 접속 DNS/IPv4' \
        '  --agent-host HOST  에이전트가 접속할 HTTPS 9200 주소 (기본: --host)' \
        '  --bind-ip IP       이 Ubuntu 서버에 실제 할당된 IPv4' \
        '  --dry-run          설치 계획만 표시. 변경·다운로드·환경 검사는 실행하지 않음' \
        '  --prepare-only     필수 프로그램과 인증서만 준비. SOC 서버는 시작하지 않음' \
        '  --yes              설치 확인 생략. 관리자 비밀번호는 터미널에서 직접 입력' \
        '  --help             도움말 표시' \
        '지원: Ubuntu Server 22.04·24.04·26.04 LTS (amd64/arm64, systemd).' \
        '기존 서버 설정을 덮어쓰거나 방화벽 규칙을 변경하지 않습니다.'
}

die() { printf '오류: %s\n' "$*" >&2; exit 1; }
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
            *[!a-zA-Z0-9.-]*|'') die 'DNS 이름 또는 IPv4를 입력하세요. https://, 포트, 경로는 빼세요.' ;;
        esac
        [ "${#HOST}" -le 253 ] || die 'DNS 이름은 253자 이내로 입력하세요.'
        case "$HOST" in
            *[!0-9.]*)
                printf '%s\n' "$HOST" | awk -F. '{for(i=1;i<=NF;i++) if(length($i)<1 || length($i)>63 || $i !~ /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/) exit 1}' || die 'DNS 이름 형식이 올바르지 않습니다.'
                ;;
            *) valid_ipv4 "$HOST" || die '접속 IPv4 형식이 올바르지 않습니다.'
               [ "$HOST" != '0.0.0.0' ] || die '접속 주소에 0.0.0.0은 사용할 수 없습니다.' ;;
        esac
        HOST=$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')
    fi
    if [ -n "$BIND_IP" ]; then
        valid_ipv4 "$BIND_IP" || die '바인딩 IPv4 형식이 올바르지 않습니다.'
        [ "$BIND_IP" != '0.0.0.0' ] || die '바인딩 주소에는 서버에 할당된 IPv4를 입력하세요. 0.0.0.0은 사용할 수 없습니다.'
    fi
}

show_plan() {
    printf '%s\n' \
        "대시보드 주소: ${HOST:-<입력 필요>}" \
        "에이전트 수신 주소: ${AGENT_HOST:-${HOST:-<대시보드와 동일>}}" \
        "서버 바인딩 IP: ${BIND_IP:-<입력 필요; 빈 값은 127.0.0.1>}" \
        "설정 저장 위치: $STATE" \
        "Ubuntu 버전/코드명: ${UBUNTU_VERSION:-<설치 시 확인>} / ${UBUNTU_SUITE:-<설치 시 확인>}" \
        '1. Ubuntu LTS·systemd·관리자 권한·런타임 메모리 예산(8 GiB급)·디스크 여유 10 GiB 이상을 확인합니다.' \
        '2. 기존 설치와 TCP 443/5601/9200 포트 충돌을 확인합니다.' \
        '3. 누락된 ca-certificates·curl·git·python3·openssl을 설치합니다.' \
        '4. 기존 로컬 Docker/Compose를 사용하거나 공식 서명 저장소에서 설치합니다.' \
        '5. 필요하면 vm.max_map_count를 1048576으로 올립니다.' \
        '6. Portal 관리자 비밀번호와 인증서를 준비하고 신규 에이전트 설치 토큰 기능을 활성화합니다.'
    if [ "$PREPARE_ONLY" = yes ]; then
        printf '%s\n' '7. SOC 컨테이너 기동 전 종료합니다. 새로 설치한 Docker 서비스는 실행됩니다.'
    else
        printf '%s\n' '7. 이미지를 빌드·다운로드하고 필수 워커와 서버를 시작한 뒤 HTTPS를 확인합니다.'
    fi
    printf '%s\n' \
        '클라우드 환경에서는 설치 전에 보안그룹의 접속 허용 IP를 설정하세요.' \
        '에이전트 설치·패킷 수집·방화벽 변경·기존 프로그램 및 데이터 삭제는 수행하지 않습니다.'
}

confirm_installation() {
    [ "$YES" != yes ] || return 0
    printf '필수 프로그램·Docker·호스트 설정을 변경합니다. 접속 허용 범위를 확인했다면 y/yes/INSTALL 입력 (기본: 취소): '
    read -r CONFIRM || die '설치를 취소했습니다. 변경한 항목은 없습니다.'
    case "$CONFIRM" in
        [Yy]|[Yy][Ee][Ss]|INSTALL) ;;
        *) die '설치를 취소했습니다. 변경한 항목은 없습니다.' ;;
    esac
}

check_ubuntu_release() {
    [ "${ID:-}" = ubuntu ] || die "Ubuntu Server가 필요합니다 (현재 ID: ${ID:-unknown}). 파생 배포판은 지원하지 않습니다."
    UBUNTU_VERSION=${VERSION_ID:-}
    # Match Docker's supported LTS releases; never use jammy packages on a newer OS.
    # Review this list against https://docs.docker.com/engine/install/ubuntu/ when adding releases.
    case "$UBUNTU_VERSION" in
        22.04) EXPECTED_SUITE=jammy ;;
        24.04) EXPECTED_SUITE=noble ;;
        26.04) EXPECTED_SUITE=resolute ;;
        *) die "Ubuntu ${UBUNTU_VERSION:-unknown}은 설치 대상이 아닙니다. Ubuntu Server 22.04·24.04·26.04 LTS를 사용하세요." ;;
    esac
    UBUNTU_SUITE=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
    [ "$UBUNTU_SUITE" = "$EXPECTED_SUITE" ] || die "Ubuntu $UBUNTU_VERSION의 코드명은 $EXPECTED_SUITE이어야 합니다. /etc/os-release를 확인하세요. 저장소는 변경하지 않았습니다."
    if [ -n "${VERSION_CODENAME:-}" ] && [ "$VERSION_CODENAME" != "$EXPECTED_SUITE" ]; then
        die '/etc/os-release의 Ubuntu 코드명이 서로 다릅니다. 저장소는 변경하지 않았습니다.'
    fi
}

check_platform() {
    [ "$(id -u)" = 0 ] || die 'Ubuntu 서버에서 sudo로 실행하세요.'
    [ -f /etc/os-release ] || die '/etc/os-release 파일이 없습니다.'
    ID= VERSION_ID= VERSION_CODENAME= UBUNTU_CODENAME=
    # This file is part of the trusted, root-managed operating system.
    . /etc/os-release
    check_ubuntu_release
    [ -d /run/systemd/system ] || die 'systemd가 실행 중인 서버가 필요합니다. 컨테이너·chroot에서는 설치할 수 없습니다.'
    for tool in apt-get dpkg-query dpkg ip ss sysctl flock awk df stat mktemp systemctl; do
        has_command "$tool" || die "필수 Ubuntu 도구가 없습니다: $tool. 표준 Ubuntu Server 이미지를 사용하세요."
    done
    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in amd64|arm64) ;; *) die 'amd64와 arm64만 지원합니다.' ;; esac
}

check_fresh_state() {
    [ ! -L "$ROOT/state" ] || die 'state/가 심볼릭 링크입니다. 원래 경로를 확인하세요.'
    if path_exists "$STATE"; then
        die 'state/server가 이미 있습니다. 인증서를 다시 만들지 말고 docs/runtime_deployment.md의 복구 절차를 따르세요.'
    fi
    for item in deploy/server/prepare.py deploy/server/server_cli.py deploy/server/compose.yaml deploy/server/Dockerfile; do
        [ -f "$ROOT/$item" ] || die "필수 파일이 없습니다: $item"
    done
}

check_resources_and_network() {
    awk '/^MemTotal:/ { found=1; if ($2 < 6291456) exit 1 } END { if (!found) exit 1 }' /proc/meminfo || die '메모리가 6 GiB 이상 필요합니다. 8 GiB 이상 서버를 사용하세요.'
    FREE_KB=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
    case "$FREE_KB" in ''|*[!0-9]*) die '디스크 여유 공간을 조회하지 못했습니다.' ;; esac
    [ "$FREE_KB" -ge 10485760 ] || die '다운로드 전 디스크 여유 공간이 10 GiB 이상 필요합니다.'
    ADDRESSES=$(ip -4 -o address show) || die '서버 IPv4를 조회하지 못했습니다.'
    printf '%s\n' "$ADDRESSES" | awk -v wanted="$BIND_IP" '{split($4, address, "/"); if (address[1] == wanted) found=1} END {exit !found}' || die '서버에 할당되지 않은 바인딩 IP입니다. EC2에서는 사설 IPv4를 입력하세요.'
    LISTENERS=$(ss -H -ltn) || die '사용 중인 포트를 조회하지 못했습니다.'
    if printf '%s\n' "$LISTENERS" | awk '$4 ~ /:(443|5601|9200)$/ {found=1} END {exit !found}'; then
        die 'TCP 443·5601·9200 중 사용 중인 포트가 있습니다. 기존 서비스는 중지하지 않았습니다.'
    fi
}

docker_local() { docker --host unix:///var/run/docker.sock "$@"; }
compose() (
    # Shell overrides must not redirect the reviewed stack to a different state/host.
    unset SOC_PUBLIC_HOST SOC_AGENT_ENDPOINT SOC_ELASTIC_ENDPOINT SOC_BIND_IP SOC_STATE_DIR COMPOSE_PROFILES COMPOSE_FILE COMPOSE_PROJECT_NAME
    docker_local compose --project-name cloud-soc-central --env-file "$STATE/compose.env" -f "$ROOT/deploy/server/compose.yaml" "$@"
)

check_docker_stack() {
    docker_local info >/dev/null 2>&1 || die '로컬 Docker가 실행 중이고 접근 가능해야 합니다. 오래된 CLI라면 Docker를 업데이트하세요. 원격 Docker는 사용하지 않습니다.'
    docker_local compose version >/dev/null 2>&1 || die 'Docker Compose v2.24.0 이상이 필요합니다. 공식 저장소를 통해 플러그인을 설치·업데이트하세요.'
    check_runtime_compatibility
    EXISTING=$(docker_local ps -aq --filter label=com.docker.compose.project=cloud-soc-central) || die 'Docker 컨테이너를 조회하지 못했습니다.'
    [ -z "$EXISTING" ] || die '기존 cloud-soc-central 컨테이너가 있습니다. 복구·업그레이드 절차를 따르세요.'
    VOLUMES=$(docker_local volume ls --format '{{.Name}}') || die 'Docker 볼륨을 조회하지 못했습니다.'
    if printf '%s\n' "$VOLUMES" | grep -q '^cloud-soc-central_'; then
        die '기존 중앙 서버 볼륨이 있습니다. 데이터와 자격 증명을 보존하고 기존 서버 복구 절차를 따르세요.'
    fi
}

check_runtime_compatibility() {
    python3 "$ROOT/deploy/server/check-dependencies.py"
}

render_docker_source() {
    case "${UBUNTU_SUITE:-}" in jammy|noble|resolute) ;; *) die 'Docker 저장소를 만들기 전에 Ubuntu 버전과 코드명을 확인하세요.' ;; esac
    printf '%s\n' 'Types: deb' 'URIs: https://download.docker.com/linux/ubuntu' \
        "Suites: $UBUNTU_SUITE" 'Components: stable' "Architectures: $ARCH" "Signed-By: $KEY_FILE"
}

check_repository() {
    for directory in "$APT_ROOT/keyrings" "$APT_ROOT/sources.list.d"; do
        [ ! -L "$directory" ] || die "APT 경로가 심볼릭 링크입니다: $directory"
        if path_exists "$directory"; then
            [ -d "$directory" ] || die "APT 디렉터리가 아닙니다: $directory"
        fi
    done
    for source in "$APT_ROOT/sources.list" "$APT_ROOT"/sources.list.d/*.list "$APT_ROOT"/sources.list.d/*.sources; do
        [ -f "$source" ] || continue
        [ "$source" = "$SOURCE_FILE" ] && continue
        if grep -q 'download\.docker\.com' "$source"; then
            die "기존 Docker APT 저장소가 있습니다: $source. 덮어쓰지 않았습니다. 기존 저장소에서 Docker를 설치하세요."
        fi
    done
    if path_exists "$SOURCE_FILE"; then
        [ ! -L "$SOURCE_FILE" ] && [ -f "$SOURCE_FILE" ] || die '기존 Docker 저장소 파일의 형식·링크를 확인하세요.'
        [ "$(stat -c '%u:%a' "$SOURCE_FILE")" = '0:644' ] || die '기존 Docker 저장소 파일은 root 소유·권한 0644여야 합니다.'
        [ "$(render_docker_source)" = "$(cat "$SOURCE_FILE")" ] || die '기존 Docker 저장소 파일 내용이 다릅니다. 덮어쓰지 않았습니다.'
        [ -f "$KEY_FILE" ] || die 'Docker 저장소의 서명 키가 없습니다.'
    fi
    if path_exists "$KEY_FILE"; then
        [ ! -L "$KEY_FILE" ] && [ -f "$KEY_FILE" ] && [ -s "$KEY_FILE" ] || die '기존 Docker 서명 키의 형식·링크를 확인하세요.'
        [ "$(stat -c '%u:%a' "$KEY_FILE")" = '0:644' ] || die '기존 Docker 서명 키는 root 소유·권한 0644여야 합니다.'
    fi
}

detect_docker() {
    INSTALL_DOCKER=no
    if has_command docker; then
        check_docker_stack
        return
    fi
    for package in docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc docker-ce docker-ce-cli containerd.io; do
        installed "$package" && die "기존 패키지를 확인하세요: $package. 자동 삭제·교체하지 않았습니다."
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
        [ -s "$TEMP/docker.asc" ] || die '다운로드한 Docker 서명 키가 비어 있습니다.'
        grep -q '^-----BEGIN PGP PUBLIC KEY BLOCK-----' "$TEMP/docker.asc" || die '다운로드한 Docker 서명 키의 형식이 올바르지 않습니다.'
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
        [ ! -L "$SYSCTL_FILE" ] && [ -f "$SYSCTL_FILE" ] || die '기존 커널 설정 파일의 형식·링크를 확인하세요.'
        [ "$(cat "$SYSCTL_FILE")" = 'vm.max_map_count=1048576' ] || die '기존 커널 설정 파일 내용이 다릅니다. 덮어쓰지 않았습니다.'
    fi
}

configure_kernel() {
    check_kernel_config
    MAP_COUNT=$(sysctl -n vm.max_map_count)
    case "$MAP_COUNT" in ''|*[!0-9]*) die 'vm.max_map_count 값을 읽지 못했습니다.' ;; esac
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
    if [ -n "${AGENT_HOST:-}" ]; then
        python3 "$ROOT/deploy/server/prepare.py" --host "$HOST" --agent-host "$AGENT_HOST" --bind-ip "$BIND_IP"
    else
        python3 "$ROOT/deploy/server/prepare.py" --host "$HOST" --bind-ip "$BIND_IP"
    fi
    # The export remains inside protected state; the guide copies only this public file.
    openssl x509 -in "$STATE/tls/ca.crt" -outform DER -out "$STATE/tls/ca.cer"
    chmod 0644 "$STATE/tls/ca.cer"
    printf '%s\n' '공개 DER 인증서 SHA-256 (개인키가 아닙니다):'
    sha256sum "$STATE/tls/ca.cer"
}

start_stack() {
    python3 "$ROOT/deploy/server/manage.py" install --workspace "$ROOT" --state "$STATE" --build
}

http_status() {
    curl --silent --noproxy '*' --cacert "$STATE/tls/ca.crt" --resolve "$HOST:$1:$BIND_IP" \
        --connect-timeout 2 --max-time 4 --output /dev/null --write-out '%{http_code}' "https://$HOST:$1$2" || true
}

check_ready() {
    printf '%s\n' '[설치] 서버 구성과 HTTPS 접속 준비를 확인합니다.'
    python3 "$ROOT/deploy/server/manage.py" verify --state "$STATE" --startup-only
    DEADLINE=$(($(date +%s) + 300))
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        ES_CODE=$(http_status 9200 /)
        PORTAL_CODE=$(http_status 443 /api/portal)
        KIBANA_CODE=$(http_status 5601 /login)
        if [ "$ES_CODE" = 401 ] && [ "$PORTAL_CODE" = 401 ] && [ "$KIBANA_CODE" = 200 ]; then
            printf '%s\n' '서버의 TLS/HTTP 기동 확인을 통과했습니다. 다음으로 Portal에서 에이전트를 등록하고 실제 수신을 확인하세요.'
            return 0
        fi
        sleep 5
    done
    die 'HTTPS 기동 확인 시간이 초과됐습니다. 기존 설정은 보존됐습니다. Compose 로그를 확인하고 인증서를 다시 만들지 마세요.'
}

finish() {
    RESULT=$?
    trap - 0
    if [ -n "${TEMP:-}" ]; then
        rm -f "$TEMP/docker.asc"
        rmdir "$TEMP" 2>/dev/null || true
    fi
    if [ "$RESULT" -ne 0 ]; then
        case "${STAGE:-arguments}" in
            arguments) LABEL='입력';; preflight) LABEL='설치 조건';; packages) LABEL='필수 프로그램';;
            docker) LABEL='Docker';; kernel) LABEL='커널 설정';; certificates) LABEL='인증서';;
            compose) LABEL='서버 구성';; readiness) LABEL='HTTPS 접속';; *) LABEL='알 수 없음';;
        esac
        printf '설치 중단 단계: %s. 기존 설정과 부분 설치 상태는 보존됐습니다.\n' "$LABEL" >&2
        printf '%s\n' '인증서 준비 후 실패했다면 deploy/server/README.md의 공통 관리자 복구 절차를 따르세요.' >&2
    fi
    exit "$RESULT"
}

main() {
    HOST= AGENT_HOST= BIND_IP= DRY_RUN=no PREPARE_ONLY=no YES=no TEMP= STAGE=arguments
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
            --host) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$HOST" ] || die '--host는 값과 함께 한 번만 지정하세요.'; HOST=$2; shift 2 ;;
            --agent-host) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$AGENT_HOST" ] || die '--agent-host는 값과 함께 한 번만 지정하세요.'; AGENT_HOST=$2; shift 2 ;;
            --bind-ip) [ "$#" -ge 2 ] && [ -n "$2" ] && [ -z "$BIND_IP" ] || die '--bind-ip는 값과 함께 한 번만 지정하세요.'; BIND_IP=$2; shift 2 ;;
            --dry-run) DRY_RUN=yes; shift ;;
            --prepare-only) PREPARE_ONLY=yes; shift ;;
            --yes) YES=yes; shift ;;
            --help|-h) usage; return 0 ;;
            *) die "지원하지 않는 옵션입니다. --help로 사용법을 확인하세요." ;;
        esac
    done
    validate_addresses
    if [ -n "$AGENT_HOST" ]; then
        PUBLIC_HOST=$HOST
        HOST=$AGENT_HOST
        validate_addresses
        AGENT_HOST=$HOST
        HOST=$PUBLIC_HOST
    fi
    if [ "$DRY_RUN" = yes ]; then
        printf '%s\n' '미리보기: 계획만 표시합니다. 실제 OS·주소·파일·포트·필수 프로그램은 검사하지 않았습니다.'
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
    case "$ROOT" in *[!a-zA-Z0-9_./-]*) die '저장소 경로에는 영문·숫자·밑줄·하이픈·슬래시만 사용하세요.' ;; esac
    [ -t 0 ] && [ -t 1 ] || die '대화형 SSH 터미널에서 실행하세요. 비밀번호는 명령 인자나 파이프로 전달할 수 없습니다.'
    if [ -z "$HOST" ]; then
        printf 'PC에서 접속할 대시보드 DNS/IPv4 (https:// 제외): '
        read -r HOST
    fi
    if [ -z "$BIND_IP" ]; then
        ip -4 -brief address
        printf '이 서버의 바인딩 IPv4 (EC2는 사설 IP, 빈 값은 127.0.0.1): '
        read -r BIND_IP
        BIND_IP=${BIND_IP:-127.0.0.1}
    fi
    [ -n "$HOST" ] || die '포털 접속 주소를 입력하세요.'
    validate_addresses
    check_fresh_state
    check_resources_and_network
    detect_docker
    check_kernel_config
    show_plan
    confirm_installation
    # Serialize this installer, including a retry launched from another checkout.
    exec 9>/run/lock/cloud-soc-central-install.lock
    flock -n 9 || die '다른 중앙 서버 설치가 실행 중입니다.'
    check_fresh_state
    check_resources_and_network
    detect_docker
    check_kernel_config
    STAGE=packages
    printf '%s\n' '[설치 1/5] 필수 프로그램을 준비합니다.'
    install_packages
    STAGE=docker
    printf '%s\n' '[설치 2/5] Docker 서비스를 준비합니다.'
    install_docker
    STAGE=kernel
    printf '%s\n' '[설치 3/5] 서버 커널 설정을 준비합니다.'
    configure_kernel
    STAGE=certificates
    printf '%s\n' '[설치 4/5] 관리자 비밀번호와 인증서를 준비합니다.'
    prepare_state
    if [ "$PREPARE_ONLY" != yes ]; then
        STAGE=compose
        printf '%s\n' '[설치 5/5] 이미지를 준비하고 Cloud SOC 서버를 시작합니다.'
        start_stack
        STAGE=readiness
        check_ready
    fi
    if [ "$PREPARE_ONLY" = yes ]; then
        printf '\n인증서와 필수 프로그램 준비가 완료됐습니다. SOC 서버는 아직 시작하지 않았습니다.\n'
    else
        printf '\nCloud SOC 서버 설치와 기동 확인이 완료됐습니다.\n'
    fi
    printf 'Portal 접속: https://%s\nKibana 접속: https://%s:5601\n로그 수신: https://%s:9200\n' "$HOST" "$HOST" "${AGENT_HOST:-$HOST}"
    printf '%s\n' '공개 CA 인증서의 지문을 확인하고 접속 PC에서 신뢰 등록하세요. private/와 secrets/는 서버에 보관하세요.' \
        '다음 단계: Portal에서 에이전트 설치 파일과 설치 토큰을 발급하고 실제 수신을 확인하세요.'
}

# RUN INSTALLER
main "$@"

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const script = path.join(root, 'deploy/server/install-ubuntu.sh');
const source = fs.readFileSync(script, 'utf8');
const sh = process.env.SH_EXE || (process.platform === 'win32' ? 'C:/Program Files/Git/bin/sh.exe' : 'sh');
const definitions = source.split('# RUN INSTALLER')[0];
const quote = value => `'${String(value).replace(/\\/g, '/').replace(/'/g, `'"'"'`)}'`;

// Ubuntu dash rejects hyphens in function names. Keep POSIX sh and intercept apt-get through PATH.
function aptGetStub(body = 'printf "%s\\n" "Unexpected live operation: apt-get $*" >&2; exit 97') {
  return ['cat > "$ROOT/bin/apt-get" <<\'SOC_APT_STUB\'', '#!/bin/sh', body,
    'SOC_APT_STUB', 'chmod 755 "$ROOT/bin/apt-get"', ''].join('\n');
}

function run(args, input) {
  const result = spawnSync(sh, args, { cwd: root, input, encoding: 'utf8', timeout: 15000 });
  assert.ifError(result.error);
  return result;
}

function ok(result) {
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result.stdout;
}

function fail(result, pattern) {
  assert.notEqual(result.status, 0, result.stdout);
  assert.match(result.stderr, pattern);
}

// Function tests never invoke real package managers, downloads, daemons or credentials.
function fixture(body) {
  const parent = path.join(root, 'state');
  fs.mkdirSync(parent, { recursive: true });
  const base = fs.mkdtempSync(path.join(parent, 'cloud-soc-server-test-'));
  const realBase = fs.realpathSync(base);
  try {
    const prelude = `${definitions}
ROOT=${quote(base)}
STATE=$ROOT/state/server
APT_ROOT=$ROOT/apt
KEY_FILE=$APT_ROOT/keyrings/cloud-soc-docker.asc
SOURCE_FILE=$APT_ROOT/sources.list.d/cloud-soc-docker.sources
SYSCTL_FILE=$ROOT/sysctl.conf
HOST=soc.example.invalid BIND_IP=10.0.0.5 ARCH=amd64 TEMP=
UBUNTU_VERSION=22.04 UBUNTU_SUITE=jammy
forbidden() { die "Unexpected live operation: $*"; }
mkdir -p "$ROOT/bin"
PATH="$(cd "$ROOT/bin" && pwd):$PATH"; export PATH
${aptGetStub()}
curl() { forbidden curl "$@"; }
docker() { forbidden docker "$@"; }
systemctl() { forbidden systemctl "$@"; }
sysctl() { forbidden sysctl "$@"; }
python3() { forbidden python3 "$@"; }
check_runtime_compatibility() { :; }
openssl() { forbidden openssl "$@"; }
mkdir -p "$ROOT/deploy/server" "$APT_ROOT/sources.list.d" "$APT_ROOT/keyrings"
touch "$ROOT/deploy/server/server_cli.py" "$ROOT/deploy/server/prepare.py" "$ROOT/deploy/server/compose.yaml" "$ROOT/deploy/server/Dockerfile"
`;
    return run(['-s'], prelude + '\n' + body + '\n');
  } finally {
    assert.equal(fs.realpathSync(base), realBase);
    assert.equal(path.dirname(realBase), fs.realpathSync(parent));
    assert.ok(path.basename(realBase).startsWith('cloud-soc-server-test-'));
    fs.rmSync(realBase, { recursive: true, force: true });
  }
}

test('POSIX sh syntax, LF checkout and help', () => {
  assert.ok(!source.includes('\r'), 'Keep the installer LF-only');
  const launcher = path.join(root, 'soc');
  assert.ok(!fs.readFileSync(launcher, 'utf8').includes('\r'), 'Keep the soc launcher LF-only');
  ok(run(['-n', launcher]));
  ok(run(['-n', script]));
  assert.match(ok(run([script, '--help'])), /--prepare-only/);
});

test('dashboard and receiver addresses are independent, without any installation', () => {
  const output = ok(run([script, '--dry-run', '--host', 'dashboard.example.test', '--agent-host', '192.168.32.60', '--bind-ip', '10.0.0.5']));
  assert.match(output, /대시보드 주소: dashboard\.example\.test/);
  assert.match(output, /에이전트 수신 주소: 192\.168\.32\.60/);
  for (const value of ['https://receiver:9200', 'bad-.test', 'receiver/path', '0.0.0.0', 'host\nOTHER=value']) {
    // Windows argument transport can split a newline; either path must stop.
    fail(run([script, '--dry-run', '--agent-host', value]), /DNS|IPv4|0\.0\.0\.0|지원하지 않는 옵션/);
  }
  fail(run([script, '--dry-run', '--agent-host', 'a', '--agent-host', 'b']), /한 번만/);
  assert.match(source, /unset SOC_PUBLIC_HOST SOC_AGENT_ENDPOINT SOC_ELASTIC_ENDPOINT/);
  assert.match(source, /--agent-host "\$AGENT_HOST"/);
});

test('confirmation accepts y and yes in any case, plus legacy INSTALL', () => {
  for (const answer of ['y', 'Y', 'yes', 'yeS', 'yEs', 'yES', 'Yes', 'YeS', 'YEs', 'YES', 'INSTALL']) {
    const output = ok(fixture(`
YES=no
printf '%s\\n' ${quote(answer)} | confirm_installation
printf '\\nCONFIRMED\\n'
`));
    assert.match(output, /y\/yes\/INSTALL 입력 \(기본: 취소\)/);
    assert.match(output, /\nCONFIRMED\n$/);
  }
});

test('empty, negative, unrecognized and EOF confirmation stops before installation', () => {
  for (const answer of ['', ' ', 'n', 'N', 'no', 'NO', 'true', 'yesplease', 'y;true']) {
    const result = fixture(`
YES=no
printf '%s\\n' ${quote(answer)} | confirm_installation
install_packages
`);
    fail(result, /설치를 취소했습니다/);
    assert.doesNotMatch(result.stderr, /Unexpected live operation/);
  }
  fail(fixture('YES=no; confirm_installation < /dev/null; install_packages'), /설치를 취소했습니다/);
});

test('--yes confirmation skips the prompt without reading input', () => {
  assert.equal(ok(fixture('YES=yes; confirm_installation < /dev/null')), '');
});

test('apt-get is an isolated executable stub and refuses unplanned package operations', () => {
  assert.match(ok(fixture('command -v apt-get')), /\/bin\/apt-get\s*$/);
  fail(fixture('apt-get update'), /Unexpected live operation: apt-get update/);
});

for (const [version, suite] of [['22.04', 'jammy'], ['24.04', 'noble'], ['26.04', 'resolute']]) {
  test(`Ubuntu ${version} selects only its own Docker repository (${suite})`, () => {
    for (const arch of ['amd64', 'arm64']) {
      const output = ok(fixture(`
ID=ubuntu VERSION_ID=${quote(version)} VERSION_CODENAME=${quote(suite)} UBUNTU_CODENAME=${quote(suite)} ARCH=${quote(arch)}
check_ubuntu_release
render_docker_source
`));
      assert.match(output, new RegExp(`^Suites: ${suite}$`, 'm'));
      assert.match(output, new RegExp(`^Architectures: ${arch}$`, 'm'));
      if (suite !== 'jammy') assert.doesNotMatch(output, /jammy/);
    }
  });
}

test('Ubuntu codename fallback is validated, not replaced with jammy', () => {
  const output = ok(fixture('ID=ubuntu VERSION_ID=24.04 VERSION_CODENAME=noble; unset UBUNTU_CODENAME; check_ubuntu_release; render_docker_source'));
  assert.match(output, /Suites: noble/);
  fail(fixture('ID=ubuntu VERSION_ID=24.04; unset VERSION_CODENAME UBUNTU_CODENAME; check_ubuntu_release'), /코드명은 noble/);
  fail(fixture('ID=ubuntu VERSION_ID=24.04 VERSION_CODENAME=jammy UBUNTU_CODENAME=noble; check_ubuntu_release'), /코드명이 서로 다릅니다/);
  fail(fixture('ID=ubuntu VERSION_ID=24.04 VERSION_CODENAME=noble UBUNTU_CODENAME=jammy; check_ubuntu_release'), /코드명은 noble/);
  fail(fixture('unset UBUNTU_SUITE; render_docker_source'), /Ubuntu 버전과 코드명을 확인/);
});

test('unsupported releases and non-Ubuntu distributions stop before mutation', () => {
  for (const version of ['18.04', '20.04', '23.10', '24.10', '25.04', '25.10', '99.04', '']) {
    const result = fixture(`
ID=ubuntu VERSION_ID=${quote(version)} VERSION_CODENAME=noble UBUNTU_CODENAME=noble
check_ubuntu_release
install_packages
`);
    fail(result, /설치 대상이 아닙니다/);
    assert.doesNotMatch(result.stderr, /Unexpected live operation/);
  }
  for (const id of ['debian', 'linuxmint', 'pop', '']) {
    fail(fixture(`ID=${quote(id)} ID_LIKE=ubuntu VERSION_ID=24.04 VERSION_CODENAME=noble; check_ubuntu_release`), /Ubuntu Server가 필요/);
  }
});

test('dry-run does not require root, OS validation, network or state writes', () => {
  const before = fs.existsSync(path.join(root, 'state/server'));
  const result = ok(run([script, '--dry-run', '--host', 'SOC.EXAMPLE.INVALID', '--bind-ip', '10.0.0.5']));
  assert.match(result, /미리보기/);
  assert.match(result, /대시보드 주소: soc.example.invalid/);
  assert.match(result, /검사하지 않았습니다/);
  assert.equal(fs.existsSync(path.join(root, 'state/server')), before);
  assert.match(ok(run([script, '--dry-run', '--prepare-only'])), /SOC 컨테이너 기동 전/);
});

for (const host of ['https://soc.example', 'soc.example:9200', 'user@host', '-bad.example', 'bad-.example', 'a..b', 'a.', '256.0.0.1', '01.2.3.4', '0.0.0.0', '::1', '${HOME}', 'name\nother', 'a'.repeat(64) + '.com']) {
  test(`reject malformed public host: ${JSON.stringify(host)}`, () => {
    fail(run([script, '--dry-run', '--host', host]), /오류:/);
  });
}

test('reject malformed bind IPs, duplicate options and password flags', () => {
  for (const ip of ['0.0.0.0', '1.2.3', '01.2.3.4', '10.0.0.256', 'host', '::1']) {
    fail(run([script, '--dry-run', '--bind-ip', ip]), /오류:/);
  }
  for (const args of [['--host'], ['--bind-ip'], ['--host', 'a', '--host', 'b'], ['--password', 'secret']]) {
    fail(run([script, '--dry-run', ...args]), /오류:/);
  }
});

test('dry-run cannot reach mocked mutation functions', () => {
  assert.match(ok(fixture(`
check_platform() { forbidden platform; }
install_packages() { forbidden packages; }
install_docker() { forbidden docker; }
prepare_state() { forbidden state; }
start_stack() { forbidden compose; }
main --dry-run
`)), /미리보기/);
});

test('existing state and incomplete checkouts fail closed', () => {
  fail(fixture('mkdir -p "$STATE"; check_fresh_state'), /이미 있습니다/);
  fail(fixture('rm "$ROOT/deploy/server/prepare.py"; check_fresh_state'), /필수 파일이 없습니다/);
  ok(fixture('check_fresh_state'));
});

const networkMocks = `
awk() { case "$*" in *'/proc/meminfo'*) return 0;; *) command awk "$@";; esac; }
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/test 20000000 1 15000000 1%% /\n'; }
ip() { printf '2: ens5 inet 10.0.0.5/24 brd 10.0.0.255 scope global ens5\n'; }
ss() { :; }
`;

test('preflight rejects nonlocal NAT address, occupied ports and low disk/RAM', () => {
  ok(fixture(networkMocks + '\ncheck_resources_and_network'));
  fail(fixture(networkMocks + '\nBIND_IP=203.0.113.5; check_resources_and_network'), /할당되지 않은 바인딩 IP/);
  fail(fixture(networkMocks + '\nss() { printf "LISTEN 0 4096 [::]:9200 [::]:*\\n"; }; check_resources_and_network'), /사용 중인 포트/);
  fail(fixture(networkMocks + '\ndf() { printf "Filesystem Blocks Used Available\\n/dev/test 2000 1000 1000\\n"; }; check_resources_and_network'), /디스크 여유 공간/);
  fail(fixture(networkMocks + '\nawk() { return 1; }; check_resources_and_network'), /메모리가 6 GiB/);
});

test('existing Docker is reused, remote engines are not selected', () => {
  assert.match(ok(fixture(`
has_command() { [ "$1" = docker ]; }
docker_local() { printf 'DOCKER %s\n' "$*" >&2; }
detect_docker
printf '%s\n' "$INSTALL_DOCKER"
`)), /^no\n$/);
  const output = ok(fixture('docker() { printf "%s\\n" "$*"; }; docker_local info'));
  assert.match(output, /^--host unix:\/\/\/var\/run\/docker.sock info/);
});

test('Docker failures, existing central containers/volumes and conflicting packages stop installation', () => {
  fail(fixture('docker_local() { return 1; }; check_docker_stack'), /실행 중/);
  fail(fixture('docker_local() { case "$1" in compose) return 1;; esac; }; check_docker_stack'), /Compose v2/);
  fail(fixture('docker_local() { case "$1" in ps) printf "existing";; esac; }; check_docker_stack'), /기존 cloud-soc-central 컨테이너/);
  fail(fixture('docker_local() { case "$1" in volume) printf "cloud-soc-central_es-data\\n";; esac; }; check_docker_stack'), /기존 중앙 서버 볼륨/);
  fail(fixture('has_command() { return 1; }; installed() { [ "$1" = docker.io ]; }; detect_docker'), /자동 삭제·교체하지/);
});

test('only missing dependencies are installed, with no upgrade/removal flags', () => {
  const result = ok(fixture(`
installed() { [ "$1" != curl ] && [ "$1" != openssl ]; }
${aptGetStub('printf \'%s\\n\' "$*"')}
install_packages
`));
  const limits = '-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any ';
  assert.equal(result, limits + 'update\n' + limits + 'install -y --no-remove --no-upgrade --no-install-recommends curl openssl\n');
  ok(fixture('installed() { return 0; }; install_packages'));
});

test('Docker repository conflicts and altered managed sources are preserved', () => {
  fail(fixture('printf "%s" "deb https://download.docker.com/linux/ubuntu jammy stable" > "$APT_ROOT/sources.list.d/existing.list"; check_repository'), /기존 Docker APT 저장소/);
  fail(fixture('printf "%s" "foreign source" > "$SOURCE_FILE"; stat() { printf "0:644"; }; check_repository'), /파일 내용이 다릅니다/);
  fail(fixture('render_docker_source > "$SOURCE_FILE"; stat() { printf "0:644"; }; check_repository'), /서명 키가 없습니다/);
  fail(fixture('printf "key" > "$KEY_FILE"; stat() { printf "1000:644"; }; check_repository'), /root 소유/);
  const output = ok(fixture('render_docker_source'));
  assert.match(output, /URIs: https:\/\/download.docker.com\/linux\/ubuntu/);
  assert.match(output, /Suites: jammy/);
  assert.match(output, /Signed-By:/);
});

test('old managed jammy repository on a newer Ubuntu is not silently replaced', () => {
  fail(fixture(`
render_docker_source > "$SOURCE_FILE"
printf 'key' > "$KEY_FILE"
stat() { printf '0:644'; }
UBUNTU_SUITE=noble
trap 'grep -q "Suites: jammy" "$SOURCE_FILE" || exit 99' 0
check_repository
`), /파일 내용이 다릅니다/);
});

test('new Docker install uses verified HTTPS key transport and explicit signed APT source', () => {
  const output = ok(fixture(`
INSTALL_DOCKER=yes
mktemp() { mkdir "$ROOT/download"; printf '%s' "$ROOT/download"; }
curl() { printf 'CURL %s\n' "$*"; printf '%s\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----' > "$TEMP/docker.asc"; }
${aptGetStub('printf \'APT %s\\n\' "$*"')}
systemctl() { printf 'SYSTEMCTL %s\n' "$*"; }
check_docker_stack() { printf 'CHECK STACK\n'; }
install_docker
cat "$SOURCE_FILE"
`));
  assert.match(output, /--proto =https --tlsv1.2/);
  assert.match(output, /APT .*Acquire::Retries=3 .*Acquire::https::Timeout=30 .*install -y --no-remove --no-upgrade/);
  assert.match(output, /--retry 3 --retry-delay 5 --retry-max-time 180/);
  assert.match(output, /docker-compose-plugin/);
  assert.match(output, /SYSTEMCTL enable --now docker/);
  assert.match(output, /CHECK STACK/);
  assert.match(output, /Signed-By:/);
});

test('failed Docker key download stops before writing repository or installing packages', () => {
  const result = fixture(`
INSTALL_DOCKER=yes
mktemp() { mkdir "$ROOT/download"; printf '%s' "$ROOT/download"; }
curl() { printf 'MOCK download failure\n' >&2; return 22; }
trap '[ ! -e "$KEY_FILE" ] && [ ! -e "$SOURCE_FILE" ] || exit 99' 0
install_docker
`);
  fail(result, /MOCK download failure/);
  assert.equal(result.status, 22);
});

test('kernel minimum is persisted; higher runtime values and conflicting files are preserved', () => {
  const result = ok(fixture(`
sysctl() { if [ "$1" = -n ]; then printf '65530'; else printf '%s\n' "$*"; fi; }
configure_kernel
cat "$SYSCTL_FILE"
`));
  assert.equal(result, '-w vm.max_map_count=1048576\nvm.max_map_count=1048576\n');
  ok(fixture('sysctl() { [ "$1" = -n ] || forbidden lower; printf "2097152"; }; configure_kernel; [ ! -e "$SYSCTL_FILE" ]'));
  fail(fixture('printf "foreign setting" > "$SYSCTL_FILE"; check_kernel_config'), /덮어쓰지 않았습니다/);
});

test('new installs delegate to the same versioned manager used by upgrades', () => {
  const result = ok(fixture(`
SOC_PUBLIC_HOST=evil SOC_STATE_DIR=/elsewhere COMPOSE_PROFILES=evil
export SOC_PUBLIC_HOST SOC_STATE_DIR COMPOSE_PROFILES
python3() {
  printf '%s\n' "$*"
}
start_stack
`));
  assert.match(result, /manage.py install --workspace .* --state .*\/state\/server --build/);
  const failure = fixture('python3() { printf "%s\\n" "$*"; return 42; }; start_stack');
  assert.equal(failure.status, 42);
  assert.doesNotMatch(failure.stdout, /up -d/);
});

test('readiness requires managed worker startup and all three authenticated TLS endpoints', () => {
  const setup = `
python3() { printf '%s\n' 'runtime ready; ingestion not verified'; }
http_status() { case "$1" in 9200|443) printf 401;; 5601) printf 200;; esac; }
`;
  assert.match(ok(fixture(setup + '\ncheck_ready')), /TLS\/HTTP 기동 확인을 통과/);
  const failed = fixture(setup + '\npython3() { return 42; }; check_ready');
  assert.equal(failed.status, 42);
  fail(fixture(setup + `
http_status() { printf 200; }
date() { if [ -f "$ROOT/timed-out" ]; then printf 301; else printf 0; fi; }
sleep() { touch "$ROOT/timed-out"; }
check_ready
`), /시간이 초과/);
  const output = ok(fixture('curl() { printf "%s\\n" "$*"; }; http_status 443 /api/portal'));
  assert.match(output, /--cacert .*\/tls\/ca.crt --resolve soc.example.invalid:443:10.0.0.5/);
  assert.doesNotMatch(output, /--insecure| -k /);
});

test('failure trap preserves original nonzero exit status', () => {
  const result = fixture('STAGE=test; trap finish 0; exit 42');
  assert.equal(result.status, 42);
  assert.match(result.stderr, /설치 중단 단계: 알 수 없음/);
});

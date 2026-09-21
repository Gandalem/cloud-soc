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
apt-get() { forbidden apt-get "$@"; }
curl() { forbidden curl "$@"; }
docker() { forbidden docker "$@"; }
systemctl() { forbidden systemctl "$@"; }
sysctl() { forbidden sysctl "$@"; }
python3() { forbidden python3 "$@"; }
openssl() { forbidden openssl "$@"; }
mkdir -p "$ROOT/deploy/server" "$APT_ROOT/sources.list.d" "$APT_ROOT/keyrings"
touch "$ROOT/deploy/server/prepare.py" "$ROOT/deploy/server/compose.yaml" "$ROOT/deploy/server/Dockerfile"
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
  ok(run(['-n', script]));
  assert.match(ok(run([script, '--help'])), /--prepare-only/);
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
  fail(fixture('ID=ubuntu VERSION_ID=24.04; unset VERSION_CODENAME UBUNTU_CODENAME; check_ubuntu_release'), /codename noble/);
  fail(fixture('ID=ubuntu VERSION_ID=24.04 VERSION_CODENAME=jammy UBUNTU_CODENAME=noble; check_ubuntu_release'), /Conflicting Ubuntu codenames/);
  fail(fixture('ID=ubuntu VERSION_ID=24.04 VERSION_CODENAME=noble UBUNTU_CODENAME=jammy; check_ubuntu_release'), /codename noble/);
  fail(fixture('unset UBUNTU_SUITE; render_docker_source'), /Validate the Ubuntu release/);
});

test('unsupported releases and non-Ubuntu distributions stop before mutation', () => {
  for (const version of ['18.04', '20.04', '23.10', '24.10', '25.04', '25.10', '99.04', '']) {
    const result = fixture(`
ID=ubuntu VERSION_ID=${quote(version)} VERSION_CODENAME=noble UBUNTU_CODENAME=noble
check_ubuntu_release
install_packages
`);
    fail(result, /not supported by this installer/);
    assert.doesNotMatch(result.stderr, /Unexpected live operation/);
  }
  for (const id of ['debian', 'linuxmint', 'pop', '']) {
    fail(fixture(`ID=${quote(id)} ID_LIKE=ubuntu VERSION_ID=24.04 VERSION_CODENAME=noble; check_ubuntu_release`), /Ubuntu Server is required/);
  }
});

test('dry-run does not require root, OS validation, network or state writes', () => {
  const before = fs.existsSync(path.join(root, 'state/server'));
  const result = ok(run([script, '--dry-run', '--host', 'SOC.EXAMPLE.INVALID', '--bind-ip', '10.0.0.5']));
  assert.match(result, /DRY RUN/);
  assert.match(result, /Public host: soc.example.invalid/);
  assert.match(result, /have NOT been checked/);
  assert.equal(fs.existsSync(path.join(root, 'state/server')), before);
  assert.match(ok(run([script, '--dry-run', '--prepare-only'])), /Stop before starting/);
});

for (const host of ['https://soc.example', 'soc.example:9200', 'user@host', '-bad.example', 'bad-.example', 'a..b', 'a.', '256.0.0.1', '01.2.3.4', '0.0.0.0', '::1', '${HOME}', 'name\nother', 'a'.repeat(64) + '.com']) {
  test(`reject malformed public host: ${JSON.stringify(host)}`, () => {
    fail(run([script, '--dry-run', '--host', host]), /ERROR:/);
  });
}

test('reject malformed bind IPs, duplicate options and password flags', () => {
  for (const ip of ['0.0.0.0', '1.2.3', '01.2.3.4', '10.0.0.256', 'host', '::1']) {
    fail(run([script, '--dry-run', '--bind-ip', ip]), /ERROR:/);
  }
  for (const args of [['--host'], ['--bind-ip'], ['--host', 'a', '--host', 'b'], ['--password', 'secret']]) {
    fail(run([script, '--dry-run', ...args]), /ERROR:/);
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
`)), /DRY RUN/);
});

test('existing state and incomplete checkouts fail closed', () => {
  fail(fixture('mkdir -p "$STATE"; check_fresh_state'), /already exists/);
  fail(fixture('rm "$ROOT/deploy/server/prepare.py"; check_fresh_state'), /Incomplete checkout/);
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
  fail(fixture(networkMocks + '\nBIND_IP=203.0.113.5; check_resources_and_network'), /Bind IP is not/);
  fail(fixture(networkMocks + '\nss() { printf "LISTEN 0 4096 [::]:9200 [::]:*\\n"; }; check_resources_and_network'), /already in use/);
  fail(fixture(networkMocks + '\ndf() { printf "Filesystem Blocks Used Available\\n/dev/test 2000 1000 1000\\n"; }; check_resources_and_network'), /free disk/);
  fail(fixture(networkMocks + '\nawk() { return 1; }; check_resources_and_network'), /6 GiB RAM/);
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
  fail(fixture('docker_local() { return 1; }; check_docker_stack'), /must be running/);
  fail(fixture('docker_local() { case "$1" in compose) return 1;; esac; }; check_docker_stack'), /Compose v2/);
  fail(fixture('docker_local() { case "$1" in ps) printf "existing";; esac; }; check_docker_stack'), /containers found/);
  fail(fixture('docker_local() { case "$1" in volume) printf "cloud-soc-central_es-data\\n";; esac; }; check_docker_stack'), /volumes found/);
  fail(fixture('has_command() { return 1; }; installed() { [ "$1" = docker.io ]; }; detect_docker'), /no automatic removal/);
});

test('only missing dependencies are installed, with no upgrade/removal flags', () => {
  const result = ok(fixture(`
installed() { [ "$1" != curl ] && [ "$1" != openssl ]; }
apt-get() { printf '%s\n' "$*"; }
install_packages
`));
  assert.equal(result, 'update\ninstall -y --no-remove --no-upgrade --no-install-recommends curl openssl\n');
  ok(fixture('installed() { return 0; }; install_packages'));
});

test('Docker repository conflicts and altered managed sources are preserved', () => {
  fail(fixture('printf "%s" "deb https://download.docker.com/linux/ubuntu jammy stable" > "$APT_ROOT/sources.list.d/existing.list"; check_repository'), /Existing Docker APT source/);
  fail(fixture('printf "%s" "foreign source" > "$SOURCE_FILE"; stat() { printf "0:644"; }; check_repository'), /differs/);
  fail(fixture('render_docker_source > "$SOURCE_FILE"; stat() { printf "0:644"; }; check_repository'), /without its signing key/);
  fail(fixture('printf "key" > "$KEY_FILE"; stat() { printf "1000:644"; }; check_repository'), /root-owned/);
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
`), /differs/);
});

test('new Docker install uses verified HTTPS key transport and explicit signed APT source', () => {
  const output = ok(fixture(`
INSTALL_DOCKER=yes
mktemp() { mkdir "$ROOT/download"; printf '%s' "$ROOT/download"; }
curl() { printf 'CURL %s\n' "$*"; printf '%s\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----' > "$TEMP/docker.asc"; }
apt-get() { printf 'APT %s\n' "$*"; }
systemctl() { printf 'SYSTEMCTL %s\n' "$*"; }
check_docker_stack() { printf 'CHECK STACK\n'; }
install_docker
cat "$SOURCE_FILE"
`));
  assert.match(output, /--proto =https --tlsv1.2/);
  assert.match(output, /APT install -y --no-remove --no-upgrade/);
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
  fail(fixture('printf "foreign setting" > "$SYSCTL_FILE"; check_kernel_config'), /not be overwritten/);
});

test('Compose ignores inherited state overrides and validates before starting', () => {
  const result = ok(fixture(`
SOC_PUBLIC_HOST=evil SOC_STATE_DIR=/elsewhere COMPOSE_PROFILES=evil
export SOC_PUBLIC_HOST SOC_STATE_DIR COMPOSE_PROFILES
docker_local() {
  if env | grep -qE '^(SOC_PUBLIC_HOST|SOC_STATE_DIR|COMPOSE_PROFILES)='; then forbidden inherited; fi
  printf '%s\n' "$*"
}
start_stack
`));
  assert.match(result, /--project-name cloud-soc-central --env-file .*\/state\/server\/compose.env/);
  assert.match(result, /config --quiet\n.*up -d --build\n$/);
  const failure = fixture('compose() { printf "%s\\n" "$*"; return 42; }; start_stack');
  assert.equal(failure.status, 42);
  assert.doesNotMatch(failure.stdout, /up -d/);
});

test('readiness requires successful bootstrap and all three authenticated TLS endpoints', () => {
  const setup = `
compose() { printf 'bootstrap-id'; }
docker_local() { printf 'exited:0'; }
http_status() { case "$1" in 9200|443) printf 401;; 5601) printf 200;; esac; }
`;
  assert.match(ok(fixture(setup + '\ncheck_ready')), /startup checks passed/);
  fail(fixture(setup + '\ndocker_local() { printf "exited:1"; }; check_ready'), /did not exit successfully/);
  fail(fixture(setup + `
http_status() { printf 200; }
date() { if [ -f "$ROOT/timed-out" ]; then printf 301; else printf 0; fi; }
sleep() { touch "$ROOT/timed-out"; }
check_ready
`), /timed out/);
  const output = ok(fixture('curl() { printf "%s\\n" "$*"; }; http_status 443 /api/portal'));
  assert.match(output, /--cacert .*\/tls\/ca.crt --resolve soc.example.invalid:443:10.0.0.5/);
  assert.doesNotMatch(output, /--insecure| -k /);
});

test('failure trap preserves original nonzero exit status', () => {
  const result = fixture('STAGE=test; trap finish 0; exit 42');
  assert.equal(result.status, 42);
  assert.match(result.stderr, /Stopped during: test/);
});

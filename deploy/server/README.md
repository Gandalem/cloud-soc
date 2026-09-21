# Ubuntu LTS 중앙 서버 설치

이 구성은 **단일 노드 졸업작품·실습용**입니다. Elasticsearch, Kibana, 에이전트 배포 포털을 함께 실행합니다. 저장소 루트의 `compose.yaml`은 기존 로컬 개발용으로 유지하며, 아래에서는 항상 `deploy/server/compose.yaml`을 지정합니다.

AWS EC2에 처음 배포하고 Windows PC에서 검증하는 경우에는 [AWS Ubuntu + Windows 실제 수집 테스트](../../docs/aws_windows_e2e_test.md)를 먼저 따라가세요. 아래는 공통 구성과 운영 제약 설명입니다.

```text
관리자 PC -- HTTPS 443 --> Caddy --> 관리 포털 (인증·패키지·수집 키)
관리자 PC -- HTTPS 5601 -> Caddy --> Kibana (별도 로그인)
수집 서버 -- HTTPS 9200 ----------> Elasticsearch (서버별 API 키)
  Windows / Ubuntu: Filebeat -> soc-host-raw-*
  선택한 NIC: Packetbeat     -> soc-network-*
```

**지금 가능한 것:** 실제 설치 묶음 생성·조회·검색·다운로드·삭제, 서버별 만료형 수집 키 발급·폐기. 화면만 있는 데모가 아닙니다.

**아직 없는 것:** 원격 자동 설치, 에이전트 접속/헬스 현황, 정책 배포, 자동 업그레이드, 서명된 EXE, 실데이터 관제 메인/조사 화면, 신규 로그·네트워크 탐지 연동. 기존 관제 화면은 데모로 명확히 구분합니다. 탐지 규칙은 이번 단계에서 추가하지 않습니다.

## 빠른 설치: Git + sh (권장)

**새 Ubuntu 22.04·24.04·26.04 LTS 서버**에서 먼저 아래 네트워크 제한을 준비한 뒤 사용합니다. Windows PC에서 실행하는 스크립트가 아닙니다. 기존 설치의 업그레이드·재설치 도구도 아닙니다.

```bash
# git이 없을 때만 실행: 저장소를 받으려면 Git 자체는 먼저 필요합니다.
sudo apt-get update
sudo apt-get install -y --no-remove --no-upgrade git
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
git rev-parse HEAD
less deploy/server/install-ubuntu.sh
sh deploy/server/install-ubuntu.sh --dry-run
sudo sh deploy/server/install-ubuntu.sh
```

공인 DNS/IPv4, 로컬 바인딩 IPv4, 변경 승인(`INSTALL`), 16자 이상 관리자 비밀번호를 요청합니다. EC2의 바인딩 IP는 **프라이빗 IPv4**입니다. 공란이면 루프백만 열리므로 원격 접속을 원하는 경우 반드시 실제 프라이빗 IP를 입력하세요. 비밀번호를 CLI 인자·환경변수로 넘기지 않습니다.

| 자동 처리 | 조건·제약 |
| --- | --- |
| 사전 검사 | Ubuntu 22.04·24.04·26.04 LTS + systemd, amd64/arm64, root, 대화형 터미널, RAM 6GiB 이상, 체크아웃 디스크 여유 10GiB 이상 |
| 필수 패키지 | 누락된 `ca-certificates`, `curl`, `git`, `python3`, `openssl`만 APT 설치. 전체 시스템 업그레이드 없음 |
| Docker | 기존 로컬 Docker·Compose는 실행 가능한 경우 재사용. 없으면 OS 코드명에 맞는 공식 서명 APT 저장소의 Docker CE·Compose 플러그인 설치·데몬 활성화 |
| 기존 설정 보호 | 충돌하는 Docker 패키지/저장소, 기존 `state/server`, 중앙 컨테이너·볼륨, 사용 중인 443·5601·9200, 비로컬 바인딩 IP는 중단 |
| 커널 | `vm.max_map_count`가 낮으면 1048576으로 올리고 `/etc/sysctl.d/90-cloud-soc.conf`에 저장. 이미 높은 값은 낮추지 않음 |
| 인증서·서비스 | `prepare.py` 재사용, 공개 CA의 DER 사본 추가, Compose 빌드·기동, bootstrap 종료 코드와 로컬 TLS/HTTP 응답 확인 |

APT가 결정하는 Docker 버전은 고정하지 않으며 기존 엔진을 자동 업그레이드하지 않습니다. 이미지 다운로드·빌드·로그 보관에는 추가 공간이 필요합니다. Docker 데이터 디렉터리가 다른 디스크라면 해당 여유 공간도 별도로 확인하세요. **보안그룹·방화벽·DNS 설정, Windows CA 신뢰, 에이전트 설치, 실제 수신 검증은 자동 처리하지 않습니다.**

`--dry-run`은 파일·OS·포트·의존성 확인 없이 계획만 출력합니다. `--prepare-only`는 의존성 설치와 인증서 준비까지만 하고 SOC 컨테이너는 기동하지 않습니다. 다만 새로 설치한 Docker 데몬은 시작됩니다. `--yes`는 변경 승인만 생략하며 관리자 비밀번호 때문에 대화형 터미널은 계속 필요합니다.

자동 설치가 완료되면 아래 2~3절을 반복하지 말고 [AWS 가이드 6절](../../docs/aws_windows_e2e_test.md#6-windows에-ca-공개-인증서-전달신뢰)에서 Windows 신뢰 등록과 실제 수집 검증을 이어갑니다. 수동 설치를 원하는 경우에만 아래 1~3절을 진행합니다.

### Ubuntu 버전 범위

`/etc/os-release`의 `ID=ubuntu`, `VERSION_ID`, `UBUNTU_CODENAME` 또는 `VERSION_CODENAME`을 함께 확인합니다. 다음은 **중앙 설치기의 분기 지원 범위**이며 버전별 실제 EC2 설치 완료를 뜻하지 않습니다.

| Ubuntu | Docker APT suite |
| --- | --- |
| 22.04 LTS | `jammy` |
| 24.04 LTS | `noble` |
| 26.04 LTS | `resolute` |

기준은 2026-09-21 확인한 [Docker 공식 지원 목록](https://docs.docker.com/engine/install/ubuntu/#os-requirements)입니다. 코드명 누락·불일치, 파생 배포판, 목록 밖의 구버전·중간 릴리스·미검토 신버전은 설치 전에 중단합니다. Ubuntu Pro 적용 여부와 Docker 지원은 별개이며, 모든 Ubuntu 버전을 무조건 허용하거나 다른 버전의 저장소로 대체하지 않습니다. [Ubuntu 지원 기간](https://ubuntu.com/about/release-cycle)

**Ubuntu 로그/네트워크 에이전트는 이번 변경 대상이 아닙니다.** 해당 설치기는 여전히 Ubuntu 22.04 대상으로 유지하며 Windows 에이전트 동작에도 변경이 없습니다.

이전 버전의 `Only Ubuntu 22.04 is supported` 오류로 중단한 서버는 해당 실행에서 패키지·인증서가 생성되기 전 상태입니다. 저장소의 로컬 변경을 먼저 확인하고 수정본을 받은 뒤 다시 실행할 수 있습니다. Git 갱신이 충돌로 중단되면 강제로 덮어쓰지 않습니다.

```bash
git status --short
git pull --ff-only origin main
cat /etc/os-release
sudo sh deploy/server/install-ubuntu.sh
```

### 실패·재시도

첫 오류와 `Stopped during:` 단계를 확인하세요. 설치된 패키지와 생성된 상태는 자동 롤백하거나 지우지 않습니다. `state/server`가 없는 패키지 설치 단계 실패는 원인을 해결한 뒤 재실행할 수 있습니다. 다른 Docker 저장소·부분 설치 패키지가 감지되면 관리자가 먼저 정리 여부를 판단해야 합니다.

비밀번호는 **16자 이상**이어야 하며 입력 중 화면에 글자나 별표가 표시되지 않는 것이 정상입니다. 길이 부족이면 확인 입력 전에 이유를 표시하고, 확인 불일치면 두 값을 다시 받습니다. 최대 3회 시도 후에는 상태 파일을 만들지 않고 종료합니다. 비밀번호를 명령 인자·채팅·로그에 넣지 마세요.

구버전의 비밀번호 입력 직후 `Preparation failed (ValueError)`는 길이 부족 등 여러 검증 오류를 한 문구로 표시한 것입니다. 이 메시지만으로 원인을 확정하지 말고 다음처럼 **폴더 존재 여부만** 확인합니다.

```bash
sudo ls -ld state/server
```

`No such file or directory`이면 인증서 준비 상태가 없는 것입니다. Git 변경을 보존하며 `git pull --ff-only origin main`으로 수정본을 받고 설치기를 다시 실행합니다. 기존 Docker는 재사용하며 삭제할 필요가 없습니다. **폴더가 존재하거나 권한 오류 등 다른 결과이면 지우거나 덮어쓰지 말고 먼저 검토합니다.** 예상 가능한 검증 오류는 비밀번호를 노출하지 않는 구체적 메시지로 안내하며, 알 수 없는 암호화·OS·OpenSSL 오류의 원문은 계속 숨깁니다.

**`state/server/compose.env`까지 정상 생성된 뒤 이미지 다운로드·기동·준비 확인이 실패했다면 설치기를 다시 실행하지 않습니다.** 아래 3절의 `config --quiet`, `up -d --build`, `ps -a`, `logs`로 같은 상태를 재사용합니다. 인증서 준비 자체가 실패해 `compose.env`가 없다면 상태를 보존하고 원인을 검토합니다. CA·비밀번호를 임의로 다시 만들거나 `down -v`로 데이터를 삭제하지 않습니다.

## 1. 준비 (수동 설치)

- 위 목록의 Ubuntu LTS 서버, Docker Engine와 Compose v2, Git, Python 3, OpenSSL이 필요합니다. Python 패키지는 컨테이너 안에 설치되므로 호스트 가상환경은 필요 없습니다.
- 소규모 실습의 시작점으로 메모리 8GB와 여유 디스크를 권장합니다. 실제 필요량은 수집량에 따라 측정해야 합니다. 현재 ES 힙은 1GB, 컨테이너 한도는 ES 2GB/Kibana 1GB입니다.
- 관리자와 에이전트가 실제 접근할 DNS 또는 IPv4 하나를 정합니다. 예시 `soc.example.com`, 서버 내부 IP `10.0.0.10`을 그대로 사용하지 말고 실제 값으로 바꿉니다. IPv6는 이 설치기에서 지원하지 않습니다.
- 모든 대상 서버에서 공식 Elastic 배포처로 HTTPS 다운로드가 가능해야 합니다. Windows 네트워크 수집에는 승인된 Npcap을 별도로 준비합니다.
- 호스트 로그에는 개인정보·인증 관련 기록이 포함될 수 있습니다. 수집 권한, 저장 기간, 대상 서버와 네트워크 범위를 먼저 승인받습니다.

Docker는 [공식 Ubuntu 설치 안내](https://docs.docker.com/engine/install/ubuntu/)에 따라 설치하고 `docker compose version`을 확인합니다. 기존 Docker/컨테이너를 임의로 삭제하지 않습니다.

Elasticsearch의 [Docker 운영 요구사항](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod)에 맞춰 `vm.max_map_count`를 확인합니다. 값이 부족하면 관리자가 다음 값을 적용하고 재부팅 후에도 유지되도록 `/etc/sysctl.d/` 설정을 관리합니다. 아래 명령만으로는 영구 적용되지 않습니다.

```bash
sysctl vm.max_map_count
sudo sysctl -w vm.max_map_count=1048576
```

### 네트워크 접근 제한

| 포트 | 허용 대상 | 용도 |
| --- | --- | --- |
| TCP 443 | 관리자 VPN/허용 IP만 | 포털과 설치 파일 다운로드 |
| TCP 5601 | 분석가 VPN/허용 IP만 | Kibana |
| TCP 9200 | 승인된 수집 서버/VPN만 | HTTPS Elasticsearch 수신 |

인터넷 전체에 위 포트를 열지 않습니다. 특히 포털은 단일 관리자 Basic 인증이며 MFA·로그인 속도 제한·사용자별 RBAC가 없으므로 반드시 관리망/VPN으로 제한합니다. Docker 공개 포트는 UFW 규칙을 우회할 수 있어 클라우드 보안그룹 및 실제 Docker 방화벽 경로를 확인해야 합니다. [Docker 방화벽 설명](https://docs.docker.com/engine/network/packet-filtering-firewalls/)

`--bind-ip`는 **서버에 실제 할당된 인터페이스 IP**입니다. NAT 공인 IP가 서버 인터페이스에 없으면 공인 IP를 바인딩 값에 넣지 않습니다. `--host`에는 대상 서버에서 접근 가능한 외부 DNS/IP, `--bind-ip`에는 내부 IP를 사용합니다. 포트포워딩에서도 위 허용 대상을 제한합니다.

## 2. 최초 인증서·비밀번호 준비 (수동 설치)

```bash
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
sudo python3 deploy/server/prepare.py --host soc.example.com --bind-ip 10.0.0.10
```

명령은 포털 `admin` 계정의 16자 이상 비밀번호를 대화형으로 두 번 요청합니다. 비밀번호를 명령 인자, 셸 히스토리, Git에 넣지 않습니다. 이미 저장소가 있다면 새로 복제할 필요가 없습니다.

생성 위치는 `state/server/`입니다. 기존 경로가 있으면 덮어쓰지 않습니다. 중간 실패 시에도 남은 상태를 자동 삭제하지 않으며 관리자가 먼저 검토해야 합니다. `--bind-ip`를 생략하면 안전하게 `127.0.0.1`에만 포트를 게시합니다.

| 파일/경로 | 역할 |
| --- | --- |
| `compose.env` | 공개 주소·바인딩 IP·상태 경로. 비밀번호 없음 |
| `tls/ca.crt` | 에이전트에 배포할 CA 공개 인증서 |
| `tls/ca.cer` | 자동 설치기가 추가로 내보내는 동일 CA의 공개 DER 사본. Windows 신뢰 등록용 |
| `tls/server.crt`, `tls/server.key` | 서버 TLS 인증서·개인키 |
| `private/ca.key` | CA 개인키. 배포 금지 |
| `secrets/` | 관리자 해시와 서비스별 비밀번호. 배포 금지 |
| `kibana.yml` | 서비스 비밀번호·영속 암호화 키 포함. 배포 금지 |
| `portal/` | 패키지와 발급 키 ID를 저장하는 SQLite. API 키 원문 없음 |

상태 루트와 `secrets/` 부모는 root 전용입니다. 컨테이너에 필요한 개별 파일만 읽기 전용으로 마운트합니다. 이 권한을 완화하거나 `state/server` 전체를 에이전트에 복사하지 않습니다. Docker 관리자 자체는 호스트 root와 동등한 권한으로 취급합니다.

### CA 신뢰

준비 명령이 출력한 CA 파일 SHA-256을 인증된 별도 경로로 전달합니다. 관리자 PC에는 `tls/ca.crt` **한 파일만** 안전하게 전달하고, 해당 파일 해시를 대조한 뒤 조직이 승인한 절차로 신뢰 저장소에 등록합니다. 에이전트는 설치 묶음의 CA 파일로 서버를 검증합니다.

사설 CA를 신뢰하기 전에는 브라우저 경고가 발생할 수 있습니다. 경고를 무시해서 접속하거나 `curl -k`, `verify_certs=False`, 실행 정책 우회를 사용하지 않습니다. 공개 인증기관 인증서로 교체하려면 중앙 설정과 에이전트 CA 배포를 함께 검토해야 합니다.

## 3. 기동

다음 명령은 인증 계정과 인덱스 템플릿을 새 클러스터에 생성합니다. 기존 개발 볼륨과는 `cloud-soc-central` 프로젝트명으로 분리합니다. 같은 호스트의 9200/5601 포트가 이미 사용 중이면 먼저 충돌을 해결합니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml config --quiet
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --build
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --tail 100 bootstrap portal gateway
```

ES 정상 기동 후 `bootstrap`이 계정·템플릿을 준비하고 **종료 코드 0**으로 끝나야 포털과 Kibana가 시작됩니다. 이 초기화 컨테이너는 계속 실행되는 서비스가 아닙니다. 실패하면 원인을 고친 뒤 같은 `up -d --build` 명령으로 재시도하며 데이터 볼륨을 삭제하지 않습니다.

| 접속 주소 (실제 host로 교체) | 계정 |
| --- | --- |
| `https://soc.example.com` | `admin` / 준비 단계에서 입력한 비밀번호 |
| `https://soc.example.com:5601` | `cloud_soc_analyst` / 보호된 `secrets/analyst_password` 파일의 값 |
| `https://soc.example.com:9200` | 인증 필요. 에이전트는 발급된 API 키 사용 |

분석가 초기 비밀번호는 서버 관리자가 root 권한으로 해당 파일을 확인해 안전하게 전달합니다. `elastic` 최고 관리자 비밀번호를 일반 분석이나 에이전트에 사용하지 않습니다. 분석가 계정은 수집 인덱스 읽기와 Kibana 관리 권한을 가지며 ES 전체 관리자 계정은 아닙니다.

포털의 **Elasticsearch 연결 확인**은 중앙 서버 내부 연결 결과입니다. 원격 에이전트에서의 DNS·방화벽·TLS 도달 가능성이나 문서 수신 성공까지 보장하지 않습니다.

## 4. 화면에서 배포

1. **설치 파일 추가**에서 Windows 또는 Ubuntu, 파일 이름, 조직 ID, 네트워크 수집 여부를 선택합니다. 서버 주소는 중앙 설정으로 고정되며 임의 수신처를 입력할 수 없습니다.
2. 생성한 ZIP 또는 tar.gz를 다운로드합니다. 설치 스크립트, CA 공개 인증서, 설정·체크섬이 포함됩니다. Beat 실행 파일·키·비밀번호·개인키는 포함되지 않습니다.
3. **키 발급**을 대상 서버마다 따로 실행합니다. 로그/네트워크 키는 분리되며 1·7·30·90일 중 만료 기간을 선택합니다. 한 번만 표시되므로 안전하게 보관합니다. 창을 닫거나 응답을 잃으면 키 원문을 다시 조회할 수 없습니다. 불필요한 키 ID는 폐기하고 새로 발급합니다.
4. 승인된 방법으로 패키지를 대상 서버에 전달합니다. **설치 명령**을 열어 해시를 확인하고 해당 OS의 관리자 터미널에서 실행합니다. ZIP/tar 안의 모든 파일을 함께 유지해야 합니다.
5. 네트워크 옵션을 선택했다면 NIC 이름/GUID를 실제 값으로 바꿉니다. Windows는 승인된 Npcap이 먼저 실행 중이어야 합니다. PowerShell 서명이 필요한 환경에서는 묶음 안의 모든 관련 스크립트도 승인된 서명 절차를 거칩니다.
6. Filebeat 프롬프트에는 **로그 수집 키**, Packetbeat 프롬프트에는 **네트워크 수집 키**를 입력합니다. 화면의 키 값은 `id:api_key` 형식입니다. 명령줄 인자에 붙이지 않습니다.

압축 해제 후 핵심 설치 명령은 다음과 같습니다. 주소와 조직은 이미 묶음에 포함되어 있습니다. NIC는 예시를 실제 값으로 교체합니다.

```bash
# Ubuntu: 로그만 선택한 패키지
sudo bash install.sh
# Ubuntu: 로그 + 네트워크 패키지
sudo bash install.sh --interface ens3
```

```powershell
# Windows: 로그만 선택한 패키지
.\install.ps1
# Windows: 로그 + 네트워크 패키지
Get-NetAdapter -IncludeHidden | Select-Object Name, Status, InterfaceGuid
.\install.ps1 -InterfaceGuid '실제-NIC-GUID'
```

설정 출력만 하려면 Linux는 `--dry-run`, Windows는 `-DryRun`을 추가합니다. DryRun은 실제 CA·OS·서비스·Npcap 설치 상태를 확인하지 않으므로 설치 성공 보장이 아닙니다. 기존 설치는 자동 교체하지 않습니다. 네트워크 설치가 나중에 실패하면 먼저 성공한 Filebeat는 계속 실행됩니다.

추가 앱 로그 경로는 현재 웹 폼에 없습니다. 필요하면 검토 후 [개별 설치기 옵션](../agents/README.md)을 사용합니다. 모든 디스크 데이터·비활성 채널·클라우드 Audit API를 무조건 수집하는 방식이 아닙니다. 정확한 범위는 [로그 수집 계약](../agents/COLLECTION.md)과 [네트워크 메타데이터 계약](../agents/NETWORK.md)을 확인합니다.

**패키지 삭제는 다운로드 파일만 삭제합니다.** 설치된 서비스 제거, 이미 받은 파일 회수, API 키 폐기는 별도입니다. 키 관리 목록은 최근 500개 발급 이력이며 실시간 유효 상태 목록이 아닙니다. 키 폐기는 해당 키를 사용하는 수집기의 전송을 중단시킵니다. 만료 전 keystore 수동 갱신이 필요하며 자동 회전 기능은 없습니다.

## 5. 실제 수신 확인

1. 포털의 연결 상태를 확인합니다.
2. 대상 서버에서 Filebeat, 네트워크 선택 시 Packetbeat 서비스와 전송 오류를 확인합니다. OS별 명령은 [설치 후 확인](../../README.md#7-설치-후-실제-로그-확인)과 [네트워크 가이드](../agents/NETWORK.md)에 있습니다.
3. Kibana에서 `soc-host-raw-*`, `soc-network-*` Data View를 각각 만들고 시간 필드를 `@timestamp`로 선택합니다.
4. 승인된 테스트 서버에서 정상 로그인/테스트 로그를 생성하고 자신의 테스트 서비스에 DNS/TLS 요청을 보냅니다. 해당 `host.name`, `organization.id`, 시각, NIC 범위와 문서를 비교합니다.
5. 재부팅 자동 시작, 수신 중단 후 재전송, 키 만료·폐기 시 실패, 불필요한 로그의 제외, DNS/TLS 정보의 개인정보 포함 여부를 확인합니다.

Packetbeat는 지정한 NIC에서 볼 수 있는 트래픽만 관측합니다. 암호화 내용을 복호화하거나 다른 서버의 트래픽까지 자동으로 수집하지 않습니다. 원본 PCAP과 HTTP 본문·쿠키는 보관하지 않습니다. PCAP 파일은 오프라인 합성 테스트에만 사용합니다.

## 6. 운영 제약과 백업

- **보존 정책은 자동 설정하지 않습니다.** 수집량을 늘리기 전에 ILM/삭제 정책·디스크 사용량 경보·백업을 정합니다. 일 단위 인덱스와 에이전트별 1GB 큐만으로 저장량이 제한되지는 않습니다.
- 단일 노드이며 중앙 템플릿은 복제본 0개입니다. 장애 허용 구성이 아닙니다. ES 스냅샷과 복원 절차를 별도로 준비합니다.
- 서버 인증서는 365일, CA는 3650일입니다. 갱신 자동화가 없으므로 만료 전 교체를 계획합니다. 기존 클러스터에 `prepare.py`를 새로 실행해 비밀번호·CA를 바꾸면 서비스 간 설정이 어긋납니다.
- CA 개인키, 서비스 비밀번호, Kibana 암호화 키, 포털 DB는 접근 제한과 암호화된 백업이 필요합니다. SQLite는 쓰기를 멈춘 상태 또는 SQLite 백업 API로 일관된 복사본을 만듭니다. Git에 올리지 않습니다.
- API 키는 각 수집 인덱스에 추가할 수 있지만 읽거나 삭제할 수 없습니다. `organization.id`는 분류용 태그이며 조직별 보안 격리가 아닙니다.
- 서명 검증, 설치 바이너리 오프라인 배포, 불변 감사 이력, MFA/RBAC, 키 자동 회전은 후속 작업입니다. 다중 조직·실서비스용으로 그대로 공개하지 않습니다.

중지만 하려면 다음을 사용합니다. 데이터 보존이 필요하면 `down -v`를 실행하지 않습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml stop
```

## 7. 개발 검증 범위

포털 테스트는 모의 Elasticsearch와 임시 DB/아카이브를 사용합니다. 인증, Host/Origin/CSRF 차단, 비밀정보 제외, 실제 ZIP/tar 내용·해시, 생성 래퍼의 DryRun, 키 권한 분리와 부분 발급 실패 처리를 검사합니다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r deploy/server/requirements.txt
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
node --test prototype/tests/logs.test.cjs deploy/agents/tests/installers.test.cjs deploy/agents/tests/network.test.cjs deploy/server/tests/install-ubuntu.test.cjs deploy/server/tests/guides.test.cjs
```

중앙 `sh` 설치기 테스트는 POSIX 구문, dry-run, Ubuntu 버전·코드명별 저장소 선택과 불일치 차단, 입력 검증, 기존 상태·저장소·포트 보호, 모의 APT/Docker·커널·TLS 준비 확인을 검사합니다. 실제 패키지 설치·다운로드·서비스 기동은 하지 않습니다.

**실제 AWS Ubuntu에서 이미지 빌드·기동·인증서·API 키·문서 수신을 통합 검증하지 못했습니다.** Compose 정적 검사, 오프라인 테스트와 테스트 서버의 브라우저 동작을 검증했습니다. 운영 전에는 실제 서버에서 기동·Windows 에이전트·Kibana 수신까지 확인해야 합니다.

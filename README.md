# Cloud SOC 설치 가이드

Cloud SOC는 Elasticsearch·Kibana와 Python 탐지 엔진을 사용하는 보안관제 프로젝트입니다. **Ubuntu 중앙 관리 서버의 웹 화면에서 OS별 설치 파일을 생성·다운로드하고, 각 서버에서 로그·선택적 네트워크 수집기를 설치**할 수 있습니다.

> **중앙 서버를 처음 만들려면 [Ubuntu LTS + Docker Compose 중앙 서버 가이드](deploy/server/README.md)부터 진행하세요.** 루트 `compose.yaml`은 로컬 개발용 HTTP 구성, `deploy/server/compose.yaml`은 HTTPS·인증을 적용한 중앙 서버 구성입니다. 둘을 혼용하지 않습니다.

**AWS 인스턴스에 설치하고 현재 Windows PC에서 실제 수집을 시험하려면 [AWS Ubuntu + Windows 실제 수집 테스트](docs/aws_windows_e2e_test.md)를 순서대로 진행하세요.** EC2·보안그룹·인증서·패키지 설치와 고유 테스트 로그의 Kibana 검색까지 다룹니다.

설치 중 오류가 발생했다면 [8. 문제 해결](#8-문제-해결)을 먼저 확인하세요. Ubuntu 버전·비밀번호·Elasticsearch 파일 권한, 웹 HTTPS 접속, Windows ZIP 경로·GUID 입력·스크립트 서명 오류와 백그라운드 동작을 정리했습니다.

**수집 중인 에이전트는 중앙 포털의 [에이전트 접속 현황](docs/agent_status.md)에서 확인합니다.** 실제 마지막 서버 수신 시각으로 로그·네트워크 수집기 상태를 표시합니다. 미수신은 오프라인을 의미하지 않으며, 기존 중앙 서버는 가이드의 업데이트 절차를 먼저 진행해야 합니다.

### Git으로 받아 중앙 서버 자동 설치

**새 Ubuntu 22.04·24.04·26.04 LTS 서버의 SSH 터미널**에서 실행합니다. 먼저 AWS 보안그룹의 22·443·5601·9200 접근을 승인된 IP로 제한하세요. 메모리 8GiB 이상을 권장하며, 설치기는 최소 6GiB RAM·10GiB 여유 디스크를 확인합니다.

```bash
# git이 없는 새 서버에서만 먼저 실행
sudo apt-get update
sudo apt-get install -y --no-remove --no-upgrade git

git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
sh deploy/server/install-ubuntu.sh --dry-run
sudo sh deploy/server/install-ubuntu.sh
```

실행 전 `deploy/server/install-ubuntu.sh`를 검토하세요. 스크립트는 **누락된 필수 패키지 → Docker·Compose → 커널 설정 → 인증서·비밀번호 준비 → 중앙 서비스 기동 → 로컬 HTTPS 확인**을 진행합니다. 공인 IP/도메인, EC2 프라이빗 IP, 설치 승인(`y`/`yes`, 대소문자 무관 또는 기존 `INSTALL`), 포털 비밀번호를 순서대로 입력합니다. 빈 입력이나 다른 값은 설치를 중단합니다. 패키지·컨테이너 다운로드에 인터넷 연결이 필요합니다.

Ubuntu 버전·코드명을 확인해 Docker 저장소를 `jammy`/`noble`/`resolute`로 선택합니다. 모든 과거·미래 버전의 호환성을 보장하지 않으며, 현재 설치 대상 외 버전은 변경 전에 중단합니다. 범위는 [Docker 공식 Ubuntu 지원 목록](https://docs.docker.com/engine/install/ubuntu/#os-requirements)에 맞췄습니다. **중앙 서버 지원 확대이며 Ubuntu 에이전트 설치기는 별도로 22.04만 지원합니다.**

기존 서버 상태·중앙 볼륨·포트 충돌은 자동 삭제하거나 덮어쓰지 않습니다. `--dry-run`은 계획 출력만 하며 설치 가능 여부를 검증하지 않습니다. 완료 후 [가이드 6절](docs/aws_windows_e2e_test.md#6-windows에-ca-공개-인증서-전달신뢰)부터 Windows 인증서 신뢰·에이전트 설치·실제 로그 수신을 확인하세요. **PC 에이전트와 AWS 보안그룹은 이 스크립트가 자동 설치·변경하지 않습니다.**

## 1. 설치 경로 선택

| 목적 | 진행 순서 | 결과 |
| --- | --- | --- |
| 중앙 서버와 에이전트 설치 파일 관리 화면 | [중앙 서버 가이드](deploy/server/README.md) | HTTPS ES·Kibana·포털, OS별 실제 설치 묶음과 수집 키 |
| 에이전트 실제 수신 현황 | [접속 현황 및 기존 서버 업데이트](docs/agent_status.md) | 수집기별 마지막 수신·지연 상태·호스트 정보 |
| 개발 PC에서 저장소·탐지 코드 실행 | 2 → 3 | 로컬 Elasticsearch/Kibana 및 Python 실행환경 |
| Ubuntu 서버 로그 수집 | 2 → 4 → 5 → 7 | Filebeat 설치 및 원격 수신 서버 연결 |
| Windows 서버 로그 수집 | 2 → 4 → 6 → 7 | Filebeat 설치 및 이벤트·파일 로그 수집 |
| 서버 네트워크 통신 수집 | [네트워크 추가 설치](deploy/agents/NETWORK.md) | 별도 Packetbeat 서비스, 통신 흐름·DNS·TLS 메타데이터 |
| 화면 모양만 확인 | 3의 화면 미리보기 | 샘플 데이터 기반 정적 UI |

에이전트 설치는 **각 서버에서 설치 명령 한 번 실행 + API 키 입력** 방식입니다. 포털에서 스크립트·CA 공개 인증서 묶음을 다운로드하거나 관리자가 직접 전달합니다. 중앙에서 여러 서버에 원격 자동 설치하는 기능은 아니며 에이전트 서버에 Python이나 Docker는 필요 없습니다. Windows EXE 대신 ZIP, Ubuntu는 tar.gz를 제공합니다.

네트워크 수집은 기존 로그 수집기와 독립된 추가 설치입니다. 수집 NIC를 명시하고 네트워크 전용 API 키를 사용합니다. 원본 PCAP은 저장하지 않으며 Windows는 Npcap을 먼저 준비합니다. `soc-network-*` 조회는 Kibana에서 검증하고, 기존 SSH 탐지·정적 대시보드에는 아직 자동 연결되지 않습니다.

### 지원 범위

| 구성 요소 | 버전 또는 조건 |
| --- | --- |
| Elasticsearch / Kibana | Compose에 고정된 9.5.2 |
| 중앙 서버 설치기 | Ubuntu 22.04·24.04·26.04 LTS + systemd, amd64/arm64. 버전별 설치 분기 지원, 실제 서버 검증은 별도 |
| Ubuntu 수집기 | Ubuntu 22.04 + systemd, x86_64 또는 ARM64, Filebeat 9.5.2 |
| Windows 수집기 | Windows x86_64, 64비트 관리자 PowerShell, Filebeat 9.5.2 (`winlog` + 파일 입력) |
| Python 개발환경 | Python 3.10 이상, `venv`, `requirements.txt` |
| 설치기 테스트 | Node.js, Bash, Windows에서는 PowerShell 7(`pwsh`) |

Windows 설치기는 PowerShell 5.1 문법으로 작성했으며 5.1 구문 검사와 7에서의 오프라인 테스트를 수행했습니다. 실제 OS의 Beat 지원 여부와 서비스 동작은 배포할 서버에서 확인해야 합니다.

## 2. 저장소 준비

Git이 설치된 환경에서 실행합니다. 이후 명령은 별도 안내가 없으면 저장소 루트 기준입니다.

```shell
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
```

이미 저장소가 있다면 새로 복제하지 않아도 됩니다. 로컬 변경 사항을 확인한 후 필요한 버전을 가져오세요. 배포에는 검토한 커밋의 파일을 사용하고, 원격 스크립트를 확인 없이 다운로드와 동시에 실행하지 않습니다.

| 파일 | 용도 |
| --- | --- |
| [compose.yaml](compose.yaml) | 로컬 Elasticsearch·Kibana 실행 |
| [중앙 서버 Compose](deploy/server/compose.yaml) | Ubuntu 서버 HTTPS·인증·배포 포털 |
| [중앙 서버 설치 안내](deploy/server/README.md) | 인증서 준비·포털 사용·접근 제한·실제 수신 확인 |
| [.env.example](.env.example) | Python 연결 설정 예제 |
| [Ubuntu 설치기](deploy/agents/install-ubuntu.sh) | Filebeat 신규 설치 |
| [Windows 설치기](deploy/agents/install-windows.ps1) | Filebeat 신규 설치 및 소스 자동 탐색 |
| [인덱스 템플릿](deploy/agents/index-template.json) | 중앙 수신 인덱스의 최소 매핑 |
| [게시 권한 예제](deploy/agents/publisher-role.json) | 에이전트 API 키의 권한 범위 |
| [에이전트 상세 안내](deploy/agents/README.md) | 설치 동작·보안·제약 사항 |

## 3. 로컬 개발환경 실행

이 절은 **Windows 개발 PC의 PowerShell** 기준입니다. Git, Python, Docker Desktop과 Docker Compose가 준비되어 있어야 합니다. 원격 에이전트만 설치하려면 4절로 이동합니다.

### Elasticsearch와 Kibana

Docker Desktop을 실행한 뒤 다음 명령을 실행합니다.

```powershell
docker compose up -d
docker compose ps
```

초기 실행은 이미지 다운로드와 서비스 기동에 시간이 걸릴 수 있습니다.

- [Elasticsearch 로컬 주소](http://localhost:9200)에서 클러스터 정보 JSON을 확인합니다.
- [Kibana 로컬 주소](http://localhost:5601)에서 화면을 확인합니다.

기동되지 않으면 로그를 확인합니다.

```powershell
docker compose logs --tail 100 elasticsearch kibana
```

현재 포트는 `127.0.0.1`에만 연결됩니다. 인증 없는 9200·5601 포트를 외부로 열지 않습니다.

### Python 가상환경과 연결 검사

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
.\.venv\Scripts\python.exe -m cloud_soc.elastic.client
$LASTEXITCODE
```

가상환경 활성화는 필수가 아닙니다. 위처럼 가상환경의 Python을 직접 실행하면 됩니다. `.env`가 이미 있으면 덮어쓰지 않습니다.

로컬 개발용 `.env` 설정은 다음과 같습니다.

```dotenv
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_USERNAME=
ELASTICSEARCH_PASSWORD=
```

성공 시 연결 성공 메시지, 클러스터 이름, 버전이 출력되고 종료 코드는 `0`입니다. 실패하면 `1`입니다. `PYTHONPATH`는 현재 PowerShell에만 적용되므로 새 터미널에서는 다시 지정합니다. 패키지명은 `cloud_soc`이며 `cloud\_soc`가 아닙니다.

### 기존 SSH 탐지 파이프라인 실행

기존 수집 경로로 `raw-logs-*`에 `labels.log_source=linux_auth`인 SSH 로그가 들어온 경우에만 해당 데이터를 처리합니다.

**기존 인덱스를 사용 중이면 먼저 [파이프라인 보완·적용 안내](docs/pipeline_reliability.md)를 확인하세요.** 경보 근거 보존용 필드 매핑이 없으면 일반 실행은 중단됩니다. 아래 준비 명령은 실제 클러스터의 매핑에 새 필드를 추가하지만 기존 문서를 삭제하거나 다시 쓰지 않습니다. 이 준비 작업은 이번 코드 수정 과정에서 실제 서버에 실행하지 않았습니다.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
.\.venv\Scripts\python.exe -m cloud_soc.main --prepare-lineage-mappings
$LASTEXITCODE
```

준비 명령이 `0`으로 끝났는지 확인한 후 파이프라인을 실행합니다. 원본에는 유효한 `organization.id`와 시간대가 포함된 `event.created` 또는 `@timestamp`가 필요합니다. syslog 소스 시간대의 기본값은 `UTC`이며 다른 환경은 `--source-timezone=+09:00`처럼 지정합니다.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
.\.venv\Scripts\python.exe -m cloud_soc.main
```

종료 코드는 정상 완료 `0`, 처리 실패 `1`, 잘못된 문서가 포함된 배치 `2`, Ctrl+C 중단 `130`입니다. 이 파이프라인은 10,000건을 넘는 로그도 조회하지만 아직 영속 체크포인트 없이 전체 배치를 반복 처리합니다. 기존 문서는 덮어쓰지 않으며 규칙이나 근거가 변경되면 새 경보 ID를 사용합니다. 과거 경보와 새 경보가 함께 보일 수 있습니다.

반복 처리하려면 마지막 명령 대신 다음을 실행합니다. 실행 중에는 정규화 이벤트와 탐지 결과가 Elasticsearch에 저장될 수 있습니다.

```powershell
.\.venv\Scripts\python.exe -m cloud_soc.main --watch --interval 5
```

기존 [Filebeat 설정](filebeat/filebeat.yml)의 `127.0.0.1:19200`은 기존 터널 환경을 전제로 한 값입니다. 새 서버에 그대로 적용하지 마세요. 이번 에이전트 설치기는 별도 인덱스를 사용하므로 이 Python 파이프라인과 아직 자동 연결되지 않습니다.

### 화면 미리보기

별도 터미널에서 다음 명령을 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m http.server 8765 --bind 127.0.0.1 --directory prototype
```

[관제 메인 화면](http://localhost:8765/index.html)과 [조사 화면](http://localhost:8765/workbench.html)을 확인할 수 있습니다. 이 화면은 샘플 데이터 기반 정적 프로토타입이며 실제 로그 조회 API나 분석 결과 저장 기능이 아닙니다.

## 4. 원격 수집을 위한 중앙 서버 준비

**이 절을 완료한 뒤에만 5·6절의 실제 설치를 진행합니다.** 새 중앙 서버는 [전용 설치 가이드](deploy/server/README.md)를 사용하면 인증서·계정·템플릿·배포 포털을 준비할 수 있습니다. 아래 내용은 기존 보안 클러스터에 수동 연결할 때의 참고 절차입니다. 중앙 가이드로 설치했다면 템플릿과 키를 중복 준비할 필요가 없습니다. 개발용 Compose를 보안 설정 없이 원격 수신용으로 전환하지 않습니다.

### HTTPS·인증서·네트워크

1. 인증이 활성화된 Elasticsearch HTTPS 주소를 준비합니다. 기존 보안 클러스터를 사용하거나 관리자가 별도 보안 구성을 수행해야 합니다.
2. 연결할 DNS/IP가 서버 인증서 SAN과 일치하도록 구성하고, 서버 인증서를 검증할 CA PEM 파일을 준비합니다. 클라이언트 통신 암호화는 [Elastic HTTPS 설정 안내](https://www.elastic.co/docs/deploy-manage/security/set-up-basic-security-plus-https)를 참고합니다.
3. 사설망/VPN과 방화벽 허용 목록으로 필요한 수집 서버만 접근하도록 제한합니다. 여러 노드로 구성하는 경우 [노드 간 TLS 설정](https://www.elastic.co/docs/deploy-manage/security/set-up-basic-security)도 필요합니다.
4. CA 공개 인증서만 수집 서버에 전달합니다. CA 개인키, 서버 개인키, 관리자 자격증명은 에이전트에 전달하지 않습니다.

`xpack.security.enabled=true` 한 줄 변경만으로 HTTPS 전환이 완료되지는 않습니다. Kibana·healthcheck·기존 Python 클라이언트 연결 설정도 함께 검토해야 합니다. 현재 Python 클라이언트는 에이전트의 CA·API 키 설정을 공유하지 않습니다.

### 인덱스 템플릿

보안 클러스터의 Kibana Dev Tools에서 관리자 권한으로 다음 요청을 실행합니다. 본문에는 [index-template.json](deploy/agents/index-template.json)의 **JSON 객체 전체**를 넣습니다.

```http
PUT /_index_template/cloud-soc-host-raw-v1
```

템플릿 우선순위 충돌과 적용될 매핑은 다음 요청으로 확인합니다.

```http
POST /_index_template/_simulate_index/soc-host-raw-linux-9.5.2-2099.01.01
```

이 템플릿은 최소 공통 필드만 정의하며 완전한 ECS 템플릿이나 보존 정책이 아닙니다. 복제본은 1개이므로 단일 노드 실습 환경에서는 미할당 복제본이 생깁니다. 관리자가 환경에 맞는 복제본 수, 보존 기간, 용량 경보, 조회 역할을 결정해야 합니다.

### 서버별 수집용 API 키

서버마다 다른 이름과 만료 기간으로 키를 발급합니다. 관리자 계정의 비밀번호를 설치 명령에 사용하지 않습니다.

```http
POST /_security/api_key
{
  "name": "cloud-soc-ubuntu-01",
  "expiration": "30d",
  "role_descriptors": {
    "cloud_soc_publisher": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["soc-host-raw-*"],
          "privileges": ["auto_configure", "create_doc"]
        }
      ]
    }
  }
}
```

발급자는 위 권한을 실제로 보유해야 합니다. 중앙 인덱스 자동 생성 정책도 `soc-host-raw-*`를 허용해야 합니다. 에이전트에는 조회·삭제·템플릿 관리 권한을 부여하지 않습니다.

응답의 `id`와 `api_key`를 콜론으로 연결한 **`id:api_key`** 값을 설치 중 프롬프트에 입력합니다. `encoded` 값은 사용하지 않습니다. 키를 명령줄, README, Git에 기록하지 마세요.

`organization.id`는 분류 태그이지 테넌트 접근 통제 기능이 아닙니다. 다중 조직 운영에는 조직별 인덱스·권한·서버 측 검증이 추가로 필요합니다.

## 5. Ubuntu 22.04 에이전트 설치

기본 수집 대상은 **시스템 journald와 `/var/log` 전체 하위 디렉터리에서 자동 발견한 텍스트 로그**입니다. 파일명을 하나씩 등록할 필요가 없고, 새 파일도 1분 주기 탐색 후 반영됩니다. **systemd가 실행 중인 Ubuntu 22.04 신규 수집 서버**에서 진행합니다.

필수 도구는 `curl`, `tar`, `sha512sum`, `sha256sum`, `timeout`, `realpath`, `pgrep`, `systemctl`, `find`, `file`, `flock`, `sort`, `cmp`, `journalctl`입니다. 설치기는 누락된 패키지나 로깅 서비스를 자동 설치하지 않습니다. 설치 스크립트와 같은 폴더에 `discover-linux.sh`도 있어야 합니다.

```bash
uname -m
systemctl is-system-running
sudo journalctl --no-pager -n 0
```

`auth.log`나 `syslog`가 없어도 journald 수집을 구성할 수 있습니다. 기존 Filebeat·Elastic Agent가 있으면 중복 수집을 막기 위해 설치를 거부하므로 전환 계획을 먼저 세웁니다.

### 미리보기

아래 `soc.example.invalid`는 실제로 연결되지 않는 예시 주소입니다. 실제 설치에서는 중앙 HTTPS 주소와 전달받은 CA 파일의 절대 경로로 교체합니다.

```bash
bash deploy/agents/install-ubuntu.sh --endpoint https://soc.example.invalid:9200 --ca /etc/cloud-soc-ca.crt --organization school --dry-run
```

### 설치 명령 한 번 실행

```bash
sudo bash deploy/agents/install-ubuntu.sh --endpoint https://soc.example.invalid:9200 --ca /etc/cloud-soc-ca.crt --organization school
```

API 키 입력 후 다운로드·SHA-512 검사·설정 생성·설정 및 연결 검사·서비스 등록을 진행합니다. 일반 대화형 터미널에서 실행해야 합니다.

Nginx·audit 등의 로그가 `/var/log` 아래에 있으면 자동 탐색됩니다. 별도 서비스가 다른 위치에 기록한다면 **최초 설치 명령에** `--log-root /srv/myapp/logs`처럼 로그 디렉터리를 추가합니다. 해당 경로 아래 파일도 재귀 탐색합니다. 기존 `--log-file`은 호환 목적으로만 남아 있으며 `/var/log` 자동 탐색에 이미 포함됩니다. 일반 문서·비밀키를 수집하지 않도록 전체 디스크를 탐색하지 않습니다.

## 6. Windows 에이전트 설치

기본 수집 대상은 **자동 발견한 모든 활성 Admin/Operational 이벤트 채널**과 표준 로그 디렉터리의 텍스트 파일입니다. `Application`·`Security`·`System` 3개로 제한하지 않습니다. 설치기와 `discover-windows.ps1`, `download-windows.ps1`을 함께 준비하고, 검토된 스크립트를 실행할 수 있는 조직 정책 아래에서 **64비트 관리자 PowerShell**을 사용합니다. Windows 시스템 `curl.exe`가 필요합니다.

CA 파일을 예를 들어 `C:\certs\cloud-soc-ca.crt`에 준비하고, 실제 존재하는 채널을 확인합니다.

```powershell
Get-WinEvent -ListLog * -Force | Select-Object LogName,IsEnabled,LogType
```

### 미리보기

```powershell
.\deploy\agents\install-windows.ps1 -Endpoint https://soc.example.invalid:9200 -CaPath C:\certs\cloud-soc-ca.crt -Organization school -DryRun
```

### 설치 명령 한 번 실행

```powershell
.\deploy\agents\install-windows.ps1 -Endpoint https://soc.example.invalid:9200 -CaPath C:\certs\cloud-soc-ca.crt -Organization school
```

예시 주소와 CA 경로를 실제 값으로 바꾸고, 설치 중 API 키를 입력합니다.

활성화된 PowerShell·Defender·Sysmon 등의 채널은 이름을 지정하지 않아도 탐색됩니다. `-AdditionalChannel`은 수집 범위를 제한하는 옵션이 아니라 **반드시 존재해야 하는 채널을 검사**하는 옵션입니다.

```powershell
-AdditionalChannel 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational'
```

위 옵션은 단독 명령이 아닙니다. 지정한 채널이 존재하고 활성화되어 있어야 하며, 설치기는 Sysmon 설치나 감사 정책 변경, 채널 활성화를 수행하지 않습니다.

파일 로그는 `%SystemRoot%\Logs`, `%SystemRoot%\System32\LogFiles`, `%SystemDrive%\inetpub\logs`, `%ProgramData%\logs`를 재귀 탐색합니다. 다른 앱의 로그 디렉터리는 `-AdditionalLogRoot 'D:\MyApp\logs'`로 추가합니다. 새 파일과 새로 활성화된 지원 채널은 1분 주기로 재탐색합니다.

신규 Windows 수집기는 이벤트와 파일을 함께 처리하는 **Filebeat**를 사용합니다. 기존 Winlogbeat 설치를 자동으로 교체하거나 registry를 이전하지 않습니다.

스크립트가 실행 정책에 막히면 서명 등 조직이 승인한 배포 절차를 사용합니다. 실행 정책이나 인증서 검증을 우회하지 않습니다.

## 7. 설치 후 실제 로그 확인

미리보기는 설정 출력만 수행합니다. 네트워크·파일·서비스를 변경하지 않으며 OS·CA·로그 소스·기존 설치 상태의 실물 검증도 하지 않습니다. **미리보기 성공은 설치 가능 판정이 아닙니다.**

### 서비스 확인

Ubuntu:

```bash
sudo systemctl status cloud-soc-filebeat --no-pager
sudo systemctl status cloud-soc-discovery.timer --no-pager
sudo journalctl -u cloud-soc-filebeat -n 100 --no-pager
```

Windows:

```powershell
Get-Service cloud-soc-filebeat
Get-ScheduledTaskInfo -TaskName Cloud-SOC-Discovery
Get-ChildItem "$env:ProgramFiles\Cloud-SOC-Agent\logs"
```

| 대상 | 설치 위치 | 실행 계정 |
| --- | --- | --- |
| Ubuntu | `/opt/cloud-soc-agent` | root |
| Windows | `%ProgramFiles%\Cloud-SOC-Agent` | LocalSystem |

설정·CA·keystore·registry·디스크 큐는 설치 경로 아래에 있습니다. 서비스 계정의 파일 접근, TLS 오류, 401/403, bulk 저장 실패를 에이전트 로그에서 확인합니다.

두 OS 모두 설치 경로의 `discovery-report.json`에 선택된 파일·채널과 제외 사유를 기록합니다. 보고서의 `selected`는 설정에 포함했다는 의미이며 실제 전송 성공을 뜻하지 않습니다. Linux 탐색 디렉터리는 `discovery-roots.txt`, Windows는 `discovery-settings.json`에 기록됩니다. 설정 변경은 관리자만 수행해야 합니다.

### Kibana에서 수신 확인

1. 조회 권한이 있는 계정으로 **에이전트가 연결된 클러스터의 Kibana**에 접속합니다.
2. `soc-host-raw-*` Data View를 만들고 시간 필드로 `@timestamp`를 선택합니다.
3. 테스트 서버에서 승인된 정상 로그인 등 새 이벤트를 한 건 발생시킵니다.
4. Discover에서 해당 서버의 `host.name`, `agent.id`, `organization.id`, `labels.log_source`, `message`를 확인합니다. Windows는 `winlog.channel`, `event.code`도 확인합니다.
5. 원본과 시간·호스트·내용이 일치하는지 확인하고, 재부팅 후 자동 시작과 일시 연결 장애 후 재전송도 별도로 검증합니다.

서비스 실행과 연결 검사 통과는 **문서 저장 성공을 보장하지 않습니다.** 문서가 보이지 않으면 Kibana 시간 범위와 에이전트의 인덱싱 오류부터 확인합니다.

### 기존 탐지와의 관계

```text
기존 SSH 경로: raw-logs-* → Python SSH 파서 → normalized-events → security-alerts
신규 수집 경로: Ubuntu/Windows 에이전트 → soc-host-raw-* → Kibana Discover
```

신규 수집 데이터는 기존 SSH 파이프라인과 충돌하지 않도록 분리했습니다. Windows·일반 파일 로그의 파싱, 탐지 규칙, 조회 API, 정적 대시보드와의 실데이터 연결은 후속 구현 사항입니다.

## 8. 문제 해결

**명령은 안내된 운영체제의 터미널에서 실행합니다.** `PS C:\...>`, `ubuntu@...$`, `>>`, 코드블록의 시작·끝 표시와 `bash`/`powershell` 언어 표시는 입력하지 않습니다. 비밀번호·API 키·개인키·실제 운영 로그는 오류 보고나 Git에 포함하지 않습니다.

### 중앙 서버 설치와 웹 접속

| 발생한 증상 | 원인과 조치 |
| --- | --- |
| `Only Ubuntu 22.04 is supported` | 구버전 중앙 설치기의 제한. 현재 중앙 설치기는 22.04·24.04·26.04 LTS와 각 OS 코드명을 지원합니다. 로컬 Git 변경을 확인하고 검토한 수정본을 적용하세요. 모든 Ubuntu 버전을 허용하거나 다른 버전의 Docker 저장소를 강제하지 않습니다. Ubuntu 에이전트는 여전히 22.04 대상입니다. |
| 비밀번호 입력 후 `Preparation failed (ValueError)` | 구버전은 길이 부족 등 여러 검증 오류를 같은 문구로 표시했습니다. 이 오류만으로 원인을 확정하지 않습니다. 현재 비밀번호는 빈 값만 거부하며 확인 입력이 일치해야 합니다. 상태 폴더 존재 여부부터 확인하는 [재시도 절차](deploy/server/README.md#실패재시도)를 따릅니다. |
| 설치 승인에 `yes`를 입력했는데 중단 | 구버전은 `INSTALL`만 허용했습니다. 현재 수정본은 `y`/`yes`를 대소문자 구분 없이 허용하며 기존 `INSTALL`도 지원합니다. 원격 서버에 수정본을 반영해야 적용됩니다. 빈 입력과 `no`는 중단합니다. |
| ES가 재시작하며 `ELASTIC_PASSWORD_FILE ... actually has: 644` 출력 | 비밀번호 내용이 아니라 해당 파일 권한 문제입니다. 기본 Docker 구성에서는 기존 `secrets/elastic_password` 파일 하나를 소유자 `1000:0`, 권한 `0400`으로 교정합니다. [정확한 권한 복구 명령](deploy/server/README.md#기존-설치의-elasticsearch-비밀번호-파일-권한-복구)을 사용하고 재설치·비밀번호 재생성·재귀 권한 변경은 하지 않습니다. |
| 집 PC에서 EC2의 `http://10.x.x.x:5601` 접속 실패 | 프라이빗 IP는 VPN 등 별도 내부망 경로 없이 인터넷에서 직접 접근할 수 없습니다. 중앙 구성은 HTTP가 아닌 HTTPS입니다. 브라우저에는 설치 때 지정한 공인 DNS/IP를 사용하고, 서버 바인딩에는 실제 EC2 프라이빗 IP를 사용합니다. 보안그룹은 승인된 출발지 IP만 허용합니다. |
| 포털·Kibana 모두 `ERR_SSL_PROTOCOL_ERROR` | TLS 협상 실패입니다. 같은 Caddy 버전에서 공인 IP와 Docker/NAT 내부 IP가 다르고 클라이언트가 SNI를 보내지 않을 때의 인증서 선택 오류를 재현했습니다. [Caddy 복구 절차](deploy/server/README.md#공인-ip-접속의-tls-오류-복구)에 따라 전역 블록의 `default_sni {$SOC_PUBLIC_HOST}`를 확인하고 설정 검증 성공 후 gateway만 재시작합니다. 다른 원인의 TLS 오류까지 이 설정으로 해결되는 것은 아닙니다. |
| `ERR_CERT_AUTHORITY_INVALID` | TLS 프로토콜 오류와 별개인 CA 신뢰 문제입니다. [공개 CA 해시 확인·Windows 등록](docs/aws_windows_e2e_test.md#6-windows에-ca-공개-인증서-전달신뢰)을 진행합니다. 인증서 경고를 무시하거나 TLS 검증을 끄지 않습니다. |
| `logs --since 10m ... gateway` 결과가 비어 있음 | 그 시간 안에 기록된 로그가 없다는 뜻입니다. 시작 시각이 더 이전이거나 TLS 실패가 기본 로그 수준에 기록되지 않을 수 있습니다. 빈 출력만으로 HTTPS가 정상이라고 판단하지 않습니다. |

**Ubuntu 서버의 기존 체크아웃 루트**에서 상태와 시작 로그를 먼저 확인합니다. 아래 명령은 설치나 재시작을 하지 않습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --tail 100 gateway
```

정상 기동 기준은 Elasticsearch `healthy`, bootstrap `Exited (0)`, portal·kibana·gateway 실행 중입니다. **bootstrap은 준비 작업 후 종료되는 것이 정상**이며, 나머지 컨테이너의 `Up`만으로 HTTPS·로그인·실제 문서 수신이 검증되지는 않습니다. `state/server/compose.env`까지 생성된 기존 서버는 설치기를 반복 실행하지 말고 같은 상태를 사용하는 Compose 복구 절차를 따릅니다. `state/server`나 데이터 볼륨을 삭제하지 않습니다.

브라우저에서 키 파일을 매번 입력하는 구조는 아닙니다. AWS `.pem`은 SSH 관리용 개인키이며 웹 로그인용이 아닙니다. `ca.cer`/`ca.crt`는 서버를 신뢰하기 위한 공개 인증서로, 현재 사설 CA 구성에서는 브라우저를 사용하는 PC에 최초 신뢰 등록이 필요합니다. **`server.key`·`ca.key`는 PC나 에이전트에 배포하지 않습니다.**

| 화면 | 설치한 공인 DNS/IP를 사용하는 HTTPS 경로 | 로그인 |
| --- | --- | --- |
| Cloud SOC 메인 | `https://<공인-DNS-또는-IP>/index.html` | `admin` / 설치 때 입력한 포털 비밀번호 |
| 에이전트 설치·키 관리 | `https://<공인-DNS-또는-IP>/agents.html` 또는 `/` | 포털 계정 |
| Kibana | `https://<공인-DNS-또는-IP>:5601` | 별도 `cloud_soc_analyst` 계정 |

`<공인-DNS-또는-IP>` 표시는 실제 주소로 바꿉니다. 현재 자체 메인·조사·로그 목록 화면은 데모 데이터이며, 실제 수신은 Kibana Discover에서 확인합니다. `soc.example.invalid`나 `preview-*`, 정적 미리보기의 `Failed to fetch`는 실제 중앙 포털과 혼동하지 않도록 확인하세요.

### Windows ZIP 경로와 해시 오류

`Resolve-Path: '.\이름-setup.zip' 경로는 존재하지 않습니다` 뒤에 `SHA-256 mismatch`가 이어졌다면 **파일이 없어서 해시를 계산하지 못한 것인지 먼저 확인**합니다. 예를 들어 `Downloads\이름-setup`은 압축을 푼 폴더이고, ZIP은 상위 `Downloads\이름-setup.zip`에 있을 수 있습니다. 경로 오류만으로 변조나 실제 체크섬 불일치라고 판단하지 않습니다.

```powershell
Get-Location
Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'Downloads') -Filter '*-setup.zip'
```

실제 ZIP의 절대 경로와 **현재 포털의 해당 패키지 SHA-256**으로 검증합니다. 이전 패키지의 해시를 재사용하지 않습니다. 아래는 검증만 하며 압축 해제나 설치를 하지 않습니다.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $Zip = (Read-Host '다운로드한 ZIP의 절대 경로').Trim().Trim('"')
    if (-not [IO.Path]::IsPathRooted($Zip)) { throw 'Use an absolute ZIP path.' }
    if (-not (Test-Path -LiteralPath $Zip -PathType Leaf)) { throw 'ZIP file not found. Check its location.' }
    $ExpectedHash = (Read-Host '현재 포털에 표시된 SHA-256 64자리').Trim()
    if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid SHA-256.' }
    $ActualHash = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($ActualHash -ine $ExpectedHash) { throw 'SHA-256 mismatch. Stop installation.' }
    Write-Host 'ZIP SHA-256 verified. No installation performed.'
}
```

파일이 실제로 존재하는데 해시가 다르면 설치를 중단하고 출처·패키지 버전·다운로드를 확인합니다. 검증을 생략하지 않습니다. 이미 압축을 풀었다면 같은 폴더에 `Expand-Archive -Force`로 덮어쓰지 말고, 그 파일들이 검증된 ZIP과 같은 내용인지 확인하세요. 확신할 수 없으면 [새 폴더에 검증 후 압축 해제](docs/aws_windows_e2e_test.md#windows-해시-검증압축-해제) 절차를 사용합니다.

### Windows NIC GUID 문법 오류

`'[' 뒤에 형식 이름이 없습니다` / `MissingTypename`은 `[guid]` 자리에 실제 GUID를 넣어서 발생할 수 있습니다. **`[guid]`는 PowerShell 자료형 이름이므로 수정하지 않습니다.** GUID 값은 `Read-Host`가 입력을 요청할 때 입력합니다. `실제-NIC-GUID`나 `<...>` 같은 설명 문구를 그대로 인자로 넣지 않습니다.

먼저 자신의 수집 승인 대상인 이더넷/Wi-Fi 장치를 확인합니다. `Up`인 장치가 여러 개면 임의로 첫 번째 것을 고르지 말고 필요한 장치를 선택합니다.

```powershell
Get-NetAdapter -Physical | Select-Object Name, Status, InterfaceGuid
```

아래는 네트워크 포함 패키지의 **설정 미리보기**입니다. 코드는 그대로 실행하고 프롬프트에 실제 값을 입력합니다. 실제 설치·패킷 캡처는 하지 않습니다.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $AgentDir = (Read-Host '검증한 패키지를 압축 해제한 폴더의 절대 경로').Trim().Trim('"')
    if (-not [IO.Path]::IsPathRooted($AgentDir)) { throw 'Use an absolute package directory.' }
    $NicGuid = ([guid](Read-Host '수집할 장치의 InterfaceGuid 값 입력')).ToString()
    if ([guid]$NicGuid -eq [guid]::Empty) { throw 'An empty NIC GUID is not allowed.' }
    & (Join-Path $AgentDir 'install.ps1') -InterfaceGuid $NicGuid -DryRun
    if ($LASTEXITCODE -ne 0) { throw 'Dry run failed. Do not install yet.' }
}
```

미리보기는 Npcap·NIC 상태·서버 연결을 검증하지 않습니다. 실제 설치에서는 승인된 x64 Npcap이 실행 중이어야 하고 선택한 NIC가 `Up`이어야 합니다. 준비 후 같은 명령에서 `-DryRun`을 제거하면 서비스 설치와 실제 수집을 시작하므로 수집 권한·범위를 먼저 확인하세요. Filebeat용과 Packetbeat용 API 키를 각각 해당 입력 단계에 사용합니다. NIC를 모른다는 이유로 전체 장치를 자동 선택하지 않습니다.

### Windows 미서명 스크립트 차단

`파일이 디지털 서명되지 않았습니다` / `PSSecurityException` / `UnauthorizedAccess`는 실행 정책이나 인터넷 다운로드 출처 표시로 인해 발생할 수 있습니다. 실제 설치에 사용할 **관리자 PowerShell 창에서** 정책을 확인합니다. 관리자 권한만으로 서명 요건이 없어지는 것은 아닙니다.

```powershell
Get-ExecutionPolicy -List
Get-ExecutionPolicy
```

- 유효 정책이 `RemoteSigned`이고, ZIP 해시·추출 파일·스크립트 내용·출처를 검토하여 실행을 승인한 경우에만 해당 파일의 차단 표시를 해제합니다.
- `AllSigned`, `Restricted` 또는 조직 정책에 의해 차단된 경우에는 관리자에게 승인된 서명·배포 절차를 확인합니다. `Unblock-File`로 `AllSigned`의 서명 요건이 없어지지는 않습니다.
- `Bypass`/`Unrestricted`로 정책을 낮추거나 전체 Downloads 폴더를 재귀적으로 차단 해제하지 않습니다. [Microsoft Unblock-File 안내](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file)

**검증한 패키지를 압축 해제한 폴더에서만** 다음을 실행합니다. 로그 전용 패키지는 앞의 3개 파일, 로그+네트워크 패키지는 4개 파일 모두 대상입니다. 이 명령은 서명을 추가하거나 실행 정책을 바꾸지 않고 해당 파일의 다운로드 차단 표시만 제거합니다.

```powershell
Unblock-File -LiteralPath '.\install.ps1'
Unblock-File -LiteralPath '.\install-windows.ps1'
Unblock-File -LiteralPath '.\discover-windows.ps1'
Unblock-File -LiteralPath '.\download-windows.ps1'
```

네트워크 포함 패키지에서만 추가합니다.

```powershell
Unblock-File -LiteralPath '.\install-network-windows.ps1'
```

오류 없이 완료된 뒤 미리보기와 설치를 다시 진행합니다. 계속 서명 오류가 나면 어떤 파일이 차단됐는지 확인하고, 정책을 일괄 해제하거나 실행 방식을 바꿔 우회하지 않습니다.

### 백그라운드 실행과 설치 완료 확인

| 항목 | 정상 설치 후 역할 |
| --- | --- |
| `cloud-soc-filebeat` | 활성 지원 이벤트 채널·지정 로그 디렉터리에서 발견한 파일을 수집하고 중앙 Elasticsearch에 HTTPS 전송 |
| `cloud-soc-packetbeat` | 네트워크 포함 설치에서 선택한 NIC의 통신 흐름·DNS·TLS 메타데이터 전송 |
| `Cloud-SOC-Discovery` | 1분 주기로 로그 소스를 다시 탐색하여 Filebeat 입력 설정 갱신 |
| `npcap` | Packetbeat가 패킷을 읽도록 지원하는 드라이버. 이것만 `Running`이라고 SOC로 전송 중인 것은 아님 |

정상 설치된 두 수집 서비스는 터미널을 닫아도 동작하며 재부팅 후 자동 시작합니다. 대시보드·Elasticsearch는 중앙 서버에 있고 PC에는 수집기가 설치됩니다. 네트워크 수집은 원본 PCAP·HTTP 본문·쿠키를 저장하지 않지만 DNS 이름·IP 등 메타데이터에도 민감정보가 포함될 수 있습니다.

```powershell
Get-Service -Name cloud-soc-filebeat,cloud-soc-packetbeat,npcap -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
Get-ScheduledTask -TaskName Cloud-SOC-Discovery -ErrorAction SilentlyContinue |
    Select-Object TaskName, State
Get-Process -Name filebeat,packetbeat -ErrorAction SilentlyContinue |
    Select-Object Name, Id
```

항목이 없으면 아직 등록되지 않았거나 설치가 중단됐을 수 있습니다. 설치 스크립트의 마지막 오류와 종료 코드를 확인하고 기존 서비스·부분 상태를 삭제하거나 무조건 재설치하지 않습니다. 예약 작업의 `Ready`는 상시 실행 프로세스가 아니라 다음 실행을 기다리는 상태일 수 있으며, 실행 결과는 `Get-ScheduledTaskInfo -TaskName Cloud-SOC-Discovery`로 확인합니다. 서비스가 `Running`이어도 **실제 수신은 [7절의 Kibana 조회](#7-설치-후-실제-로그-확인)로 별도 검증**합니다.

### 이번 문제 해결에서 확인한 범위

2026-09-21 확인 당시의 기록이며 현재 서버·PC 상태를 보장하지 않습니다.

- AWS 출력에서 Elasticsearch `healthy`, bootstrap `Exited (0)`, 나머지 중앙 컨테이너 실행 중인 상태를 확인했습니다. 이것만으로 브라우저 접속과 문서 수신 성공을 확정하지 않았습니다.
- 동일 Caddy 버전의 로컬 컨테이너에서 NAT/IP 무-SNI TLS 오류를 재현하고 수정 후 443·5601 TLS 연결 및 잘못된 CA·호스트 차단을 확인했습니다. 실제 AWS 브라우저 접속 완료 여부와 구분합니다.
- Windows 사례에서는 잘못된 ZIP 상대 경로를 확인했고, 실제 ZIP 해시와 추출 파일 내용은 일치했습니다. NIC 자료형 입력 오류와 `RemoteSigned`·다운로드 표시로 인한 미서명 스크립트 차단도 확인했습니다.
- PC 상태 확인 시 Npcap만 실행 중이었고 SOC 수집 서비스·프로세스·탐색 예약 작업은 확인되지 않았습니다. 따라서 에이전트 설치와 로그·네트워크 문서 수신을 완료한 것으로 기록하지 않습니다.

### 기타 수집·개발 오류

| 증상 | 확인할 내용 |
| --- | --- |
| `No module named 'cloud_soc'` | 저장소 루트에서 `PYTHONPATH=src`를 현재 셸에 지정했는지, 가상환경 Python을 사용했는지 확인 |
| HTTP 주소 거부 | 에이전트는 HTTPS만 허용. 개발용 Compose가 아닌 보안 수신 환경 준비 필요 |
| TLS 연결 실패 | CA PEM 파일, 인증서 만료, DNS/IP와 SAN 일치 여부 확인. 검증을 끄지 않음 |
| API 키 인증/저장 실패 | `id:api_key` 형식, 만료, 대상 인덱스 권한, 중앙 인덱스 자동 생성 정책 확인 |
| 기존 설치 감지 | 기존 서비스·설정·registry를 검토한 후 전환 계획 수립. 무조건 삭제하거나 덮어쓰지 않음 |
| Ubuntu 로그 파일 없음 | journald 수집과 `discovery-report.json`, 탐색 타이머 상태 확인 |
| Windows 채널 없음/비활성 | 보고서의 `disabled`·`unsupported_direct_channel`·`enumeration_error` 확인. 비활성 채널을 자동으로 켜지는 않음 |
| 새 로그가 수집되지 않음 | 탐색 타이머/예약 작업, 실행 정책, 보고서 갱신 시각, 실제 파일 위치와 인코딩 확인 |
| 체크섬 불일치 | 설치 중단 상태 유지. 다운로드 경로·파일·고정 버전을 확인하고 검증을 생략하지 않음 |
| 설치 중 실패 | 0이 아닌 종료 코드와 오류 확인. 보호된 부분 설치 상태를 검토한 뒤 관리자가 복구 |
| 연결은 되지만 로그 없음 | 새 이벤트 생성 여부, Kibana 시간 범위, bulk 매핑 오류, 디스크/큐 상태 확인 |

재설치·업그레이드·키 교체·제거 자동화는 아직 없습니다. 장애 분석 전에 `data` 디렉터리를 지우면 중복 재수집이나 대기 로그 유실이 발생할 수 있습니다.

로컬 개발 컨테이너를 중지만 하려면 `docker compose stop`을 사용합니다. 데이터를 보존해야 한다면 볼륨을 삭제하지 마세요.

### Windows 다운로드가 수십 분 걸리는 경우

구버전의 `웹 요청을 쓰는 중 / 요청 스트림을 쓰는 중` 표시는 PowerShell `Invoke-WebRequest` 다운로드입니다. 바이트 수가 늘어도 정상 속도라는 뜻은 아닙니다. 수십 분씩 기다리지 말고 다운로드 중인 설치 창에서 `Ctrl+C`로 중단한 뒤 부분 설치 상태부터 확인합니다. 창을 닫거나 중단해도 기존 파일·서비스가 자동 복구되지는 않습니다.

최신 Windows 설치기는 시스템 `curl.exe`를 사용합니다. 연결 제한 30초, 1회 전송 제한 300초, 60초 동안 초당 16KiB 미만인 저속 전송을 중단합니다. 일부 통신 오류만 3초 후 한 번 재시도하므로 파일 하나의 네트워크 전송은 최대 약 10분입니다. TLS·HTTP 오류와 SHA-512 실패는 무시하지 않습니다. [curl 옵션 문서](https://curl.se/docs/manpage.html)

**수정한 저장소가 이미 받은 ZIP이나 실행 중인 설치기에 자동 반영되지는 않습니다.** 중앙 서버에 변경을 배포하고 포털 이미지를 다시 빌드한 뒤, 새 이름으로 설치 패키지를 생성하여 새 ZIP·새 해시를 받아야 합니다. 기존 패키지는 생성 당시 내용이 보존됩니다. `download-windows.ps1`이 포함되어야 하며, 기존 실행 정책에 따라 이 보조 파일도 검토·서명 또는 개별 차단 해제가 필요합니다.

중단 후 별도의 관리자 PowerShell에서 다음은 상태만 조회합니다. 파일 내용·API 키는 출력하지 않습니다.

```powershell
Get-Service -Name 'cloud-soc-filebeat','cloud-soc-packetbeat' -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
Get-Item -LiteralPath "$env:ProgramFiles\Cloud-SOC-Agent", "$env:ProgramFiles\Cloud-SOC-Network" -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime
```

**폴더가 남아 있으면 바로 재설치하거나 재귀 삭제하지 않습니다.** 기존 `data`·keystore·서비스 유무를 확인한 후 관리자가 복구해야 합니다. Filebeat 설치 후 Packetbeat 다운로드에서 실패했다면 Filebeat는 정상 실행 중일 수 있으므로 전체 설치를 되풀이하지 않습니다. 실제 전송 속도는 네트워크·프록시·Elastic 배포 서버에 따라 달라지며, 중앙 서버 캐시와 다운로드 이어받기는 아직 구현하지 않았습니다.

## 9. 테스트와 현재 한계

오프라인 설치기 테스트:

```powershell
.\.venv\Scripts\python.exe -m pip install -r deploy/server/requirements.txt
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
node --test prototype/tests/logs.test.cjs deploy/agents/tests/installers.test.cjs deploy/agents/tests/network.test.cjs deploy/agents/tests/download.test.cjs
```

Windows에서는 Git Bash와 `pwsh`가 필요합니다. `BASH_EXE`, `POWERSHELL_EXE` 환경변수로 설치된 실행 파일 경로를 지정할 수 있습니다. 테스트는 실제 에이전트 설치, 중앙 서버 변경, 로그 전송을 수행하지 않습니다.

- 검사 범위: 스크립트 구문, 미리보기 설정, HTTPS·인자 검증, 추가 소스·중복 소스, 체크섬 실패, 기존 설치 거부, 네이티브 명령 실패 전달, 모의 ACL 구성.
- 실제 검증 필요: Ubuntu/systemd 설치, Windows 서비스·LocalSystem 접근, Beat 바이너리의 설정 해석, 실제 CA/API 키 연결, 인덱스 템플릿 적용, 문서 수신과 장애 복구.
- Linux journald·로그 디렉터리와 Windows 활성 지원 이벤트 채널·표준 로그 디렉터리를 자동 탐색합니다. 클라우드 Audit API, Windows Analytic/Debug 직접 채널, 압축·바이너리 아카이브, 임의 위치의 모든 파일까지 수집하는 것은 아닙니다. 상세 범위와 제외 사유는 [자동 수집 계약](deploy/agents/COLLECTION.md)을 확인하세요.
- 설치 파일의 버전과 SHA-512는 고정되어 있습니다. 자동 최신 버전 업데이트가 아니며, 변경 시 두 값을 함께 검토해야 합니다.
- API 키·비밀번호·개인키·실제 운영 로그는 Git에 올리지 않습니다. `.env`는 추적하지 않고 서버별로 관리합니다.

설치 세부 동작과 보안 제약은 [에이전트 상세 안내](deploy/agents/README.md)를 참고하세요.

# Cloud SOC 설치 가이드

Cloud SOC는 Elasticsearch·Kibana와 Python 탐지 엔진을 사용하는 보안관제 프로젝트입니다. 이 문서는 **로컬 개발환경 실행**과 **Ubuntu·Windows 서버의 로그 수집 에이전트 설치**를 안내합니다.

> 현재 저장소의 Docker Compose는 로컬 개발용 HTTP·인증 비활성 구성입니다. 원격 에이전트 설치기는 HTTPS·CA 인증서·API 키가 준비된 수신 서버를 요구합니다. `docker compose up -d`만 실행했다고 원격 수집 준비가 끝나는 것은 아닙니다.

## 1. 설치 경로 선택

| 목적 | 진행 순서 | 결과 |
| --- | --- | --- |
| 개발 PC에서 저장소·탐지 코드 실행 | 2 → 3 | 로컬 Elasticsearch/Kibana 및 Python 실행환경 |
| Ubuntu 서버 로그 수집 | 2 → 4 → 5 → 7 | Filebeat 설치 및 원격 수신 서버 연결 |
| Windows 서버 로그 수집 | 2 → 4 → 6 → 7 | Winlogbeat 설치 및 원격 수신 서버 연결 |
| 화면 모양만 확인 | 3의 화면 미리보기 | 샘플 데이터 기반 정적 UI |

에이전트 설치는 **각 서버에서 설치 명령 한 번 실행 + API 키 입력** 방식입니다. 사전에 스크립트와 CA 파일을 전달해야 하며, 중앙에서 여러 서버에 원격 배포하는 기능은 아닙니다. 에이전트 서버에 Python이나 Docker를 설치할 필요는 없습니다.

### 지원 범위

| 구성 요소 | 버전 또는 조건 |
| --- | --- |
| Elasticsearch / Kibana | Compose에 고정된 9.5.2 |
| Ubuntu 수집기 | Ubuntu 22.04 + systemd, x86_64 또는 ARM64, Filebeat 9.5.2 |
| Windows 수집기 | Windows x86_64, 64비트 관리자 PowerShell, Winlogbeat 9.5.2 |
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
| [.env.example](.env.example) | Python 연결 설정 예제 |
| [Ubuntu 설치기](deploy/agents/install-ubuntu.sh) | Filebeat 신규 설치 |
| [Windows 설치기](deploy/agents/install-windows.ps1) | Winlogbeat 신규 설치 |
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

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
.\.venv\Scripts\python.exe -m cloud_soc.main
```

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

**이 절을 완료한 뒤에만 5·6절의 실제 설치를 진행합니다.** HTTPS 수신 서버를 자동 구성하는 스크립트는 아직 제공하지 않습니다. 현재 개발용 Compose를 보안 설정 없이 원격 수신용으로 전환하지 않습니다.

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

기본 수집 대상은 `/var/log/auth.log`, `/var/log/syslog`입니다. **systemd가 실행 중인 Ubuntu 22.04 신규 수집 서버**에서 진행합니다.

필수 도구는 `curl`, `tar`, `sha512sum`, `sha256sum`, `timeout`, `realpath`, `pgrep`, `systemctl`입니다. 설치기는 누락된 패키지나 로깅 서비스를 자동 설치하지 않습니다.

```bash
uname -m
systemctl is-system-running
sudo ls -l /var/log/auth.log /var/log/syslog
```

로그 파일이 없으면 rsyslog 등 서버의 로깅 설정부터 점검합니다. 기존 Filebeat·Elastic Agent가 있으면 중복 수집을 막기 위해 설치를 거부하므로 전환 계획을 먼저 세웁니다.

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

추가 텍스트 파일을 수집하려면 **최초 설치 명령에** `--log-file /var/log/nginx/access.log` 같은 옵션을 추가합니다. 여러 번 지정할 수 있지만 실제 읽을 수 있는 일반 파일이어야 합니다. `/var/log` 외부 경로, 심볼릭 링크, 와일드카드, 공백·특수문자가 있는 경로는 지원하지 않습니다. 설치 후 같은 명령을 다시 실행하여 설정을 갱신하는 방식은 지원하지 않습니다.

## 6. Windows 에이전트 설치

기본 수집 대상은 Windows 이벤트 로그 `Application`, `Security`, `System`입니다. 검토된 스크립트를 실행할 수 있는 조직 정책 아래에서 **64비트 관리자 PowerShell**을 사용합니다.

CA 파일을 예를 들어 `C:\certs\cloud-soc-ca.crt`에 준비하고, 실제 존재하는 채널을 확인합니다.

```powershell
Get-WinEvent -ListLog Application,Security,System | Select-Object LogName,IsEnabled
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

추가 채널은 **최초 설치 명령에** 다음 옵션을 덧붙입니다.

```powershell
-AdditionalChannel 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational'
```

위 옵션은 단독 명령이 아닙니다. 지정한 채널이 존재하고 활성화되어 있어야 하며, 설치기는 Sysmon 설치나 감사 정책 변경, 채널 활성화를 수행하지 않습니다.

스크립트가 실행 정책에 막히면 서명 등 조직이 승인한 배포 절차를 사용합니다. 실행 정책이나 인증서 검증을 우회하지 않습니다.

## 7. 설치 후 실제 로그 확인

미리보기는 설정 출력만 수행합니다. 네트워크·파일·서비스를 변경하지 않으며 OS·CA·로그 소스·기존 설치 상태의 실물 검증도 하지 않습니다. **미리보기 성공은 설치 가능 판정이 아닙니다.**

### 서비스 확인

Ubuntu:

```bash
sudo systemctl status cloud-soc-filebeat --no-pager
sudo journalctl -u cloud-soc-filebeat -n 100 --no-pager
```

Windows:

```powershell
Get-Service cloud-soc-winlogbeat
Get-ChildItem "$env:ProgramFiles\Cloud-SOC-Agent\logs"
```

| 대상 | 설치 위치 | 실행 계정 |
| --- | --- | --- |
| Ubuntu | `/opt/cloud-soc-agent` | root |
| Windows | `%ProgramFiles%\Cloud-SOC-Agent` | LocalSystem |

설정·CA·keystore·registry·디스크 큐는 설치 경로 아래에 있습니다. 서비스 계정의 파일 접근, TLS 오류, 401/403, bulk 저장 실패를 에이전트 로그에서 확인합니다.

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

| 증상 | 확인할 내용 |
| --- | --- |
| `No module named 'cloud_soc'` | 저장소 루트에서 `PYTHONPATH=src`를 현재 셸에 지정했는지, 가상환경 Python을 사용했는지 확인 |
| HTTP 주소 거부 | 에이전트는 HTTPS만 허용. 개발용 Compose가 아닌 보안 수신 환경 준비 필요 |
| TLS 연결 실패 | CA PEM 파일, 인증서 만료, DNS/IP와 SAN 일치 여부 확인. 검증을 끄지 않음 |
| API 키 인증/저장 실패 | `id:api_key` 형식, 만료, 대상 인덱스 권한, 중앙 인덱스 자동 생성 정책 확인 |
| 기존 설치 감지 | 기존 서비스·설정·registry를 검토한 후 전환 계획 수립. 무조건 삭제하거나 덮어쓰지 않음 |
| Ubuntu 로그 파일 없음 | rsyslog 등 로깅 구성을 확인. journald만 있는 환경은 현재 설치기 기본 소스와 다름 |
| Windows 채널 없음/비활성 | 설치된 소프트웨어, 활성 채널, 감사 정책을 확인하고 실제 필요한 채널만 지정 |
| 체크섬 불일치 | 설치 중단 상태 유지. 다운로드 경로·파일·고정 버전을 확인하고 검증을 생략하지 않음 |
| 설치 중 실패 | 0이 아닌 종료 코드와 오류 확인. 보호된 부분 설치 상태를 검토한 뒤 관리자가 복구 |
| 연결은 되지만 로그 없음 | 새 이벤트 생성 여부, Kibana 시간 범위, bulk 매핑 오류, 디스크/큐 상태 확인 |

재설치·업그레이드·키 교체·제거 자동화는 아직 없습니다. 장애 분석 전에 `data` 디렉터리를 지우면 중복 재수집이나 대기 로그 유실이 발생할 수 있습니다.

로컬 개발 컨테이너를 중지만 하려면 `docker compose stop`을 사용합니다. 데이터를 보존해야 한다면 볼륨을 삭제하지 마세요.

## 9. 테스트와 현재 한계

오프라인 설치기 테스트:

```powershell
node --test deploy/agents/tests/installers.test.cjs
```

Windows에서는 Git Bash와 `pwsh`가 필요합니다. `BASH_EXE`, `POWERSHELL_EXE` 환경변수로 설치된 실행 파일 경로를 지정할 수 있습니다. 테스트는 실제 에이전트 설치, 중앙 서버 변경, 로그 전송을 수행하지 않습니다.

- 검사 범위: 스크립트 구문, 미리보기 설정, HTTPS·인자 검증, 추가 소스·중복 소스, 체크섬 실패, 기존 설치 거부, 네이티브 명령 실패 전달, 모의 ACL 구성.
- 실제 검증 필요: Ubuntu/systemd 설치, Windows 서비스·LocalSystem 접근, Beat 바이너리의 설정 해석, 실제 CA/API 키 연결, 인덱스 템플릿 적용, 문서 수신과 장애 복구.
- 현재 자동 수집 대상은 지정된 Linux 텍스트 파일과 Windows 이벤트 채널입니다. 모든 OS 로그 자동 발견, Windows 일반 파일 수집, journald 직접 수집, 클라우드 Audit API 커넥터는 포함하지 않습니다.
- 설치 파일의 버전과 SHA-512는 고정되어 있습니다. 자동 최신 버전 업데이트가 아니며, 변경 시 두 값을 함께 검토해야 합니다.
- API 키·비밀번호·개인키·실제 운영 로그는 Git에 올리지 않습니다. `.env`는 추적하지 않고 서버별로 관리합니다.

설치 세부 동작과 보안 제약은 [에이전트 상세 안내](deploy/agents/README.md)를 참고하세요.

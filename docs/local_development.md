# 로컬 개발환경 안내

일반 사용자는 [빠른 시작](../README.md)을 따르세요. 이 문서는 개발 PC에서 Python·로컬 Elasticsearch·화면 배치를 확인하는 절차입니다. **명령은 저장소 루트에서 실행**하며 운영 서버나 PC 에이전트를 갱신하는 절차가 아닙니다.

## 저장소 준비

Git이 설치된 환경에서 실행합니다. 이후 명령은 별도 안내가 없으면 저장소 루트 기준입니다.

```shell
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
```

이미 저장소가 있다면 새로 복제하지 않아도 됩니다. 로컬 변경 사항을 확인한 후 필요한 버전을 가져오세요. 배포에는 검토한 커밋의 파일을 사용하고, 원격 스크립트를 확인 없이 다운로드와 동시에 실행하지 않습니다.

| 파일 | 용도 |
| --- | --- |
| [compose.yaml](../compose.yaml) | 로컬 Elasticsearch·Kibana 실행 |
| [중앙 서버 Compose](../deploy/server/compose.yaml) | Ubuntu 서버 HTTPS·인증·배포 포털 |
| [중앙 서버 설치 안내](../deploy/server/README.md) | 인증서 준비·포털 사용·접근 제한·실제 수신 확인 |
| [.env.example](../.env.example) | Python 연결 설정 예제 |
| [Ubuntu 설치기](../deploy/agents/install-ubuntu.sh) | Filebeat 신규 설치 |
| [Windows 설치기](../deploy/agents/install-windows.ps1) | Filebeat 신규 설치 및 소스 자동 탐색 |
| [인덱스 템플릿](../deploy/agents/index-template.json) | 중앙 수신 인덱스의 최소 매핑 |
| [게시 권한 예제](../deploy/agents/publisher-role.json) | 에이전트 API 키의 권한 범위 |
| [에이전트 상세 안내](../deploy/agents/README.md) | 설치 동작·보안·제약 사항 |

## 개발환경 실행

이 절은 **Windows 개발 PC의 PowerShell** 기준입니다. Git, Python, Docker Desktop과 Docker Compose가 준비되어 있어야 합니다. 원격 에이전트만 설치하려면 [빠른 시작의 에이전트 설치](../README.md#2-에이전트-설치)로 이동합니다.

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

**기존 인덱스를 사용 중이면 먼저 [파이프라인 보완·적용 안내](pipeline_reliability.md)를 확인하세요.** 경보 근거 보존용 필드 매핑이 없으면 일반 실행은 중단됩니다. 아래 준비 명령은 실제 클러스터의 매핑에 새 필드를 추가하지만 기존 문서를 삭제하거나 다시 쓰지 않습니다. 이 준비 작업은 이번 코드 수정 과정에서 실제 서버에 실행하지 않았습니다.

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

기존 [Filebeat 설정](../filebeat/filebeat.yml)의 `127.0.0.1:19200`은 기존 터널 환경을 전제로 한 값입니다. 새 서버에 그대로 적용하지 마세요. 이번 에이전트 설치기는 별도 인덱스를 사용하므로 이 Python 파이프라인과 아직 자동 연결되지 않습니다.

### 화면 미리보기

별도 터미널에서 다음 명령을 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m http.server 8765 --bind 127.0.0.1 --directory prototype
```

[관제 메인 화면](http://localhost:8765/index.html)과 [사건 조사 목록](http://localhost:8765/cases.html)의 정적 배치·메뉴만 확인할 수 있습니다. 현재 HTML/JavaScript는 중앙 API를 요청하므로 이 서버에서는 `조회 실패`나 데이터 없음이 표시될 수 있습니다. 샘플 로그로 대체하지 않으며 설치 패키지 생성·키 발급·실제 로그 조회·사건 저장은 동작하지 않습니다. 실제 기능은 HTTPS 중앙 포털에서 확인하세요. `/workbench.html`은 경보/사건 참조가 있어야 조사할 수 있는 상세 화면입니다.

## 테스트

설치기와 문서의 검사 절차는 [설치 상세 참고](installation_reference.md#테스트와-현재-한계)를 확인하세요. 코드·테스트·배포·실제 수신은 [작업 목록](work_tracker.md)에서 구분해 기록합니다.

# 새 수집 경로와 기존 SSH 탐지 엔진 연결

작성일: 2026-10-02 · 관련 작업: P5-01 / P5-02 · 대상: Ubuntu 22.04, VS Code

## 1. 이번 변경의 목적과 범위

새 수집 경로는 `soc-host-raw-*`, `soc-network-*`, `soc-cloud-*`로 들어온 이벤트를
`soc-normalized-v1`에 정규화한다. 기존 `cloud_soc.main`은 별도의 `raw-logs-*`와
`normalized-events`를 사용하므로, 새 정규화 결과가 기존 탐지 함수에 전달되지 않았다.

이번 변경은 새 정규화 인덱스를 읽는 독립 실행기를 추가한다.
기존 AUTH-001의 조건, 임계값, 시간 창, 조직별 구분, cooldown을 그대로 사용한다.
새 공격 규칙이나 자동 차단 기능은 추가하지 않는다. AWS·OCI·Windows·네트워크 이벤트도
정규화될 수 있지만 **이번에 연결하는 탐지 규칙은 SSH 인증 실패용 AUTH-001 하나**다.
모든 플랫폼의 보안 탐지를 완료했다는 의미가 아니다.

기준 소스: `Gandalem/cloud-soc` 커밋 `c89f6c8d1bacf1030d1ff01e03efbee4418d2874`.
제공 패치는 이 커밋의 파일을 기준으로 생성한다. 다른 커밋에서는 적용 전 검사가 필요하다.
이 작업 환경에는 해당 커밋의 다운로드한 소스가 있으며, 사용자 Ubuntu 저장소나 운영 서버를
직접 수정한 것은 아니다. Git 커밋·푸시·운영 배포도 수행하지 않았다.

## 2. 설계 과정과 결정

1. 수집기와 ES 인덱스, 정규화 실행기, 기존 탐지 함수, 경보 저장, 포털 근거 조회 경로를 확인했다.
2. 기존 `main`의 입력 인덱스만 바꾸면 기존 Linux 전용 파싱 흐름과 새 정규화 흐름이 혼합된다.
   따라서 기존 실행기는 유지하고 `python -m cloud_soc.detection`을 새 진입점으로 선택했다.
3. 첫 구현에서 단순 시간 체크포인트를 쓰면 첫 배치 9건과 다음 배치 1건을 합산하지 못하거나,
   재시작 때 cooldown이 초기화되어 달라질 수 있다. 이번에는 보존 중인 정규화 문서를
   하나의 PIT 스냅샷으로 모두 읽고 기존 엔진에 전달한다.
4. 무제한 조회 대신 기본 20,000건 상한을 둔다. 상한 초과 시 앞부분만 탐지하지 않고 해당 회차를 실패시킨다.
5. 전체 읽기와 탐지 결과 작성이 끝난 후 경보를 create-only로 저장한다.
   읽기 실패와 부분 응답을 정상 0건으로 표현하지 않는다.
6. 기존 경보 ID 생성과 provenance 형식을 재사용한다. 포털은 이미 새 정규화 참조를 지원하므로
   근거 조회 구조를 바꾸지 않고 통합 시험으로 연결을 검증했다.
7. 정규화 상태와 탐지 상태를 다른 문서로 기록한다. 포털의 정적인 ‘승인 대기’ 문구를 없애고
   독립 탐지기의 실제 실행 상태를 표시한다.

실행 흐름:

```text
수집기 → 새 원본 인덱스 → 기존 normalizer → soc-normalized-v1
                                           ↓ 새 detector
                                     기존 AUTH-001 엔진
                                           ↓
                                    security-alerts
                                           ↓
                               기존 포털의 경보·근거 조회
```

## 3. 기술과 데이터 계약

| 구성 | 사용 기술 / 역할 |
|---|---|
| 정규화 | 기존 Python 처리기와 SQLite 체크포인트. 서버 수신 시각 기준으로 원본을 처리 |
| 탐지 | Python 기존 `threshold-v2` 엔진과 YAML AUTH-001. 이벤트 발생 시각으로 5분 창 계산 |
| 입력 조회 | Elasticsearch PIT + `search_after`. 별칭·데이터 스트림을 거부하고 실제 인덱스만 읽음 |
| 경보 저장 | 기존 `make_alert_id`, `build_security_alert`, ES create API. 기존 ID 충돌은 이미 저장됨으로 처리 |
| 상태 | `soc-pipeline-status/normalizer`, `soc-pipeline-status/detector` |
| UI | 기존 Flask 조회 API와 JavaScript 현황 페이지. 정규화와 탐지 상태를 구분 |
| 배포 | 선택적 Docker Compose 오버레이. 기존 Python 이미지에 rules 디렉터리 포함 |
| 인증 | HTTPS CA 검증, 파일 기반 API 키, 준비 작업과 실행 작업 권한 분리 |

AUTH-001은 같은 조직·같은 출발지 IP의 SSH 인증 실패가 **300초 안에 10회** 발생하면 탐지한다.
기존 cooldown 300초를 유지한다. 조건이 일치하지 않는 일반 이벤트는 경보를 만들지 않는다.

각 탐지 입력에 실제 `_index`, `_id`를 `_cloud_soc_meta`로 연결하고,
정규화 문서에 남아 있는 `cloud_soc.provenance.raw`를 그대로 근거로 사용한다.
새 실행기는 원본 로그를 다시 읽지 않는다. 경보 근거에는 정규화 문서 참조, 원본 참조,
규칙 스냅샷·버전과 엔진 버전이 저장된다. 원본 보존 기간이 끝나면 포털은 근거 소실 상태를 표시한다.

## 4. 변경 파일

| 파일 | 변경 내용 |
|---|---|
| `src/cloud_soc/detection/worker.py` | 새 인덱스 조회, AUTH-001 호출, 경보 저장, 탐지 상태 기록 |
| `src/cloud_soc/detection/__main__.py` | 오프라인 검사·1회 실행·주기 실행 CLI |
| `src/cloud_soc/detection/setup.py` | 관리자용 인덱스 준비와 30일 API 키 발급, 기존 키 덮어쓰기 거부 |
| `src/cloud_soc/elastic/pagination.py` | 선택적 전체 문서 상한. 기존 호출의 기본 동작 유지 |
| `src/cloud_soc/processing/worker.py`, `__main__.py` | 탐지기 별도 실행 안내 |
| `src/cloud_soc/portal/operations.py` | 탐지기 상태 별도 조회 |
| `prototype/index.html`, `operations.js` | 정적 승인 대기 문구 대신 SSH 탐지 상태 표시 |
| `deploy/server/Dockerfile` | 규칙 파일을 이미지에 포함 |
| `deploy/server/detection.compose.yaml` | 탐지기 서비스 추가 |
| `tests/test_intake_detection.py` | 실제 정규화·엔진·포털 함수와 가짜 ES를 연결하는 통합 시험 |
| `prototype/tests/operations.test.cjs` | 탐지 상태의 독립 표시 시험 |
| `docs/work_tracker.md` | 요청 범위, 검증 결과와 운영 미검증 기록 |

## 5. Ubuntu 22.04 / VS Code에서 패치 적용

아래 명령은 사용자가 Ubuntu의 저장소 루트에서 실행한다. ZIP은 전체 저장소가 아니라
**변경 파일과 적용 패치**를 담고 있다. 기존 코드에 폴더를 무작정 덮어쓰지 않는다.

```bash
cd ~/cloud-soc
git status --short
git rev-parse HEAD
# 먼저 현재 변경사항을 별도 보존한 뒤 새 브랜치에서 적용한다.
git switch -c feature/intake-detection

# 받은 ZIP을 ~/Downloads/cloud-soc-intake-detection-c89f6c8 에 해제했다고 가정
PATCH="$HOME/Downloads/cloud-soc-intake-detection-c89f6c8/intake-detection.patch"
git apply --check "$PATCH"
git apply "$PATCH"
git diff --check
git status --short
code .
```

`git apply --check`가 실패하면 실제 체크아웃과 기준 소스가 다른 것이다.
`--reject`, 강제 덮어쓰기, `reset --hard`로 밀어붙이지 말고 VS Code에서 해당 변경 부분을 비교한다.
새 파일은 `git diff`만으로 내용이 모두 표시되지 않으므로 `git status`와 편집기로도 확인한다.

### 개발 환경과 오프라인 검증

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r deploy/server/requirements.txt
export PYTHONPATH="$PWD/src:$PWD/tests"

python -m cloud_soc.detection
python -m unittest test_intake_detection test_processing test_pipeline_reliability \
  test_linux_security test_security_detail test_log_contract test_cases -v
```

기본 명령은 규칙 파일만 검증하고 ES에 연결하지 않는다. VS Code에서
Python 인터프리터를 `.venv/bin/python`으로 선택하고 위 명령을 통합 터미널에서 실행하면 된다.
Ubuntu 기본 Python 3.10을 대상으로 문법을 검사했으나, 이 작성 환경의 실제 Python 시험은
Windows의 Python 3.12에서 실행했다. Ubuntu에서 위 시험을 한 번 더 수행해야 한다.
저장소의 루트 의존성은 버전이 고정되어 있지 않으므로 설치 후 `python -m pip freeze`를
팀의 배포 기록으로 남긴다. 작성 환경의 Elasticsearch Python 클라이언트는 9.5.1이었다.

Node.js가 설치되어 있다면 UI 회귀도 실행한다.

```bash
node --test prototype/tests/*.test.cjs
```

## 6. 기존 중앙 서버에서 준비

이 절차는 저장소의 HTTPS 중앙 Elasticsearch가 이미 준비된 환경을 기준으로 한다.
신규 서버 초기 구성, Docker 설치, 외부 네트워크 개방은 기존 서버 설치 문서의 범위다.
기존 `state/server`를 다시 초기화하거나 기존 인증서를 재발급하지 않는다.

실행 전 실제 값에 맞게 경로를 수정한다. 아래 localhost는 **중앙 서버 자신에서 실행할 때**의 예다.
다른 호스트에서 실행한다면 인증서에 포함된 서버 이름을 사용하고 해당 주소에 접근 가능해야 한다.
TLS 오류를 피하려고 인증서 검증을 끄지 않는다.

```bash
SOC_STATE_PATH="$PWD/state/server"
SOC_ES_URL="https://localhost:9200"
```

### 관리자 준비: 탐지 키

다음 명령은 필요한 처리 인덱스·normalizer 역할을 준비하고 경보 매핑을 확인한 뒤
탐지 전용 키를 새 파일에 기록한다. 기존 데이터는 삭제하지 않지만, 서버 설정 변경이므로
팀의 서버 담당자가 실행한다. 매핑이 호환되지 않으면 실패시키며 인덱스를 삭제해서 해결하지 않는다.

```bash
sudo env PYTHONPATH="$PWD/src" "$PWD/.venv/bin/python" -m cloud_soc.detection.setup \
  --prepare-processing \
  --es-url "$SOC_ES_URL" \
  --ca-file "$SOC_STATE_PATH/tls/ca.crt" \
  --password-file "$SOC_STATE_PATH/secrets/elastic_password" \
  --key-file "$SOC_STATE_PATH/secrets/detector.key"
```

처리 인덱스가 이미 준비되어 있다면 `--prepare-processing`은 생략할 수 있다.
`setup`은 실행기를 자동 시작하지 않는다. 암호와 발급 키를 터미널에 출력하지 않는다.
발급 키가 이미 있으면 덮어쓰기를 거부한다. 오류 시 예약된 빈 파일이 남을 수 있으므로
파일 상태를 확인한 뒤 재시도한다. 키 발급 응답이 네트워크에서 유실되면 서버에 키가 남을 수 있어
관리자가 키 목록을 확인해야 한다. 실패가 모든 서버 변경을 되돌린다는 의미는 아니다.

### 정규화 실행기가 아직 없다면

기존 normalizer 키가 없을 때만 별도로 발급한다.

```bash
sudo env PYTHONPATH="$PWD/src" "$PWD/.venv/bin/python" -m cloud_soc.detection.setup \
  --worker normalizer \
  --es-url "$SOC_ES_URL" \
  --ca-file "$SOC_STATE_PATH/tls/ca.crt" \
  --password-file "$SOC_STATE_PATH/secrets/elastic_password" \
  --key-file "$SOC_STATE_PATH/secrets/normalizer.key"
```

컨테이너는 UID/GID 1000으로 실행되므로 키와 상태 디렉터리를 준비한다.
기존 파일·폴더가 있다면 현재 소유자와 사용 주체부터 확인하고 필요한 항목에만 적용한다.

```bash
sudo chown 1000:1000 "$SOC_STATE_PATH/secrets/detector.key"
sudo chmod 400 "$SOC_STATE_PATH/secrets/detector.key"
# 새 normalizer를 시작할 때만 다음 항목도 준비
sudo chown 1000:1000 "$SOC_STATE_PATH/secrets/normalizer.key"
sudo chmod 400 "$SOC_STATE_PATH/secrets/normalizer.key"
sudo install -d -m 700 -o 1000 -g 1000 "$SOC_STATE_PATH/processing"
```

탐지 키에는 정규화 읽기, 경보 create-only·매핑 조회, 상태 인덱스 쓰기 권한만 부여한다.
원본 읽기·인덱스 생성·보안 관리 권한은 없다. ES 권한은 인덱스 단위이므로 상태 쓰기 권한은
`detector` 문서 하나로 제한되지는 않는다. 문서별 쓰기 격리는 후속 개선이다.
키는 30일 뒤 만료된다. 만료 전에 별도 새 파일로 발급하고, 서비스 중지 후 파일 교체와
컨테이너 재생성을 수행한다. 이전 키의 폐기는 관리자가 확인하여 별도로 처리한다.

## 7. 1회 실행과 지속 실행

먼저 새 정규화 결과가 있는 환경에서 탐지기만 1회 실행할 수 있다.
이 명령은 실제 경보와 상태 문서를 쓴다. 관리자 암호가 아닌 탐지 전용 키를 사용한다.

```bash
sudo env PYTHONPATH="$PWD/src" "$PWD/.venv/bin/python" -m cloud_soc.detection \
  --run --once --es-url "$SOC_ES_URL" \
  --ca-file "$SOC_STATE_PATH/tls/ca.crt" \
  --api-key-file "$SOC_STATE_PATH/secrets/detector.key"
```

출력 예시는 `{"events": 10, "created": 1, "existing": 0}`이다. 이는 형식 예시이며 실제 측정값이 아니다.
같은 입력·규칙으로 다시 실행하면 동일 경보는 `existing`으로 집계된다.
`events: 0`이면 정규화 입력이 없다는 뜻이며 수집 정상이나 공격 부재를 증명하지 않는다.
새 탐지기를 `cloud_soc.main` 대신 실행한다. 같은 로그를 두 경로로 복제하면 경로별 경보가 발생할 수 있다.

### Compose 지속 실행

기존 processing 체크포인트가 있다면 **처음 실행 때 사용한 시작 시각을 그대로** 사용한다.
시작 시각을 임의로 바꾸면 기존 처리기는 실행을 거부한다. 새 환경에서는 검사할 로그의
서버 수신 시각보다 앞선, 실제 과거 UTC 시각을 지정한다.

```bash
# 예시를 복사하기 전에 실제 최초 수신 시각/기존 체크포인트 설정에 맞게 수정
export SOC_PROCESSING_START='2026-10-01T00:00:00Z'

sudo env SOC_PROCESSING_START="$SOC_PROCESSING_START" docker compose \
  --env-file "$SOC_STATE_PATH/compose.env" \
  -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml \
  -f deploy/server/detection.compose.yaml build normalizer detector portal

sudo env SOC_PROCESSING_START="$SOC_PROCESSING_START" docker compose \
  --env-file "$SOC_STATE_PATH/compose.env" \
  -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml \
  -f deploy/server/detection.compose.yaml up -d --no-deps normalizer detector
```

기존 normalizer가 다른 방식으로 이미 실행 중이면 중복 기동하지 않는다.
그 경우 processing 오버레이와 normalizer 서비스명을 빼고 탐지기만 배포한다.
포털의 상태 표시까지 반영하려면 기존 포털 DB 백업 절차를 수행한 후 위와 같은 compose 옵션으로
`up -d --no-deps portal`을 실행한다. 이미지 빌드만으로 기존 포털 컨테이너가 갱신되지는 않는다.

탐지기는 기본 60초마다 실행하며 `--interval`로 10~3600초를 지정할 수 있다.
정규화 문서가 ES 검색에 보이기까지의 refresh 지연과 처리기 주기가 추가된다.
즉시 탐지 지연이나 초 단위 SLA를 보장하는 구조는 아니다.

## 8. Ubuntu SSH 로그의 필수 전제

원본에 `organization.id`, 서버가 설정한 `event.ingested`, 올바른 `@timestamp`가 필요하다.
기존 Linux SSH 파서는 명시적인 `event.timezone`도 요구한다.
로그에 시간대가 없다고 임의로 UTC 또는 한국 시간으로 가정하지 않는다.

현재 설치기로 만든 Filebeat 설정에서 이 값이 빠져 있으면 이번 탐지기만 켜도 연결 시험은 실패한다.
이 경우 처리 결과는 `ssh_timezone_missing`이다. **실제 로그를 생성한 호스트의 시간대**를 확인하고,
해당 Linux auth 입력에만 다음과 같이 구조화된 필드를 추가한다. 기존 `fields`가 있으면 병합하고
YAML의 같은 키를 두 번 쓰지 않는다. 아래 예시는 호스트 로그가 실제 UTC일 때만 유효하다.

```yaml
fields_under_root: true
fields:
  event:
    timezone: UTC
```

시간대가 다른 입력·과거 로그에 이 값을 일괄 적용하지 않는다. 이 패치는 수집기 설정을 자동 수정하지 않는다.
설정 변경 후 새로 수집된 이벤트로 확인한다. 기존 원본과 invalid 처리 기록을 수정·삭제하거나
체크포인트를 되돌려 과거 데이터를 재처리하는 기능은 이번 범위에 포함되지 않는다.

## 9. 검증과 발표 시 표현

새 통합 시험은 합성 SSH 원본을 실제 `normalize()`에 전달하고 결과를 실제 엔진으로 탐지한 다음,
실제 경보 생성 함수와 포털 근거 조회 함수까지 연결한다. Elasticsearch 입출력은 가짜 클라이언트로 대체했다.

검증 항목:

- 10건 탐지, 9+1 배치 경계, 300초 창 밖 미탐지, 조직 간 합산 방지, 기존 cooldown.
- 원본 순서가 바뀌어도 경보 ID 동일, 재실행 시 기존 경보 덮어쓰기 방지.
- 경보 저장 중 일부 실패 후 전체 재실행으로 누락 경보 저장.
- PIT 페이지 이동과 종료, 부분 응답·문서 상한 초과 시 경보 미저장.
- 잘못된 인덱스·시각·근거 참조 거부, 원본 입력 변경 없음.
- 경보에서 정확한 정규화·원본 참조 조회, 상태 표시, 키 파일 덮어쓰기 방지.

최초 501953b 기준 패치의 시험 결과(아래 숫자는 이전 검증 기록이며 c89f6c8 재검증과 구분):

| 검증 | 결과 |
|---|---|
| 신규 연결 시험 | 24개 통과 |
| 연결·정규화·기존 엔진·근거·사건 관련 Python 회귀 | 신규 시험 포함 135개 통과 |
| 포털 JavaScript 회귀 | 66개 통과 |
| 전체 Python 탐색 실행 | 292개 실행, 실패 3·오류 3·건너뜀 5로 전체 통과 아님 |
| 변경 전 소스와 실패 비교 | 기존 Windows 정책/설치기 시험의 동일 실패·오류 재현 |

전체 시험의 미통과 사유는 기존 Windows 스크립트 실행 정책, Bash의 `dirname` 경로,
개인 디렉터리를 금지하는 기존 설치 정책 시험이다. 변경 전 검증에서는 로컬 소스 사본에
빠져 있던 `portal-backup.py`로 인한 추가 실패도 발견했고, 기준 커밋 파일을 복원한 뒤에는
그 실패가 없어졌다. 이 환경 문제를 해결하려고 사용자 OS 정책이나 기존 보안 정책을 변경하지 않았다.
실행 결과는 `docs/work_tracker.md`의 2026-10-02 기록을 함께 확인한다.
‘격리 통합 시험에서 연결을 검증했다’고 설명할 수 있다.
‘Ubuntu와 운영 Elasticsearch에서 실수집 탐지를 완료했다’고 설명할 수는 없다.

운영 인수 확인은 별도로 다음 순서로 기록한다.

1. Ubuntu에서 관련 Python/UI 시험 통과 기록.
2. 해당 호스트의 새 SSH 이벤트 원본 ID와 필수 필드 확인.
3. 해당 원본을 가리키는 `soc-normalized-v1` 문서 확인.
4. 통제된 테스트 이벤트가 규칙을 만족할 때 `security-alerts`의 AUTH-001 확인.
5. 포털에서 경보·근거 조회, 원본 ID 일치 확인.
6. 동일 데이터 재실행 후 신규 경보가 늘지 않는지 확인.
7. 키 만료/권한 오류/상한 초과 시 정상 0건 대신 실패 상태가 나타나는지 확인.

운영 환경에 무차별 SSH 인증 시도를 가하지 말고, 팀이 통제하는 별도 시험 환경에서
로그 표본을 수집한다. 이번 단위 시험은 서버에 합성 데이터를 삽입하지 않는다.

## 10. 실패 확인과 되돌리기

| 증상 | 확인할 사항 |
|---|---|
| `detector_configuration_or_connection_failed` | HTTPS 주소, CA 경로, 키 파일 권한·공백, AUTH-001 활성화 |
| `detection_cycle_failed` | ES 접근/키 만료/매핑/부분 조회/20,000건 상한/잘못된 정규화 입력 |
| 정규화 성공, 탐지 실행 기록 없음 | 탐지 서비스가 실제 실행 중인지와 `detector` 상태 문서 |
| 탐지 성공, 경보 0건 | 정규화 문서 수와 SSH 조건, 조직·IP·발생 시각. 다른 플랫폼 이벤트만 있는지 |
| `ssh_timezone_missing` | 해당 Linux 로그 입력의 명시적 시간대 |
| 포털 근거 소실 | 원본·정규화 보존 기간과 monitor 계정의 읽기 권한 |

실패 로그에는 원본 본문과 자격증명을 넣지 않는다. 따라서 자세한 서버 원인은 관리자의 보호된
ES 로그와 상태 점검으로 확인해야 한다. 상태 기록 자체가 실패하면 이전 상태가 남을 수 있고
포털은 5분 이후 stale로 표시한다. 컨테이너가 running인 것과 탐지 회차 성공은 다르다.

중단은 해당 compose 구성에서 `stop detector`를 실행한다. 정규화와 수집은 계속 유지할 수 있다.
코드 롤백은 변경이 더 없는지 확인하고 `git apply --reverse --check` 후 역패치를 적용한다.
이미 저장한 경보·정규화·원본과 키는 자동 삭제되지 않는다. 기존 이미지를 사용하는 경우
컨테이너도 해당 이미지로 다시 생성해야 한다. `docker compose down -v`는 사용하지 않는다.

## 11. 남은 한계와 우선순위

**P1 — 증분 탐지로 확장.** 이번 실행기는 작은 데이터의 연결 검증용이다.
문서가 기본 20,000건을 넘으면 탐지를 멈춘다. 최대 100,000건까지 옵션을 늘릴 수 있지만
메모리·조회량·반복 탐지 비용이 함께 증가한다. 상한 확대가 처리 구조 개선을 대신하지 못한다.
다음 단계는 영속 그룹별 시간 창, 수신 체크포인트, 지연 허용 기준, cooldown 상태,
상태·경보의 재시도 일관성을 함께 설계하는 것이다.

**P1 — 실수집 인수 시험.** Ubuntu, 실제 ES 매핑/권한, Filebeat 시간대, 새 문서 수신과 포털
조회까지 이어지는 시험을 수행한다. 이번 코드 시험으로 해당 운영 항목을 완료 처리하지 않는다.

**P2 — 지연·보존·규칙 변경 정책.** 같은 스냅샷과 규칙은 같은 경보 ID를 만든다.
그러나 늦은 이벤트 추가, 정규화 삭제/재작성, 보존 기간 만료 또는 규칙 버전 변경은 시간 창과
근거 목록을 바꾸어 새 ID를 만들 수 있다. 과거 경보는 자동 정정·폐기하지 않는다.
이는 동일한 실제 공격에 대한 의미적 중복까지 제거하는 exactly-once 보장이 아니다.

**P2 — 탐지 커버리지와 관측성.** AUTH-001 외 규칙은 근거·오탐·조직별 적용 범위를 설계한 후 추가한다.
현재 실패 코드는 의도적으로 일반적이며 상세 실패 분류·처리량 지표·키 만료 알림은 후속 과제다.
상태 쓰기 문서별 권한 격리, 규칙 파일 운영 버전 고정, 의존성 버전 고정도 후속으로 진행한다.

팀 검토 시 탐지 로직 담당자는 시간 창·중복·지연 정책을, 수집 담당자는 필드·시간대를,
서버 담당자는 권한·컨테이너·보존 기간을, 포털 담당자는 경보와 근거 참조를 확인하면 된다.


## 12. c89f6c8 호환 수정

사용자가 실제 사용하는 커밋의 operations.py에 분할 조회와 집계 검증이 추가되어 기존 패치 문맥이 일치하지 않았다. 해당 조회 기능 전체를 보존하고 pipeline 상태 조회 부분만 수정했다. 나머지 파일도 이 커밋의 원본을 기준으로 패치를 생성했다. 이전 패치를 먼저 적용하지 말고 이 패치 하나만 적용한다.
재검증: 관련 Python 135개 + c89f6c8 분할 조회 시험 11개 통과, UI 66개 통과. 새 패치의 적용 및 역적용 검사를 기준 원본 사본에서 수행했다. Windows의 격리 시험이며 사용자 Ubuntu/실제 ES 실행은 아직 하지 않았다.

Ubuntu에서는 새 ZIP cloud-soc-intake-detection-c89f6c8.zip을 Downloads에 저장하고 별도 폴더로 압축 해제한 뒤 새 패치만 적용한다. 기존 501953b 기준 패치를 추가로 적용하지 않는다.

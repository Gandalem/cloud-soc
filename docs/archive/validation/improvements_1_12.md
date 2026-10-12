# 1–12번 개선 적용 안내 (2026-10-04)

대상: `Gandalem/cloud-soc`의 `JEONGRIM-SEO`. 이 문서는 소스·오프라인 회귀 검증을 설명한다. 운영 VM 배포, 실제 Elasticsearch 이행, 사용자 PC의 VS Code 파일 갱신은 별도이다.

## 실제 코드와 앞선 검토의 차이

중앙 운영 구성 `deploy/server/compose.yaml`은 이미 Elasticsearch 보안/TLS, CA 검증, 발급·조회·수집·처리·탐지 역할과 키를 분리한다. 무인증 루트 Compose는 개발용이다. 기존 순차 탐지, 사례 저장, 정확한 근거 페이지 조회·정규화 해시 검증도 이미 있다. 이들을 제거하거나 중복 구현하지 않았다.

| 번호 | 적용 내용 | 경계 |
|---|---|---|
| 1 | 기존 중앙 TLS/최소 권한 유지, 개발 ES 클라이언트의 CA·API key·비밀 파일 지원 | 인증정보를 HTTP로 보내지 않음. 실제 계정/키 발급은 하지 않음 |
| 2 | 명시적 dev/prod 진입점, prod ES 호스트 포트 제거 | 기존 중앙 직접 수신 진입점은 호환 유지. 원격 에이전트 경로 별도 필요 |
| 3 | 실제 설치·시험한 직접 버전과 `constraints.txt`, `pyproject.toml` | Python 3.12 기준. ES 서버 9.5.2와 Python 클라이언트 9.5.1은 서로 다른 패키지 |
| 4 | create-only·고정 ID·provenance 유지 및 회귀 | SQLite 업무 저장은 변경 가능. 관리자의 저장소 변조까지 방지하는 WORM 보장 아님 |
| 5 | CLI / pipeline runtime / alerts / stats 분리 | 기존 `cloud_soc.main` import와 CLI·테스트 patch 호환 |
| 6 | 명시적 Threshold/Single/Sequence detector registry | YAML에서 외부 코드 로딩 금지, 알 수 없는 유형은 오류 |
| 7 | 기존 조직·호스트·계정·IP별 실패→성공 탐지 재사용, 중복 근거 계수 방지 | sudo/파일 접근을 없는 로그로 추정하지 않음. 규칙 실행은 기존 opt-in |
| 8 | 위험 점수·수준·버전·가산 근거 저장 | 악성 확률 아님, 알려지지 않은 자산 중요도/IOC 정보는 가산하지 않음 |
| 9 | 경보 상세의 위험 점수/규칙 스냅샷/MITRE 및 기존 근거 페이지 | 과거 점수는 미기록, 원문 전체 노출 없이 기존 선별 메타데이터·참조 유지 |
| 10 | 선택적 서버 세션 로그인, Admin/Analyst/Viewer, CSRF·폐기·만료·로그인 제한 | 단일 workspace 권한. 조직별 tenant 격리/외부 IdP는 별도 |
| 11 | 추가 비밀 패턴과 재귀 키 기반 화면 마스킹 | 저장된 원본은 변경하지 않음. 완전한 DLP 보장 아님 |
| 12 | 고정 SHA Actions, Ruff/pytest/Node/Bandit/pip-audit/Compose/Docker build, VS Code tasks | 라이브 수신/Windows 설치 시험은 기본 CI에서 제외 |

추가로 `SOC_LOG_FORMAT=json`을 켜면 앱 진단 로그를 구조화하며, 예외 본문은 출력하지 않는다. 인증된 `/api/healthz`는 ES 조회 계정·사건 DB의 준비 여부를 확인한다. 처리·탐지 상태/실행·제외 이력은 기존 포털 지표를 유지한다. 별도 Prometheus endpoint는 추가하지 않았다.

## 로컬 VS Code에서 가져오기

저장소 폴더의 터미널에서 실행한다. 아래 명령은 Docker 서비스를 교체하지 않는다.

```bash
git status --short
git fetch origin
git switch JEONGRIM-SEO
git pull --ff-only origin JEONGRIM-SEO
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip==26.2.1
python -m pip install -c constraints.txt -r requirements-dev.txt
python -m pytest -q
python -m ruff check src tests
```

작업 중인 로컬 변경이 있으면 먼저 별도 커밋 또는 `git stash push -u`로 보존한다. merge/rebase/강제 reset을 자동으로 수행하지 않는다. VS Code의 **Python: Select Interpreter**에서 `.venv/bin/python`을 선택하면 **Terminal → Run Task**에 테스트·린트·로컬 서비스·규칙 검증 작업이 표시된다. Windows에서는 `.venv\Scripts\Activate.ps1`을 사용한다.

## 개발 / 운영 Compose

로컬 무인증 개발 서비스는 루프백에만 공개한다.

```bash
docker compose -f compose.yaml -f compose.dev.yaml up -d
```

운영 기본값은 중앙의 기존 준비 절차로 인증서·비밀 파일을 만든 후 사용한다. Compose 2.24.4 이상이 필요하다 (`include` + `!reset`).

```bash
docker compose --env-file state/server/compose.env -f compose.prod.yaml config --quiet
```

`compose.prod.yaml`은 `deploy/server/compose.yaml` + `internal.compose.yaml`을 포함하므로 ES 9200을 호스트에 열지 않는다. 포털·Kibana는 내부 DNS의 인증된 HTTPS ES를 사용한다. **이 구성만으로 외부 Filebeat/Packetbeat가 연결되지는 않는다.** 원격 에이전트는 VPN/사설 인증 수신 경로를 먼저 제공해야 한다. 기존 직접 TLS 수신을 유지해야 한다면 기존 `deploy/server/README.md`의 중앙 Compose 진입점을 명시적으로 사용하고 `SOC_BIND_IP`·방화벽을 사설 수신 범위로 제한한다. ngrok은 포털 HTTPS 게이트웨이에 연결하고 ES를 공개 터널에 올리지 않는다. 기존 운영 실행 파일·포트는 이번 소스 수정으로 변경되지 않는다.

추가 정상화/탐지 서비스는 기존 `processing.compose.yaml`, `detection.compose.yaml` 절차를 따른다. 새 유형/규칙을 운영에서 자동으로 켜지 않았다.

## 인증과 역할 사용

기본값은 기존 관리자 Basic 인증이다. `SOC_USERS_FILE`을 지정하면 세션 모드로 전환하며 Basic으로 우회할 수 없다. 서버 세션은 SQLite에 토큰 해시만 저장한다. 쿠키는 HttpOnly/SameSite=Strict, HTTPS에서 Secure이고 1시간 절대 만료한다. 로그인 성공은 이전 쿠키를 폐기하고 새 난수 토큰을 만든다. 로그아웃은 서버 세션을 삭제한다. 계정별 5회 실패는 5분 동안 제한되며, 알 수 없는 계정은 하나의 저장 버킷을 공유한다.

| 역할 | 권한 |
|---|---|
| Admin | 기존 설치 패키지·키·Enrollment 관리, 모든 조회, 사건 업무 |
| Analyst | 로그/경보/근거/수집·탐지 상태 조회, 사건 생성·수정·메모/종결 |
| Viewer | 위 조사·상태·사건 읽기만 가능 |

서버의 모든 요청에서 역할을 검사한다. 모든 변경은 기존 `X-Cloud-SOC: portal`·JSON·Origin 검사에 세션 CSRF 토큰을 추가한다. 화면 공통 transport가 같은 origin의 요청에만 CSRF를 붙인다. 사례 변경 이력의 actor는 실제 로그인 계정이다. 한 workspace의 사용자들은 동일한 조직 자료를 읽는다. 여러 조직의 독립 고객 서비스로 사용하기 위한 RBAC/DLS는 아니다.

사용자를 오프라인으로 준비한다. 비밀번호는 숨김 입력을 사용하며 코드/명령줄/설정에 평문으로 저장하지 않는다. 최초 계정은 admin이어야 한다.

```bash
PYTHONPATH=src python deploy/server/manage-users.py \
  --file state/server/secrets/portal_users.json --user admin --role admin
PYTHONPATH=src python deploy/server/manage-users.py \
  --file state/server/secrets/portal_users.json --user analyst --role analyst
```

중앙 state 디렉터리는 실제 `SOC_STATE_DIR`에 맞춘다. JSON은 0600, Docker portal UID 1000이 읽을 수 있는 소유권이어야 한다. 기존 중앙 Compose에 `deploy/server/session.compose.yaml`을 추가하고 portal을 재시작한다. 세션 모드 사용자 설정은 시작 시 읽으므로 계정/권한 변경 후에도 재시작해야 한다. 사용자 hash/role 변경 시 기존 세션 revision이 맞지 않아 거부한다. 세션 DB는 업무 백업 대상이 아니므로 복원 후 기존 세션을 폐기하고 다시 로그인한다. 사용자 hash 파일은 보호된 운영 비밀 백업 정책으로 관리한다. 실제 활성화/계정 생성은 이번 작업에서 수행하지 않았다.

## 위험 점수와 순차 탐지 이행

`cloud_soc.risk_score` 0–100, `risk_level`, `risk_version=triage-v1`, `risk_factors`를 **새 경보**에 저장한다.

- 기본 점수: low 20 / medium 45 / high 65 / critical 85.
- threshold 규칙의 관측 수가 임계값의 2배 이상이면 +10.
- sequence 규칙의 실패 후 성공이면 +15.
- 100점 상한. low 0–29 / medium 30–59 / high 60–79 / critical 80–100.

severity 원래 값은 유지한다. 점수는 우선순위 보조이며 침해 확률/완전한 공격 사슬 판정이 아니다. 기존 경보 ID/문서를 덮어써 점수를 채우지 않는다. 기존 경보를 재시도하면 create conflict로 원본을 보존한다. 새 인덱스에 명시적 매핑을 추가했으며 기존 인덱스의 동적 매핑이 제한된 환경에서는 운영 매핑 변경을 별도로 검토해야 한다.

순차 탐지는 같은 근거 이벤트를 여러 번 받은 경우 실패 횟수를 부풀리지 않도록 했다. 알고리즘 버전은 `failure-success-v2`, 규칙 revision도 달라진다. **이미 `--include-sequence`로 운영 중인 기존 runtime DB에 즉시 연결하지 않는다.** 보호 백업을 남기고 별도 새 상태 파일·명시적 시작 범위에서 이행을 검증한다. 기존 원본/정규화/경보 삭제는 필요하지 않다. 다른 규칙의 기본 알고리즘 버전은 유지한다.

## 검사

검증한 Python 3.12 환경에서 전체 pytest 414 통과, 선택적 라이브 검사 5 생략, unittest 하위 검사 154 통과. 포털 Node 로직 82 통과. Ruff correctness 검사·Bandit medium/high·pip check·6개 규칙 오프라인 검사 통과. pip-audit에서 취약점이 보고된 기존 cryptography/pip를 수정 버전으로 갱신한 뒤 알려진 취약점 0을 확인했다. 감사 결과는 검사 시점 기준이다.

새 보안 회귀는 역할 우회, Origin/CSRF 거절, 쿠키 속성·서버 폐기·만료, 계정 변경·영속 로그인 제한, 비밀 마스킹, HTTP 인증 거절, 위험 점수, 조직별 기존 탐지 및 중복 근거 계수를 검사한다. 화면 CSRF transport도 외부 origin으로 토큰을 보내지 않는지 확인했다.

현재 작업 환경에는 Docker daemon/CLI 및 운영 접속 경로가 없어 로컬 Docker build/Compose 실행·실제 ES·브라우저 렌더링·VM/에이전트 수신은 미검증이다. GitHub Actions [검증 실행](https://github.com/Gandalem/cloud-soc/actions/runs/37209050863)에서 코드 커밋 `5e366c4`의 모든 단계가 성공했다. Ubuntu Python 3.12.14의 pytest 410 통과/11 생략/하위 검사 154 통과, Node 82 통과, Ruff·Bandit·pip-audit·개발/운영 Compose config·Docker 이미지 build 성공이다. OS별 실행 전제 차이로 생략 수가 로컬과 다르며 Windows 설치 실행을 Linux pwsh로 대신 검증하지 않는다. 운영 배포와 실제 수신은 기존 작업 목록의 미완료 인수 기준을 유지한다.

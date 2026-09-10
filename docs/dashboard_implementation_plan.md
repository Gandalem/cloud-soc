# Cloud SOC 대시보드 단계별 구현 계획

기준일: 2026-09-10. **이 문서는 계획이며 아래 코드/테스트/화면은 이번 작업에서 구현하지 않았다.**

선행 문서: [화면 요구사항](dashboard_requirements.md), [데이터 요구사항 및 Gap Analysis](dashboard_data_requirements.md).

## 1. 실행 원칙과 목표 구조

사용자가 선택한 이번 범위는 설계 문서, Gap Analysis, 구현 계획까지다. 실제 구현은 후속 요청에서 단계별로 진행한다. 기존 Elasticsearch 데이터 재처리, Filebeat 설정 배포, 인덱스 변경, 새 탐지 규칙 추가를 문서 작성에 포함하지 않는다.

```text
기존 데이터 경로 유지
  Ubuntu auth.log -> Filebeat -> raw-logs-*
    -> Parser -> Normalizer -> normalized-events
      -> Detection Engine -> security-alerts

조사 화면에 필요한 확장
  raw reference + Entity key + evidence reference + rule snapshot

후속 SOC 웹 계층
  기존 Elasticsearch 조회 계층 + SQLite 분석 이력
    -> SOC Operations / Alert Investigation / Entity Investigation
  수집원 등록 설정 + 수신 지표 + 단계별 실행 관측
    -> Data Source Health
  원본 심층 검색 -> 기존 Kibana Discover

선택 확장
  OCI Audit API -> collector -> raw-logs-* -> 별도 parser/normalizer
    -> 동일 Entity/Timeline/Health 화면
```

UI는 처음부터 네 화면을 한 번에 개발하지 않는다. 기존 Kibana로 정보/필터를 검증하고, 상태 저장이 필요한 단계에서 얇은 Python 웹 계층을 추가한다. 웹 계층은 기존 Parser/Engine을 다시 구현하지 않고 조회와 업무 상태 변경만 담당한다. 웹 프레임워크는 그 단계에서 라우팅·인증·CSRF 요구를 검토해 하나만 선택하며 이번 작업에서는 의존성을 추가하지 않는다.

## 2. 단계 요약

| Phase | 분석가에게 제공하는 결과 | 선행 조건 | 범위 밖 |
| --- | --- | --- | --- |
| 0 | 요구사항/데이터 계약 검토안 | 현재 저장소 확인 | 코드 변경 |
| 1 | 현재 SSH 경보의 신뢰 가능한 읽기 전용 운영 화면 | 조회 누락/오류 신호 검증 | 상태/담당자/점수 구현 |
| 2 | 경보 -> 정확한 근거 -> 원본 연결 | 필드/ID/시간 계약 | 새 탐지 규칙 |
| 3 | 경보 조사와 분석가 처리 이력 | Phase 2 | 자동 차단/외부 알림 |
| 4 | Host/User/IP 중심 추가 조사 | Entity 식별/근거 + workflow | 근거 없는 위험 점수 |
| 5 | 무활동/수집 장애/처리 지연 구분 | 수집원 등록/시각/내부 관측 | 보안 로그 종류 확대 |
| 6 | 클라우드 관리 활동 조사 | 필요한 작업/필드/정상 사례 확정 | 모든 API 변경의 자동 공격 분류 |

Health는 마지막에 생각하는 기능이 아니다. Phase 1부터 데이터 최신성/조회 실패를 보이고 Phase 2에서 수신 시각/소스 ID를 확보한다. Phase 5는 독립적인 생존 확인까지 완성하는 단계다.

## 3. Phase 0: 설계 검토

산출물:

- `docs/dashboard_requirements.md`: 네 화면, 패널, 필터, 업무 상태, 완료 기준.
- `docs/dashboard_data_requirements.md`: 코드/실제 데이터 분석, 패널별 매트릭스, 필드/저장소 계약.
- `docs/dashboard_implementation_plan.md`: 이번 계획.
- `README.md`: 현재 구현 상태와 설계 문서 링크.

검토할 주요 선택: 전체 미종결 큐의 시간 범위, 초기 위험 점수 미산정, workflow 별도 저장, 조직/Host/계정 식별 범위, raw/증거 보존 정책. 이 선택을 바꾸면 관련 패널과 데이터 요구사항을 먼저 함께 수정한다.

완료 기준: 모든 Panel ID가 데이터 매트릭스와 연결되고, 미구현 기능이 현재 기능처럼 기술되지 않으며, 구현 파일과 테스트 계획이 추적 가능하다. 문서 작성 완료와 설계 승인/기능 구현 완료는 구분한다.

## 4. Phase 1: 현재 SSH 기반 읽기 전용 SOC Operations

목표 패널: OPS-06, OPS-07, OPS-11의 기존 열. 화면에서 최신 이벤트가 누락된 이유를 알 수 있어야 하므로 G-01을 선행 수정한다.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `src/cloud_soc/elastic/repository.py` | 수정 | PIT/search_after 기반 전체 raw 페이지 조회, 공통 조회 도우미, 타임아웃/부분 실패 감지 |
| `src/cloud_soc/detection/engine.py` | 수정 | normalized 전체 페이지 읽기 재사용. 페이지 경계에서 시간창/cooldown이 끊기지 않게 처리 |
| `src/cloud_soc/main.py` | 수정 | 조회 완료/실패 신호, 실패 종료 코드, 처리 통계 의미 정리. 불완전 읽기를 정상으로 취급하지 않음 |
| `src/cloud_soc/config.py` | 신설 | 검증된 설정 로드 단일 진입점 |
| `config/app.yml` | 수정 | 실제 raw 패턴/인덱스/폴링/조회 배치 크기 설정을 런타임과 일치 |
| `requirements.txt` | 수정 | 현재 동작이 검증된 의존성 버전을 기록하고 재설치 회귀 검증 |
| `tests/test_repository_pagination.py` | 신설 | 10,000건 초과, 동일 시각, 페이지 실패, PIT 정리, 누락/중복 검증 |
| `tests/test_detection_engine.py` | 신설 | 기존 탐지 조건, 창/cooldown 경계, 페이지를 가로지르는 탐지 회귀 |
| `tests/test_main.py` | 신설 | ES 실패 시 종료 코드, 설정 반영, mock 클라이언트 정리 |
| `tests/fixtures/linux_auth.txt` | 신설 | 비식별 SSH 샘플. `.log`는 현재 gitignore에 걸리므로 추적 가능한 확장자 사용 |
| `kibana/operations.ndjson` | 신설 | 검증한 Data View/읽기 전용 패널 export. 더미 saved object를 손으로 만들지 않음 |
| `docs/kibana_setup.md`, `README.md` | 신설/수정 | import/조회 범위/기존 대시보드 보존/실행 방식 문서화 |

첫 구현은 전체 배치 조회로 정확성을 먼저 확보한다. 매회 전체 재처리는 규모 한계가 있으므로 처리 시간/메모리를 측정하고 이를 증분 처리 완료라고 부르지 않는다. 현재 이벤트 수를 감당하지 못하면 부분 처리 성공을 반환하지 말고 후속 증분 처리 작업을 선행한다.

완료 기준:

- 원본 10,001건 이상의 테스트에서 마지막 문서까지 처리 대상으로 읽으며 동일 시각 문서도 빠지지 않는다.
- 9건 미탐지, 창 안 10건 탐지, 300초 경계 포함/초과, cooldown 경계의 기존 동작이 고정된다.
- 기존 field와 ID 동작을 회귀 검사하고 운영 ES가 아닌 mock 또는 격리 테스트 인덱스에서 검증한다.
- 실제 기존 데이터로 운영 화면을 검증하되 상태/담당자/미산정 점수를 만들어 넣지 않는다. 최근 데이터가 없으면 조회 범위와 최신 시각을 보여준다.
- Dashboard export를 다른 테스트 공간으로 import하여 표/필터/기간 조건을 재현한다. 기존 대시보드는 덮어쓰지 않는다.

## 5. Phase 2: 조사 가능한 이벤트·경보 모델

목표 패널: INV-01~04의 데이터, OPS-08~11/ENT-01~05의 Entity 연결. 시각/소스 ID는 Health의 선행 데이터로 함께 마련한다.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `src/cloud_soc/main.py` | 수정 | raw metadata/reference_time 전달, 실제 조직 전달, 새 경보 저장 계약 호출 |
| `src/cloud_soc/normalizers/ecs.py` | 수정 | raw 참조, 수집/수신 시각, 시간대/품질, host.id/agent 정보, schema version |
| `src/cloud_soc/entities.py` | 신설 | scope를 포함한 Host/User/IP 키 생성, IP canonicalization |
| `src/cloud_soc/detection/engine.py` | 수정 | 실제 window evidence, Entity/서비스/소스 ID, 조직 격리, 규칙 정보 전달 |
| `src/cloud_soc/detection/rule_loader.py` | 수정 | severity/cooldown/type 검증, 규칙 구성 버전/스냅샷 |
| `rules/authentication.yml` | 수정 | 조직별 그룹 격리를 명시하고 이벤트 수 설명/주석 정합성 개선. 임계값/탐지 종류는 유지 |
| `src/cloud_soc/elastic/repository.py` | 수정 | 신규 mapping, 최초 생성 시각 보존/멱등 저장, 증거 조회 함수 |
| `src/cloud_soc/elastic/migrations.py` | 신설 | 명시적 additive mapping 적용, 버전 확인, dry-run/검증; 기존 ensure 함수와 구분 |
| `filebeat/filebeat.yml` | 수정 | 검증한 Host 메타데이터/수집원 ID, 중앙 ingest pipeline 연결 |
| `config/data_sources.yml` | 신설 | 조직/Host/수집원 ID/시간대/네트워크 범위 등록 |
| `elasticsearch/ingest/raw_ingest.json` | 신설 | 중앙 최초 수신 시각 설정. 과거 데이터 backfill 시각과 구분 |
| `tests/test_normalizer.py`, `tests/test_entities.py`, `tests/test_alert_model.py`, `tests/test_migrations.py`, `tests/test_rule_loader.py` | 신설 | 필드/식별/시각/스냅샷/호환성/검증 실패 테스트 |
| `docs/data_migration.md` | 신설 | 필드 보강 가능 범위, legacy 경보 처리, 참조 보존, 되돌리기/백업 |

완료 기준:

- 하나의 경보에서 N 문서와 원래 R 문서의 index/ID까지 정확히 추적된다. 보존 만료/권한 거절/참조 누락을 구분한다.
- 다른 조직에서 같은 IP로 5건씩 발생해도 합쳐서 AUTH-001을 만들지 않는다. 한 조직 내 여러 Host 합산 동작은 유지한다.
- 여러 타깃을 가진 경보가 첫 Host/User만 가진 것처럼 저장되지 않는다. 서비스/목적지 포트가 없으면 없는 상태를 유지한다.
- 연말 재처리, 비 UTC 소스, 수신 지연을 검증하며 근거 없는 연도 확정을 피한다. 기존 시각 재해석은 migration으로만 수행한다.
- 동일 배치 재처리 시 중복 경보/새 생성 시각이 생기지 않는다. 규칙 변경/늦은 이벤트로 기존 ID가 달라지는 경우는 명시적 재탐지 정책과 테스트가 필요하다.
- 과거 경보의 증거를 재구성했으면 재구성 표시가 있고, 모르는 생성 시각은 New Last 1H에 포함하지 않는다.
- 인덱스가 이미 있는 환경에서도 mapping 검증이 통과한다. 기존 문서를 지우고 새로 만들어 통과시키지 않는다.

### Phase 2B: 증분 처리 안정화 게이트

Phase 1의 전체 배치 비용이 설정된 처리 간격을 넘거나 계속 실행할 환경으로 전환하기 전 수행한다. 단순 페이지 조회와 분리된 작업 단위다.

수정 파일: `src/cloud_soc/main.py`, `src/cloud_soc/elastic/repository.py`, `src/cloud_soc/detection/engine.py`, `config/app.yml`. 신설 파일: `src/cloud_soc/pipeline_state.py`, `tests/test_pipeline_recovery.py`, `docs/pipeline_recovery.md`.

체크포인트/중복 처리/그룹별 window/cooldown 상태를 함께 저장한다. 페이지 cursor는 같은 PIT 안에서만 사용하고 영속 커서는 중앙 수신 시각과 안정적 식별자, 겹쳐 읽는 범위로 설계한다. 수신 지연·refresh 지연으로 늦게 검색되는 문서를 위한 안전 여유와 재조정 경로가 필요하다. 허용 지연 범위를 벗어난 데이터는 조용히 폐기하지 않고 재처리 대상으로 기록한다.

완료 기준: 저장 전/후 강제 종료, 같은 시각 여러 문서, 페이지 재시도, 로그 순서 역전, 재시작 직전 9건/직후 1건, cooldown 중 재시작을 통과한다. 체크포인트는 성공한 저장 결과를 앞서가지 않는다. 기존 경보 ID/최초 생성/증거/분석 상태 보존을 함께 검증하기 전 증분 모드를 기본값으로 바꾸지 않는다.

## 6. Phase 3: Alert Investigation와 Analyst Workflow

목표 패널: INV-01~05 및 OPS-01~04/11의 실제 상태 기능. 현재 Kibana 프로토타입에서 업무형 큐로 확장한다.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `src/cloud_soc/workflow/repository.py`, `src/cloud_soc/workflow/service.py`, `src/cloud_soc/workflow/__init__.py` | 신설 | SQLite 스키마/트랜잭션, 상태 전이/종결 조건, 메모/변경 이력, 멱등 등록 |
| `src/cloud_soc/queries/alerts.py`, `src/cloud_soc/queries/__init__.py` | 신설 | ES 후보와 SQL 상태 결합, 정확한 KPI/정렬/페이지, 증거/주변 이벤트 조회 |
| `src/cloud_soc/web/app.py`, `src/cloud_soc/web/auth.py`, `src/cloud_soc/web/__init__.py` | 신설 | 읽기/변경 라우트, 인증/조직별 인가, CSRF, 입력 검증/응답 오류 |
| `src/cloud_soc/web/templates/layout.html`, `src/cloud_soc/web/templates/operations.html`, `src/cloud_soc/web/templates/alert.html` | 신설 | 공통 탐색, 경보 큐, 경보 조사/상태/메모 UI |
| `src/cloud_soc/web/static/soc.css`, `src/cloud_soc/web/static/soc.js` | 신설 | 표/필터/상세/갱신 동작. 프레임워크 없는 작은 UI 우선 |
| `src/cloud_soc/main.py` | 변경 불필요 | 탐지 엔진은 workflow에 쓰지 않음. 웹 서버의 workflow service가 신규 ES 경보의 상태 초기 등록/누락 재조정을 담당 |
| `config/app.yml`, `.env.example`, `requirements.txt` | 수정 | 필요한 서버 설정/선택한 최소 웹 의존성. 비밀값은 예시에 넣지 않음 |
| `tests/test_workflow.py`, `tests/test_alert_queries.py`, `tests/test_web_auth.py` | 신설 | 상태 전이/충돌/권한/누락 등록/조회 일관성 |
| `docs/soc_web.md`, `README.md` | 신설/수정 | 실행 방법, 개발/배포 경계, 백업, 조회 상한/제약 |

완료 기준:

- New -> Investigating -> Closed 및 재개 흐름, Verdict/이유 필수 조건, 담당자/메모/이력이 재시작 후 유지된다.
- 두 분석가의 같은 버전 수정은 한 요청만 성공하고 다른 요청은 충돌 안내를 받는다.
- 경보 재처리/등록 재시도로 Closed가 New가 되거나 메모가 사라지지 않는다.
- 상태/담당자 필터 후 전체 합계와 모든 페이지를 검증한다. 프런트엔드 현재 페이지 안에서만 필터링하는 구현을 허용하지 않는다.
- 후보 조회 상한, ES 부분 실패, SQL 장애는 정확한 0건/전체 합계로 표시되지 않는다. 조회 스냅샷의 시점을 표시한다.
- 다른 조직의 경보/증거/메모 접근과 비인가 상태 변경이 서버에서 차단된다. 악성 로그/메모 문자열은 HTML로 실행되지 않는다.

## 7. Phase 4: Entity Investigation

목표 패널: ENT-01~05, OPS-08~10.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `src/cloud_soc/queries/entities.py` | 신설 | Entity별 인증 활동/관련 경보/관계/시간순 이벤트 조회 |
| `src/cloud_soc/entities.py`, `src/cloud_soc/queries/alerts.py` | 수정 | Entity 키와 경보 연결 재사용, 상태 반영 우선순위 |
| `src/cloud_soc/web/app.py`, `src/cloud_soc/web/templates/operations.html` | 수정 | Entity route/필터/드릴다운 연결 |
| `src/cloud_soc/web/templates/entity.html` | 신설 | Host/User/IP 탭, 요약/관계/Timeline |
| `tests/test_entity_queries.py`, `tests/test_drilldown.py` | 신설 | 식별 범위/관계/기간/접근 권한/페이지 동작 |

완료 기준: 두 Host의 동명 `root`가 분리되고, 여러 네트워크의 같은 사설 IP가 섞이지 않으며, 경보의 다중 타깃이 누락되지 않는다. Entity별 경보 수 중복 의미, 기간 내 First/Last Seen, 실패 이벤트와 인증 시도 차이를 화면에서 확인한다. 신규 위험 점수 없이도 조사 우선순위를 설명할 수 있어야 한다.

## 8. Phase 5: Data Source Health

목표 패널: HEALTH-01~03, OPS-05.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `config/data_sources.yml` | 수정 | 소스별 활성/기대 주기/무활동/Heartbeat/지연 정책 |
| `src/cloud_soc/health/collector.py`, `src/cloud_soc/health/service.py`, `src/cloud_soc/health/__init__.py` | 신설 | 생존/실행 결과 수집과 상태 판정, 관측 만료 |
| `src/cloud_soc/main.py`, `src/cloud_soc/pipeline_state.py` | 수정 | 정상/미지원/실패/체크포인트 실행 통계 연결 |
| `src/cloud_soc/elastic/repository.py` | 수정 | health mapping/저장/최근 관측 조회 |
| `src/cloud_soc/queries/health.py` | 신설 | registry 기준 외부 결합, raw 수신량/지연/생존 집계 |
| `src/cloud_soc/web/app.py`, `src/cloud_soc/web/templates/health.html` | 수정/신설 | Health 표/추이/상세와 운영 경고 링크 |
| `tests/test_source_health.py`, `tests/test_pipeline_health.py` | 신설 | 유휴/무수신/중단/지연/파싱 실패/관측 만료 테스트 |
| `docs/source_health.md` | 신설 | 생존 확인 배치 방법과 판정 한계, EPS/분당 이벤트 정의 |

완료 기준: 등록됐지만 0건인 수집원이 보인다. 생존 확인이 정상인 유휴 SSH와 수집기/터널 장애를 구분한다. 별도 Collector 생존 신호가 없으면 UNKNOWN으로 남긴다. raw만 수신되고 worker가 중단된 상황을 HEALTHY 한 단어로 숨기지 않는다. 음수 지연/시계 불일치, API 조회 실패, health writer 중단, 재처리로 인한 수집량 부풀림을 검증한다.

## 9. Phase 6: OCI Audit 기반 클라우드 관리 활동

추가 조건: `누가 어느 리소스에 어떤 관리 작업을 했는가?`라는 ENT-05/INV-03 조사 질문과 필요한 API 작업 목록을 먼저 확정한다. OCI VM의 SSH 계정과 OCI IAM 행위자를 같은 이름이라는 이유로 합치지 않는다.

| 파일 | 구분 | 작업 |
| --- | --- | --- |
| `src/cloud_soc/collectors/oci_audit.py`, `src/cloud_soc/collectors/__init__.py` | 신설 | Audit API 인증/페이지/재시도/지연 수집/체크포인트. 관리 API 로그는 Filebeat 파일 입력으로 가정하지 않음 |
| `src/cloud_soc/parsers/oci_audit.py`, `src/cloud_soc/normalizers/oci_audit.py` | 신설 | actor/resource/action/result/time/request ID, 공급자 원본 보존 |
| `src/cloud_soc/main.py`, `src/cloud_soc/entities.py`, `src/cloud_soc/elastic/repository.py` | 수정 | 소스별 정규화 경로, 클라우드 계정 scope, 필요한 mapping만 추가 |
| `config/data_sources.yml`, `.env.example`, `requirements.txt` | 수정 | API 주기/권한/SDK 설정. 실제 자격 증명은 Git 밖 |
| `src/cloud_soc/queries/entities.py`, `src/cloud_soc/web/templates/entity.html` | 수정 | Cloud 관리 활동 Timeline과 리소스/행위자 상세 |
| `tests/fixtures/oci_audit.json`, `tests/test_oci_audit.py` | 신설 | 비식별 실제 형식 fixture, 페이지/중복/누락/권한 실패/필드 누락 |
| `docs/oci_audit.md` | 신설 | 패널 -> 필드 -> API/권한 관계, 지원 작업, 수집 지연/보존 한계 |

완료 기준: 정상 관리 작업 하나를 행위자 -> 대상 -> 결과 -> 원본으로 조사하고 Health에서 Audit 수집 상태를 확인한다. 원본 event ID를 이용해 반복 수집을 중복 저장하지 않으며 API 지연/페이지 경계에서 누락되지 않는다. 실제 존재하지 않는 필드를 IP/계정/작업명으로 추정하여 채우지 않는다.

특정 중요 변경을 경보로 만들 필요가 확인되면 그때 `rules/cloud_audit.yml`과 해당 규칙 테스트를 별도 작업으로 추가한다. 반복 실패 후 성공 같은 순서 탐지는 기존 threshold 엔진의 기능이라고 주장하지 말고 별도 설계/테스트로 확장한다.

## 10. 검증 및 작업 단위

기본 테스트는 외부 서비스가 필요 없는 `unittest`와 mock을 우선 사용한다. ES 통합 테스트는 별도 테스트 인덱스/설정과 명시적인 실행 옵션으로 분리한다. 운영 `raw-logs-*`, `normalized-events`, `security-alerts`에 쓰는 테스트를 기본 실행 경로에 넣지 않는다.

향후 tests 작성 후 사용할 PowerShell 실행 예시:

```powershell
# D:\cloud-soc에서 실행. 현재 작업에서는 tests를 생성하거나 실행하지 않았다.
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py'
```

최종 시연 시나리오: 비식별 SSH 이벤트 -> 경보 큐 -> 근거 확인 -> Host/User/IP 조사 -> 원본 확인 -> 판단/종결 -> 동일 데이터를 재처리해도 이력 유지 -> 수집/worker 중단을 Health로 구분. 실제 서버 공격/설정 변경은 별도 허가된 실습 환경에서만 수행한다.

각 Phase는 가능하면 `테스트 고정`, `최소 코드 변경`, `화면 및 문서` 단위로 나눈다. 설계 문서만 있는 현재 상태에서 아래 feat 커밋을 만들지 않는다. 사용자의 요청 없이 commit/reset/rebase를 수행하지 않는다.

추천 커밋 메시지:

```text
docs: SOC 업무 화면과 드릴다운 요구사항 정의
docs: 대시보드 데이터 갭과 단계별 구현 계획 정리
fix: 이벤트 조회 페이지 처리와 실패 신호 보강
feat: 경보 조사 근거와 원본 이벤트 연결 추가
feat: 분석 상태와 판단 이력 저장 기능 추가
feat: 수집원 상태와 파이프라인 지연 관측 추가
```

# Cloud SOC 데이터 요구사항 및 Gap Analysis

기준일: 2026-09-10. 분석 기준: 로컬 HEAD `4724824e31af2884dec6fc77e92fab5fb1a2e7ad`와 동일한 원격 main, 현재 Python/설정 파일, Elasticsearch 읽기 전용 조회, Kibana saved object 조회.

관련 문서: [화면 요구사항](dashboard_requirements.md), [단계별 구현 계획](dashboard_implementation_plan.md).

이 문서의 `현재`는 분석 시점의 관측이며, `추가/제안`은 미구현 설계다. 애플리케이션 코드, 설정, ES 문서는 이번 작업에서 수정하지 않는다.

## 1. 현재 구현 상태

| 영역 | 확인한 구현 | 현재 한계 |
| --- | --- | --- |
| `compose.yaml` | ES/Kibana 9.5.2, ES 볼륨, localhost 포트 바인딩, ES healthcheck | Python worker/web 서비스 없음. 개발용 인증 비활성화 |
| `filebeat/filebeat.yml` | Ubuntu `/var/log/auth.log` filestream, 조직/소스 라벨, SSH 터널 경유 ES 전송 | `host.id`, 수집원 ID, 중앙 수신 시각, 생존 상태 없음 |
| `parsers/linux_auth.py` | classic syslog 형식의 SSH Accepted/Failed password/Invalid user 해석, IP 형식 검증 | ISO 시각 접두어 등 다른 형식 미지원. 일부 메시지만 파싱 |
| `normalizers/ecs.py` | 인증 분류, 시각, Host 이름, User 이름, Source IP/Port, SSH 서비스, 원문 | raw 참조, 수집 메타데이터, 안정적 Entity 키 미전달 |
| `detection/rule_loader.py` | YAML safe_load, 필수 값/연산자/규칙 ID 중복 검사 | 규칙 버전, severity/cooldown 등 일부 값 검증 보강 필요 |
| `detection/engine.py` | AND 조건, Threshold, Sliding Time Window, 여러 필드 Group By, 호출 내 Cooldown | 근거 참조 출력 없음. 영속 상태/순서 상관분석 없음 |
| `rules/authentication.yml` | AUTH-001, high, 10건/300초, Source IP 그룹, 300초 cooldown, MITRE 메타데이터 | 인증 시도 수가 아닌 일치 로그 수. 조직별 그룹 분리 없음 |
| `elastic/repository.py` | normalized/alert mapping 생성, 저장/조회, 정해진 ID로 저장 가능 | 페이지 조회/체크포인트/기존 mapping 갱신 없음 |
| `main.py` | raw -> normalize -> detect -> alert 단발/`--watch`, ID 생성, 묶음 refresh | 매회 과거 데이터 조회, 설정 상수, 경보 조직 고정, 처리 통계 영속화 없음 |
| `elastic/client.py` | dotenv, 인증값 쌍 검증, timeout, 연결 확인, 직접 실행 실패 시 종료 코드 1, close | 이 파일의 실패 종료 코드 문제는 이미 해결됨. main의 예외 처리는 별개 |
| `config/app.yml` | 인덱스/폴링 설정 파일 존재 | 실행 코드에서 읽지 않음. 실제 raw 조회는 main의 `raw-logs-*` |
| `tests/` | Git 추적 테스트 없음 | 모듈 내부 출력 예시는 assertion 기반 회귀 테스트가 아님 |
| Kibana | `Cloud SOC 통합 보안관제 대시보드`, 7개 패널인 saved object 존재 | Git에 내보낸 대시보드 없음. 4개 업무 화면/상태 저장 구현 근거 없음 |
| `docs/` | 기존 DOCX 계획서 2개 | 현재 코드와 범위가 다른 과거 계획 포함 |

### 실제 데이터 확인

`_search`의 `track_total_hits: true` 및 `exists` 집계로 확인했다. Filebeat template에 필드가 정의되어 있다는 사실만으로 실제 데이터가 있다고 판단하지 않았다.

| 조회 대상 | 문서 수 | 확인된 실제 필드 | 확인한 필드 중 값이 없는 항목 |
| --- | --- | --- | --- |
| `raw-logs-*` | 53,826 | `@timestamp`, `host.name`, `agent.id` 모두 전체 문서에 존재 | `host.id`, `event.created`, `event.ingested`, `cloud_soc.data_source.id` |
| `normalized-events` | 1,276 | Host/User 이름, Source IP/Port, service.type 모두 전체 문서에 존재 | `host.id`, `agent.id`, 원본 문서 참조, 수신 시각, 수집원 ID |
| `security-alerts` | 9 | Source IP, severity, event_count, window_start 모두 전체 문서에 존재 | Host/User, service.type, rule.description, 근거 참조, 생성 시각 |

raw 조회 패턴은 현재 `.ds-raw-logs-...` backing index를 가진 데이터 스트림의 문서를 반환한다. 표시명과 실제 `_index`를 구분하고 원본 참조에는 응답의 정확한 `_index`를 보존한다.

이 수치는 특정 시점의 저장 상태다. 원본 전부가 SSH 파싱 대상은 아니므로 `53,826 - 1,276`을 파싱 실패 건수로 계산하면 안 된다. 저장 데이터 존재만으로 현재 수집기/worker가 실행 중이라고 판정하지 않았다. 이번 문서 작업에서 파이프라인 실행이나 테스트 데이터 삽입은 하지 않았다.

### 유지할 장점

- 원본/정규화/경보를 분리하여 재처리와 조사 계층을 확장할 기반이 있다.
- Parser, Normalizer, Rule Loader, Engine, Repository가 분리되어 전면 재작성할 이유가 없다.
- ECS 형태의 인증 이벤트와 keyword/ip/date mapping 덕분에 기존 필드로 시간 추이와 검색을 시작할 수 있다.
- YAML 규칙과 순수 Python 탐지 로직은 경계 조건을 작은 테스트로 고정하기 좋다.
- 같은 raw index/ID에서 같은 normalized ID를 만들므로 동일 문서 재처리 중복 방지 기반이 있다. 다만 Filebeat가 다른 ID로 재전송한 이벤트까지 중복 제거하는 것은 아니다.

### 기존 문서와의 관계

`클라우드 보안관제(4조).docx`에는 `security-events-*`, 웹 로그 등 과거 계획이 있다. 현재 저장소는 `normalized-events`/`security-alerts`가 기준이다. `클라우드_보안관제_MVP_구현계획.docx`의 근무시간 권한·출퇴근·세션 회수 계획은 현재 Cloud SIEM 코드/요구와 다른 범위다. 두 문서는 삭제하지 않고 과거 참고 자료로 유지하며, 이번 대시보드 구현의 기준으로 혼용하지 않는다.

## 2. 우선 해결할 Gap

P1은 정확한 운영/조사 화면을 막는 문제, P2는 특정 기능 도입 전에 보완할 문제다. 여기의 우선순위는 대시보드 구현 관점이며 보안 취약점 등급이 아니다.

| ID / 우선순위 | 근거 위치 | 문제와 화면 영향 | 처리 방향 |
| --- | --- | --- | --- |
| G-01 / P1 | `elastic/repository.py:439`, `detection/engine.py:487` | 오래된 순서로 최대 10,000건만 읽음. raw 실제 수가 이미 한도를 넘어 새 데이터가 처리 대상에서 밀림 | 전체 페이지 조회 후 체크포인트로 확장. 조회 한도를 올리는 것만으로 해결하지 않음 |
| G-02 / P1 | `detection/engine.py:390`, `main.py:69` | 경보에 근거 ID/Host/User가 없어 Entity와 사건 근거를 정확히 연결할 수 없음 | 엔진의 근거 참조 전달, 규칙 스냅샷, 관련 Entity 보존 |
| G-03 / P1 | `main.py:269`, `main.py:323`, `elastic/repository.py:192` | ID 기반 재저장일 뿐 경보/분석 이력 보존 계약은 없음. 늦은 이벤트로 window/ID도 바뀔 수 있음 | 새 경보 최초 생성 보장, 재처리/재탐지 구분, workflow 별도 저장 |
| G-04 / P1 | `rules/authentication.yml`, `main.py:111` | Source IP만으로 조직 간 이벤트 합산 가능, 경보 조직은 고정 | 조직을 그룹/ID에 포함하고 실제 조직 전달. 다중 조직 지원 완료를 주장하지 않음 |
| G-05 / P1 | `main.py:255`, `normalizers/ecs.py:19` | 재처리 시 현재 연도/기본 UTC로 classic syslog 시각 추정. 원본 참조와 수신 시각도 없음 | 수집 기준 시각/소스 시간대 전달, 불확실성 표시, raw 연결 보존 |
| G-06 / P2 | `parsers/linux_auth.py:228`, `rules/authentication.yml` | Invalid user와 Failed password가 한 시도에서 둘 다 나올 수 있음. 10개 실패 로그를 10번 시도로 설명하면 부정확 | 이벤트 수로 명명. 시도 수가 필요하면 별도 상관키/검증 후 도입 |
| G-07 / P2 | `filebeat/filebeat.yml`, `main.py:377` | 등록 수집원 목록, Heartbeat, 중앙 수신 시각, 단계별 실패/지연 지표 없음 | 수집원 registry, ingest timestamp, 처리 실행 기록; 없으면 UNKNOWN |
| G-08 / P2 | `elastic/repository.py:163`, `elastic/repository.py:369` | 인덱스가 있으면 mapping 업데이트 없음. Python mapping 변경만으로 기존 ES가 바뀌지 않음 | 명시적 mapping migration과 과거 문서 보강 계획 |
| G-09 / P2 | `main.py:496`, `config/app.yml`, `requirements.txt` | main의 실패 종료 신호, 미사용 설정, 미고정 의존성, 자동 회귀 테스트 부족 | 예외/종료 코드 테스트, 단일 설정 진입점, 검증 버전 기록 |

## 3. Panel별 데이터 요구사항

약어: R=`raw-logs-*`, N=`normalized-events`, A=`security-alerts`, W=제안 SQLite workflow, S=제안 `config/data_sources.yml`, H=제안 `soc-pipeline-health`. W/S는 ES 필드가 아니다. H는 보안 로그 소스가 아닌 내부 운영 관측 데이터다.

`있음`은 필요한 문서에 값이 있음을 뜻한다. `부분`은 일부 데이터만 있거나 집계/연결 기능이 없음을 뜻한다. `없음`은 해당 기능을 지금 구현할 수 없다는 뜻이다.

| Dashboard | Panel | 필요한 데이터 | Elasticsearch 필드 | 현재 존재 여부 | 추가 개발 필요 |
| --- | --- | --- | --- | --- | --- |
| SOC Operations | OPS-01 Open Alerts | A + W, 미종결 상태와 경보 ID | A `_id`, `organization.id`; 상태는 W.status | 부분: 경보 있음, 상태 없음 | workflow, 상태 반영한 정확한 count |
| SOC Operations | OPS-02 Critical/High | A + W, 미종결 심각도별 수 | `cloud_soc.severity`, `_id`; W.status | 부분: 심각도 있음 | 상태 결합, 큐와 동일 범위 집계 |
| SOC Operations | OPS-03 New Last 1H | A, 최초 생성 시각 | 추가 `event.created` | 없음: `@timestamp`는 발생 시각 | 생성 시각 불변 저장, 과거 경보 제외 정책 |
| SOC Operations | OPS-04 Investigating | A + W, 조사 중 상태 | `_id`; W.status | 없음 | workflow 조회 |
| SOC Operations | OPS-05 Health KPI | S + H + R, 기대 소스와 이상 상태 | 추가 `cloud_soc.data_source.id`, `event.ingested`, H 상태 | 없음 | 등록원 기준 집계, 무수신/불명 상태 |
| SOC Operations | OPS-06 Alert Trend | A, 선택 기간 경보 건수 | `@timestamp`, `cloud_soc.severity` | 있음: 기존 기본 집계 가능 | 기간/부분 결과 안내; 정확한 파이프라인은 G-01 의존 |
| SOC Operations | OPS-07 Top Rules | A, 규칙별 경보 수 | `rule.id`, `rule.name`, `@timestamp` | 있음 | ID 기준 집계, 이름 변경 고려 |
| SOC Operations | OPS-08 Priority Hosts | A + W + N, Host별 경보 연결 | 추가 A `cloud_soc.entities`, N `host.id`, `host.name` | 부분: N 이름만 있음 | Host 식별/경보 연결, 상태 반영 순위 |
| SOC Operations | OPS-09 Priority Users | A + W + N, 범위 있는 계정별 경보 | 추가 `cloud_soc.entities`; N `user.name` | 부분: N 이름만 있음 | 로컬 계정 scope, 상태 반영 순위 |
| SOC Operations | OPS-10 Priority IPs | A + W + N, IP별 경보/관련 타깃 | A `source.ip`, 추가 `cloud_soc.entities` | 부분: IP별 경보 수만 가능 | 네트워크 범위, 관계/상태 결합 |
| SOC Operations | OPS-11 Alert Queue | A + W, 상세 열과 담당자 | `@timestamp`, `rule.*`, `source.ip`, `cloud_soc.severity`, `cloud_soc.event_count`, `cloud_soc.window_start`, `cloud_soc.window_end`, 추가 `cloud_soc.entities` | 부분: Host/User/상태/담당자 없음 | 경보 모델, workflow, 전역 정렬/페이지 조회 |
| Alert Investigation | INV-01 Summary | A, 식별/시각/대상/서비스 | `_id`, `rule.*`, `source.ip`, `cloud_soc.*`; 추가 `service.*`; 선택 `destination.port`, `event.risk_score_norm` | 부분: 기본 경보만 있음 | 타깃/서비스 보강; 포트/점수는 근거 없으면 미수집/미산정 |
| Alert Investigation | INV-02 Reason | A, 규칙과 실제 조건 | 기존 threshold/count/window; 추가 `rule.description`, `rule.version`, `event.reason`, `cloud_soc.rule_snapshot` | 부분: 집계 값/고정 메시지만 있음 | 설명·버전·실제 그룹/조건 스냅샷 |
| Alert Investigation | INV-03 Timeline | A -> N, 근거와 전후 이벤트 | N `@timestamp`, `event.action`, `event.outcome`, `host.name`, `user.name`, `source.ip`; 추가 A `cloud_soc.evidence` | 부분: 시간순 이벤트 조회 가능, 근거 연결 없음 | 정확한 근거 참조, 주변 검색 범위/표식 |
| Alert Investigation | INV-04 Related/Raw | A -> N -> R, 문서 연쇄 | N `event.original`, `message`, 추가 `cloud_soc.raw_event.index`, `cloud_soc.raw_event.id`; A `cloud_soc.evidence` | 부분: 원문 있음, raw 연결 없음 | 문서 ID/인덱스 전달, 보존 만료 표시 |
| Alert Investigation | INV-05 Workflow | W, 현재 상태와 변경 이력 | ES에는 상태/메모 중복 저장하지 않음; A `_id` 참조 | 없음 | SQLite 저장소, 서버 API, 인가, 충돌 검사 |
| Entity Investigation | ENT-01 Profile | N + A + W, 식별/관측 범위 | `host.name`, `user.name`, `source.ip`, `@timestamp`; 추가 `host.id`, `cloud_soc.entities` | 부분: 이름/IP만 있음 | 안정적 key/scope, 점수 미산정 처리 |
| Entity Investigation | ENT-02 Auth Activity | N, 인증 이벤트/성공/실패 | `event.category`, `event.action`, `event.outcome`, `@timestamp`, Entity 조건 | 있음: 이름/IP 범위의 기초 집계 | 안정적 Entity 필터, 시도 수와 이벤트 수 구분 |
| Entity Investigation | ENT-03 Related Alerts | A + W, Entity 관련 경보 | 추가 A `cloud_soc.entities`; 기존 rule/severity/window | 부분: IP로만 일부 조회 가능 | Host/User 연결과 상태 결합 |
| Entity Investigation | ENT-04 Relationships | N + A, Host/User/IP 관계 쌍 | `host.name`, `user.name`, `source.ip`, 추가 `cloud_soc.entities` | 부분: N 동일 문서에서 관계 관측 가능 | 범위 있는 키, 경보 연결, 페이지/집계 정확성 |
| Entity Investigation | ENT-05 Timeline | N + R, Entity의 시간순 활동 | `@timestamp`, `event.*`, `service.*`, Entity 필드, 추가 raw 참조 | 부분: SSH만 조회 가능 | 원본 연결; 클라우드 관리 활동은 OCI 확장 단계 |
| Data Source Health | HEALTH-01 Source Table | S + R + N + H, 기대원/수신/생존/지연 | 추가 `cloud_soc.data_source.id`, `event.created`, `event.ingested`, H 상태; N `@timestamp` | 부분: R 시각/라벨만 있음 | registry/수신 시각/소스 정책/Heartbeat; 0건 소스 |
| Data Source Health | HEALTH-02 Ingestion Trend | R, 중앙 수신 시간별 원본 수 | 추가 `event.ingested`, `cloud_soc.data_source.id` | 부분: raw `@timestamp`로 수집 시각 추정만 가능 | ingest pipeline, 소스별 집계, 단위 구분 |
| Data Source Health | HEALTH-03 Pipeline Status | H + S, 단계별 실행 결과 | 추가 `event.kind`, `event.action`, `event.outcome`, `cloud_soc.pipeline.*`, `cloud_soc.data_source.id` | 없음: 콘솔 출력만 존재 | 실행 결과/Heartbeat/오류 참조 영속화 |

`rule.*`, `service.*`, `cloud_soc.*`는 표를 줄이기 위한 표기다. 실제 API에서는 아래 데이터 사전에 정한 필드만 허용한다.

### Panel별 코드 계층 영향

같은 변경을 공유하는 패널은 한 행에 묶었다. `전달`은 새로운 로그 해석이 아니라 기존 수집 메타데이터를 보존하는 변경이다.

| Panel ID | Parser | Normalizer | Detection Engine / Alert builder | 기타 변경 | 새 보안 로그 소스 |
| --- | --- | --- | --- | --- | --- |
| OPS-01, OPS-02, OPS-04, INV-05 | 불필요 | 불필요 | workflow 덮어쓰기 금지 | workflow 저장/조회 API | 불필요 |
| OPS-03 | 불필요 | 불필요 | 최초 생성 시각/멱등 저장 | mapping/과거 경보 정책 | 불필요 |
| OPS-06, OPS-07 | 불필요 | 불필요 | 기존 값 재사용 | 전체 페이지 조회, 집계/화면 | 불필요 |
| OPS-08, OPS-09, OPS-10, OPS-11 | 불필요 | Host/계정/IP 식별 정보 전달 | 근거 Entity와 조직 전달 | workflow/조회 계층 | 불필요 |
| INV-01 | 포트는 현재 로그로 확보 불가 | 서비스/식별 메타데이터 전달 | 대상/서비스/시각 보존 | 선택 필드 N/A 처리 | 목적지 정보 필수화 시 별도 소스 검토 |
| INV-02 | 불필요 | 불필요 | 규칙 스냅샷/설명/버전 | Rule Loader 검증/mapping | 불필요 |
| INV-03, INV-04 | 기존 파싱 유지 | raw 참조/시간 기준 전달 | 정확한 근거 참조 | 증거 조회/보존 정책 | 불필요 |
| ENT-01, ENT-03 | 불필요 | Entity 키 생성 | 경보 Entity 연결 | Entity 조회/workflow | 불필요 |
| ENT-02, ENT-04 | 현재 메시지 해석 재사용 | 식별/시각 보강 | 현재 집계에는 불필요 | Entity 집계/페이지 조회 | 불필요 |
| ENT-05 | SSH 재사용; OCI 때 별도 parser | 공통 필드 + raw 참조 | Timeline 자체에는 불필요 | Entity 조회 | SSH는 불필요, 클라우드 관리 활동은 OCI Audit |
| OPS-05, HEALTH-01, HEALTH-02 | 시각 품질 확인 | 수집/발생 시각 보존 | 불필요 | Filebeat/ingest/registry/health 집계 | 새 보안 로그 불필요; 생존 관측은 추가 |
| HEALTH-03 | 실패/미지원 분류 반환 | 오류 분류 | 실행 결과 기록 | 내부 health 저장/체크포인트 | 새 보안 로그 불필요; 내부 운영 데이터 추가 |

## 4. Elasticsearch 데이터 모델 결정

### 4.1 저장소별 책임

| 저장소 | 책임 | 쓰기 주체 |
| --- | --- | --- |
| R `raw-logs-*` | 수집한 원본과 수집 메타데이터 | Filebeat, 향후 OCI collector, 중앙 ingest pipeline |
| N `normalized-events` | 검색 가능한 ECS 기반 이벤트, 원본 참조, Entity 식별 | 기존 정규화 파이프라인 |
| A `security-alerts` | 탐지 당시 사실/조건/근거, 불변 최초 생성 시각 | 기존 탐지 파이프라인 |
| W `state/soc_workflow.sqlite3` (제안) | 분석가의 현재 상태/담당자/판단과 변경 이력 | 향후 SOC 웹 서버만 |
| H `soc-pipeline-health` (제안) | 수집/정규화/탐지 실행 결과 및 독립적인 생존 관측 | 각 단계의 관측 코드 |
| S `config/data_sources.yml` (제안) | 들어와야 할 소스 목록과 기대 정책 | 운영자가 검토 후 설정 |

ES에 `alert.status`를 추가하고 SQLite에도 같은 상태를 저장하는 이중 원본 구조는 만들지 않는다. 분석가 데이터가 별도인 이유는 현재 엔진이 경보 문서를 재저장해도 업무 이력을 지키기 위해서다.

### 4.2 기존 필드 재사용과 명칭

| 의미 | 현재/채택 필드 | 타입·판단 |
| --- | --- | --- |
| 발생 시각 | `@timestamp` | date. N은 파싱한 발생 시각, A는 탐지를 촉발한 마지막 근거 시각 유지 |
| 이벤트 분류 | `event.kind/category/type/action/outcome/dataset` | keyword. category/type 배열 유지. 현재 N의 `type: info` 의미는 별도 정규화 검토 시 테스트와 함께 조정 |
| Source | `source.ip`, `source.port` | ip / 기존 integer. raw Filebeat의 port는 long이므로 인덱스 혼합 Data View를 기본으로 만들지 않음 |
| Host/User | `host.name`, `user.name` | keyword. 이름은 안정적인 식별자를 대신하지 않음 |
| 서비스 | `service.name`, `service.type`, `network.protocol` | keyword. 기존 N의 sshd/ssh 재사용 |
| 규칙 | `rule.id`, `rule.name` | keyword. 표시 이름 아닌 ID로 규칙별 집계 |
| 경보 심각도 | `cloud_soc.severity` | keyword 유지. 문자열 high를 숫자 타입 `event.severity`로 옮기지 않음 |
| 일치 이벤트 수 | `cloud_soc.event_count` | integer 유지. 중복 `event.count`를 신설하지 않음 |
| 임계값/창 크기 | `cloud_soc.threshold`, `cloud_soc.time_window_seconds` | integer 유지 |
| First/Last Seen | `cloud_soc.window_start`, `cloud_soc.window_end` | date 유지. 별도 first_seen/last_seen을 중복 저장하지 않음 |
| 경보 ID | ES `_id` | API 응답의 `alert_id`로 노출; 같은 값의 `alert.id` 필드 추가 안 함 |
| 원문 | `event.original`, `message` | N 기존 필드. original은 원문 조회용, 검색은 message 사용 |
| MITRE | 현재 `mitre.*` | 당장 유지. ECS threat.*로 이전하려면 별도 migration; 이번 화면 설계의 선행 조건 아님 |

`rule.severity`, `risk.score`, `alert.status`를 ECS 표준 필드라고 가정하지 않는다. ECS의 숫자 심각도/위험 점수와 이 프로젝트의 문자열 우선순위는 구분한다. [ECS Event fields](https://www.elastic.co/docs/reference/ecs/ecs-event), [ECS Rule fields](https://www.elastic.co/docs/reference/ecs/ecs-rule).

### 4.3 추가할 최소 필드

| 저장 위치 | 추가 필드 | ES 타입 | 생산자·의미 |
| --- | --- | --- | --- |
| R/N | `cloud_soc.data_source.id` | keyword | Filebeat 입력 또는 collector 설정의 안정적 수집원 ID. A에는 관련 ID 배열 |
| R/N | `host.id` | keyword | 신뢰 가능한 수집 메타데이터/자산 등록 정보. 현재 raw에도 값이 없어 전달만으로 해결되지 않음 |
| N | `agent.id/name/type/version` | keyword | raw의 Filebeat 정보 전달. 자체 SOC 프로그램 ID로 덮어쓰지 않음 |
| R/N | `event.created` | date | 수집기가 처음 관측한 시각을 확보한 경우 보존 |
| R/N | `event.ingested` | date | 중앙 raw 저장소 첫 수신 시각. N은 같은 원본 이벤트의 이 시각을 보존 |
| N | `cloud_soc.raw_event.index`, `cloud_soc.raw_event.id` | keyword | raw 조회 응답의 정확한 index/ID. 해시에서 역산하지 않음 |
| N | `cloud_soc.time_quality` | keyword | explicit / inferred / unknown. 연도·시간대를 추정했음을 표시 |
| N/A | `cloud_soc.entities` | nested | 아래의 type/key/name/scope. 원래 ECS 필드의 별칭이 아니라 범위 있는 조사 식별자 |
| A | `event.created` | date | 경보를 엔진이 최초 생성/관측한 시각. 재실행 때 갱신 금지 |
| A | `rule.description`, `rule.version` | keyword | 규칙 설명 및 검증된 구성의 버전/해시 |
| A | `event.reason` | keyword | 실제 조건과 관측값으로 만든 탐지 이유. 긴 화면 설명은 snapshot으로 구성 |
| A | `cloud_soc.rule_snapshot` | object, enabled: false | 탐지 당시의 조건/그룹/threshold/window/cooldown 구성. 검색 아닌 근거 보존용 |
| A | `cloud_soc.evidence` | nested | 근거 N 문서의 index/id 참조 목록 |
| A | `cloud_soc.evidence_truncated` | boolean | 저장 참조 수를 제한했을 때 true. 전체 근거 보존 완료로 오인하지 않음 |
| A | `service.name/type` | keyword | 근거 이벤트에서 확인된 서비스. 여러 서비스면 배열과 상세 근거 제공 |
| N/A | `cloud_soc.schema_version` | keyword | 프로젝트 문서 구조 버전. ECS 버전과 별개 |

ECS 시각 구분은 [Event fields](https://www.elastic.co/docs/reference/ecs/ecs-event)를 따른다. 중앙 수신 시각은 서버 ingest 시점에서 정하고 정규화 재처리 시 현재 시각으로 바꾸지 않는다. 수집기가 제공하는 시각을 중앙 수신 시각처럼 신뢰하지 않는다. 과거 문서를 migration하는 시각을 과거의 최초 수집/경보 생성 시각으로 채우지 않는다.

Filebeat의 `agent.id`는 수집 소프트웨어의 식별자다. Host 또는 로그 입력의 고유 ID와 다르다. `observer.name`은 실제 관측 장비 정보가 있을 때만 사용하고 빈 요구사항을 채우려고 만들어 넣지 않는다. [ECS Agent fields](https://www.elastic.co/docs/reference/ecs/ecs-agent).

선택/보류 필드:

- `destination.ip/port`: 실제 목적지 정보가 있는 로그/검증된 서비스 설정에서만 추가. SSH의 source.port로 대체 금지.
- `event.risk_score_norm`: 0~100 점수의 산정 근거/버전이 합의된 이후에만 추가. 현재 값은 미산정이며 `cloud_soc.severity`로 충분한 단계에서는 점수를 만들지 않는다.
- `source.geo.*`: GeoIP 보강 도입 후 선택 표시. 핵심 조사 흐름의 필수 조건이 아니다.
- `rule.category`: 현재 요구에 필요하면 규칙 분류를 정의한 후 추가. 이미 있는 `event.category`를 무조건 복제하지 않는다.
- `user.id`, `cloud.provider/account.id/region`, `cloud_soc.resource.id/type/name`: OCI 관리 활동의 실제 actor/resource 샘플 검증 후 사용. 공급자 원본은 별도 보존한다.

### 4.4 식별과 증거 계약

`cloud_soc.entities`의 요소는 `type`, `key`, `name`, `scope` keyword를 갖는다. key는 구분자 문자열 단순 연결 대신 버전과 구성 요소를 포함한 정규 직렬화의 해시로 만든다. UI 이름이 바뀌어도 안정적 ID가 있으면 key가 바뀌지 않는다.

| type | 기본 구성 | 과거 데이터 처리 |
| --- | --- | --- |
| host | organization.id + host.id | 조직/수집원/host.name의 임시 키, 신뢰도 제한 표시 |
| user | SSH: organization.id + host key + user.name | 이름만 전역 통합하지 않음. 계정 존재 여부 미확인 가능 |
| source_ip | organization.id + 네트워크 scope + 정규화 IP | scope 미확인 표시. IPv6 표기 차이는 canonical 형태로 통일 |

경보에는 근거 이벤트에 등장한 Entity를 모두 기록한다. `host.name`/`user.name`의 첫 값 하나를 경보 대표 대상으로 복제하지 않는다. Host-User 관계는 같은 N 문서에서 확인하고, 독립된 Host 배열과 User 배열을 임의로 교차 결합하지 않는다.

`cloud_soc.evidence`는 각 요소에 `index`, `id` keyword를 둔다. N -> R 참조는 N의 `cloud_soc.raw_event`가 담당한다. 증거 조회는 참조 배열을 그대로 신뢰하지 않고 조직/허용 인덱스/문서 일치를 서버에서 검증한다.

경보의 `cloud_soc.event_count`는 전체 일치 이벤트 수다. 증거 참조 상한을 두면 `evidence_truncated`와 저장된 참조 수를 별도로 보여준다. 상한 초과 시 추가 증거 저장소가 필요할 수 있으나, 단순히 나중에 동일 조건으로 다시 검색한 결과를 당시의 완전한 증거라고 부르지 않는다.

### 4.5 Workflow 저장과 조회

소규모 단일 서버 MVP에서는 Python 표준 `sqlite3` 기반 저장소를 제안한다. ES 탐지 사실과 분석가 변경의 책임을 분리하며 별도 DB 서버는 추가하지 않는다. 여러 웹 서버/쓰기 경쟁이 커지는 경우 저장소를 재평가한다.

| 테이블 | 주요 열 | 계약 |
| --- | --- | --- |
| alert_workflow | organization_id, alert_id, status, verdict, assignee_id, created_at, updated_at, version | 조직+alert_id 기본키; 상태 enum, optimistic concurrency |
| alert_notes | note_id, organization_id, alert_id, author_id, body, created_at | 메모 추가형, 수정은 새 정정 항목 |
| alert_workflow_history | change_id, organization_id, alert_id, actor_id, action, before_json, after_json, created_at | 상태 변경/배정/판단/재개 기록; 현재 값 변경과 동일 트랜잭션 |

SQLite는 그 자체로 위변조 방지 감사 저장소가 아니다. 웹 서버만 쓰기 가능하게 하고 백업/접근 통제/보존 정책을 적용한다. 분석가 ID는 인증 계층이 제공하며 요청 본문에서 변경자를 마음대로 지정하지 못한다.

ES와 SQL 사이에 원자적인 트랜잭션이 없으므로 경보 최초 저장 후 workflow 등록을 멱등 수행하고 누락을 재조정한다. workflow가 아직 없으면 `상태 미등록`으로 표시한다. 기존 경보 등록은 검토한 migration으로 수행하고 재실행 시 Closed를 New로 바꾸지 않는다.

**상태 필터는 페이지를 자른 뒤 적용하지 않는다.** 권장 MVP 조회 계약은 ES의 전체 후보 경보를 PIT로 페이지 순회하고, SQL의 일관된 읽기 스냅샷과 결합한 뒤 상태/담당자 필터, 정렬, 합계, 페이지를 계산하는 것이다. 완료된 동일 결과 집합으로 KPI와 큐를 만든다. 이 방식은 작은 데이터 규모를 위한 것이며 요청 시간/후보 수 상한을 설정한다. 상한을 넘으면 범위 축소를 요청하고, 일부 결과를 정확한 전체 합계로 표시하지 않는다. 성능 검증에서 부족하면 검색용 read model을 별도 설계하되 상태의 원본은 하나로 유지한다.

기존 Kibana 집계는 SQL 상태를 자동 반영하지 않는다. 초기 읽기 전용 대시보드는 그 제약을 명시하고, 업무형 큐와 상태 KPI는 후속 웹 조회 계층이 담당한다.

### 4.6 Health 데이터

`soc-pipeline-health`는 `@timestamp` date, `organization.id` keyword, `event.kind` keyword, `event.action` keyword, `event.outcome` keyword, `cloud_soc.data_source.id` keyword를 가진다. 실행 결과는 `event.kind: metric`, heartbeat는 `event.kind: state`로 구분한다.

추가 `cloud_soc.pipeline` 하위 필드: `stage`, `run_id`, `status`는 keyword; `started_at`, `finished_at`, `checkpoint_at`은 date; `processed_count`, `succeeded_count`, `unsupported_count`, `failed_count`, `pending_count`는 long. 대기량을 실제 계산할 수 없으면 필드를 생략한다. 오류 문서 참조는 제한된 배열로 보존하고 비밀값은 기록하지 않는다.

처리 카운터는 실행별 지표이며 원본 수집량으로 합산하지 않는다. 소스별 행을 만드는 registry와 실제 수신/heartbeat 관측을 결합한다. health writer 자체가 죽으면 성공 상태가 영원히 유지되지 않도록 마지막 관측 시각의 만료를 검사한다.

## 5. 탐지 엔진 확장 원칙

1. 기존 threshold/window/group-by/cooldown 로직을 테스트로 고정한 뒤 재사용한다. 새로운 탐지 언어나 엔진을 도입하지 않는다.
2. 내부 조회 메타데이터는 현재 N 문서 ID만 전달한다. index도 포함하고, sliding window의 실제 일치 문서 참조를 탐지 결과까지 전달한다.
3. 모든 그룹/경보 ID를 조직 범위로 격리한다. AUTH-001의 여러 Host를 향한 같은 IP 집계 의미는 유지한다. Host별 탐지는 나중에 별도 요구/규칙으로 검토한다.
4. 원본 index/ID 기반 normalized ID는 유지한다. 경보 ID 생성에는 조직/규칙 버전/그룹/탐지 발생의 안정성 계약을 추가한다. 지금의 window hash가 모든 늦은 이벤트·재탐지 상황에서 안정적이라고 가정하지 않는다.
5. 일단 완전한 배치를 조회하여 현재 동작을 보존한다. 페이지마다 엔진을 새로 호출하면 창 경계와 cooldown이 끊기므로 금지한다.
6. 증분 탐지는 별도 완료 조건이다. 체크포인트, 창 내 문서 상태, cooldown 상태, 늦은 도착 허용 범위를 함께 영속화해야 한다. 마지막 `@timestamp`만 저장하는 방식은 부족하다.
7. 최초 생성 시각과 당시 증거는 재처리로 변경하지 않는다. 규칙 변경 후 재탐지/역사 데이터 검증은 명시적 작업으로 구분하고 기존 분석 상태를 초기화하지 않는다.
8. 반복 실패 후 성공, 여러 Host 대상 활동, 중요 클라우드 변경은 조사 화면 요구와 샘플이 확정된 뒤 우선순위를 정한다. 이번 단계에서는 규칙을 추가하지 않는다.

페이지 조회는 [Elasticsearch의 PIT와 search_after](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results)를 기준으로 설계한다. PIT 내부의 `_shard_doc` 정렬 값은 해당 스냅샷의 페이지 이동용이지 프로세스 재시작 후 영속 체크포인트가 아니다.

## 6. 마이그레이션과 호환성

- 필드 추가는 별도 migration 명령으로 기존 인덱스에 적용한다. 새 인덱스를 만드는 함수만 고치고 끝내지 않는다.
- 타입 변경은 기존 필드에 강제로 적용하지 않는다. 버전 인덱스/alias/reindex가 필요한 경우 읽기 전환, 참조 ID 유지, 백업/복구 계획부터 검토한다.
- 과거 N의 raw 참조는 raw index/ID에서 현재 해시를 다시 계산하여 검증 가능한 경우에만 복구한다. 원본이 없으면 `연결 불가`로 표시한다.
- 과거 경보에서 당시 증거/생성 시각을 검증할 수 없으면 미확인으로 남긴다. 현재 데이터로 재구성한 근거는 `재구성`이라고 명시하고 원래 탐지 사실로 위장하지 않는다.
- 기존 경보 ID를 바꿔야 한다면 workflow와 북마크를 유지하는 old/new ID 대응표가 필요하다. 자동 전량 재생성은 하지 않는다.
- R/N/A/H는 목적별 Data View로 분리한다. Filebeat의 넓은 template에 존재하지만 값이 없는 필드를 화면에서 지원된다고 표시하지 않는다.
- `ecs.version` 문자열만으로 전체 ECS 준수를 주장하지 않는다. 실제 필드 타입/값/의미와 사용한 ECS 버전을 테스트로 검증한다.

## 7. 결론

지금 바로 검증 가능한 것은 경보 발생 추이, 규칙별 경보 수, 기존 경보 열의 읽기 전용 목록, SSH 이벤트의 이름/IP 기준 탐색이다. 정확한 SOC 업무 흐름을 위해 먼저 필요한 것은 새 로그 종류가 아니라 **조회 누락 해소, 근거/Entity 연결, 시각 의미 확정, 분석 상태 보존, 수집 건강도 관측**이다.

구현 순서와 파일별 완료 기준은 [단계별 구현 계획](dashboard_implementation_plan.md)에 정의한다.

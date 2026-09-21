# Cloud SOC: Analyst-Centric Mini SIEM

버전: 설계 제안 v2 / 2026-09-10. **구현 완료 명세가 아니다.** 외부 조사 후 정의한 목표 제품이며, 현재 구현 대조는 [로드맵](implementation_roadmap_v2.md)에서 수행한다. 기존 `dashboard_*.md`를 자동 대체하지 않는다.

## 1. 제품 목적

클라우드의 여러 보안 Telemetry를 정규화하고 탐지/상관분석으로 조사 신호를 만든다. 분석가는 우선순위 업무를 선택하고 Incident/Alert의 관련 Entity, Timeline, Evidence, Raw Event를 조사한 뒤 근거 있는 판단과 인계 기록을 남긴다.

성공 기준은 경보 수나 화려한 공격 시각화가 아니라 **상용 SIEM의 핵심 분석 흐름을 작은 범위에서 끝까지 재현하는 것**이다. SSH Brute Force는 인증 도메인의 한 사례다. 클라우드 보안의 특성은 제어면 API, IAM 주체, 클라우드 자원 식별 및 워크로드 활동을 함께 조사하는 데서 확보한다.

근거: 제품별 사건/조사 기능과 SOC 연구의 공통점을 [외부 조사 D01~D08](siem_reference_research.md)에 정리했다. 아래 UX/정책/우선순위는 그 근거에 기반한 자체 제안이다.

## 2. 사용자와 사용 상황

| 사용자 | 상황/필요 | 완료 행동 | 사용 화면 |
| --- | --- | --- | --- |
| 1차 분석가 | 근무 시작, 새 경보 다수, 수집 상태 불명 | 범위/건강도 확인, 업무 선택/인수 | MC, PH |
| 조사 분석가 | 권한 변경 또는 의심 활동이 왜 발생했는지 불명 | 이유/원본/전후 활동 확인, 판정 | IW, EN, HT |
| 관제 책임자 역할 | 미배정/장기 미처리 업무, 인계 필요 | 담당/우선순위/인계 승인 | MC, IW |
| 탐지/데이터 엔지니어 | 경보 없음, 파서 실패, 새 로그 도입 | 소스/규칙 상태 확인과 개선 계획 | DC, PH |

졸업작품에서는 한 사람이 여러 역할을 맡을 수 있다. 역할을 분리한 것은 팀 규모를 가정해서가 아니라 읽기/업무 변경/운영 변경 권한을 구분하기 위해서다.

## 3. 핵심 SOC Use Cases

| ID | 분석가 질문/업무 | 필요한 정보 | 목표 행동과 한계 |
| --- | --- | --- | --- |
| UC-01 | 지금 무엇부터 봐야 하는가? | 열린 사건, 미분류 경보, 중요 자산, 담당, 대기 시간, 데이터 건강도 | 이유를 보고 업무를 인수. 건수가 많다고 중요한 것은 아님 |
| UC-02 | 계정/자원의 변경이 정당했는가? | Cloud API 주체/대상/작업/결과, 승인 맥락, 변경 전후 | 정상 변경과 미승인 권한 변경 구별. API 성공만으로 악성 확정 금지 |
| UC-03 | 인증 실패가 실제 침해로 이어졌는가? | 인증 실패/성공, 안정적 계정/Host, 후속 프로세스/권한 활동 | 가능한 침해를 조사. 성공 로그인만으로 계정 탈취 확정 금지 |
| UC-04 | 특정 자원과 관련된 다른 활동은? | Entity ID/관계/유효 기간, 여러 소스 이벤트 | 사건 범위 확장 또는 제외 |
| UC-05 | 탐지되지 않은 활동도 있는가? | 원본/정규화 검색, 가설, 기간, 필드 존재 | Hunt를 기록하고 필요하면 사건/튜닝 항목 생성 |
| UC-06 | 지금 무엇을 볼 수 없는가? | Technique/Rule/필드/Source/최근 테스트/실행 상태 | 미수집·미구현·미검증·운영 실패를 구분 |
| UC-07 | 경보 0건이 데이터 장애 때문인가? | heartbeat, poll 결과, ingest/parse/detect 상태와 backlog | 불확실성 또는 장애를 표시하고 인계 |
| UC-08 | 다른 분석가가 같은 결론을 재현할 수 있는가? | 탐지 버전, 근거 참조, 검색 조건, 판정 이유, 변경 이력 | 인계/종료/재개 가능한 조사 기록 |

## 4. 도메인 개념

| 개념 | 정의 | 다른 개념과의 경계 |
| --- | --- | --- |
| Raw Event | 수집한 원래 레코드와 출처/수집 메타데이터 | 출력용 요약이나 Alert가 아님 |
| Normalized Event | Raw를 공통 의미/타입으로 변환한 개별 관측 | 성공적으로 파싱했다고 사실의 진실성까지 보장하지 않음 |
| Detection | 특정 버전의 규칙/분석 실행 및 일치 결과 | 실행 성공 0건, 실패, 일치, 억제를 구별 |
| Alert | 탐지 조건이 충족되어 검토가 필요한 신호 | 침해 확정 또는 Incident와 동의어가 아님 |
| Incident | 관련 Alert/Event/Entity를 묶은 **의심 사건 조사 업무 단위** | confirmed incident 여부는 별도 판단. 이름만으로 실제 침해 확정 아님 |
| Case | 제품마다 의미가 다름. 본 프로젝트에서는 Incident의 업무 기록 기능에 해당 | MVP에 Incident와 중복되는 별도 Case 엔티티를 만들지 않음 |
| Evidence | 판단에 채택한 관측/문서 참조와 채택 이유/출처 | 같은 IP/시간으로 검색한 related event 전부가 증거인 것은 아님 |
| Entity | 일정한 범위/기간에서 식별되는 계정·시스템·주소 등 | IP/계정/Host 이름을 사람이나 영구 자산과 동일시하지 않음 |
| Hunt | 가설 기반 능동 검색 과정과 결과 | 저장 Query 하나와 동일하지 않음 |

Incident 자동 생성이 없어도 Alert와 Incident 모델은 처음부터 분리한다. MVP는 Alert 하나를 조사하다 수동 Incident로 승격하거나 여러 Alert를 수동 연결한다. 큐의 `미분류 Alert` 탭을 남겨 사건으로 묶이지 않은 경보가 사라지지 않게 한다.

## 5. Workspace 및 업무 연결

| 코드 / Workspace | 중심 질문 | 중심 화면 요소 | 다른 화면으로 가는 이유 |
| --- | --- | --- | --- |
| MC / SOC Mission Control | 무엇부터 처리할까? | Incident 큐 + 미분류 Alert 탭 | IW 조사, PH 수집 확인 |
| IW / Investigation Workbench | 왜 탐지됐고 근거는 무엇인가? | 이유, Timeline, Evidence, 판단/이력 | EN 범위 확인, HT 추가 검색 |
| EN / Entity Investigation | 같은 Entity의 다른 활동은? | Profile, 관계, 관련 사건/이벤트 | IW 연결, HT 가설 확장 |
| HT / Threat Hunting & Event Search | 미탐지 활동은 없는가? | Query, 결과, 가설/북마크 | IW에 근거 채택, DC 튜닝 요구 |
| DC / Detection & Coverage | 무엇을 탐지할 수 있는가? | Rule/Telemetry/시험 연결표 | PH 누락 원인, HT 검증 검색 |
| PH / Data & Pipeline Health | 데이터가 없는 이유는? | Source/Stage 상태와 실패/지연 | DC 영향 규칙, 운영 인계 |

상세 패널 계약과 ASCII 배치는 [Wireframes](dashboard_wireframes.md), 조사 절차는 [Workflow](analyst_workflow.md)를 따른다. 6개를 모두 독립적인 신규 웹 애플리케이션으로 개발한다는 의미는 아니다.

## 6. 우선순위와 Alert Fatigue

- Severity는 규칙이 판단한 신호의 수준, Priority는 해당 업무를 먼저 처리할 이유다. 두 값을 구분한다.
- MVP 기본 정렬은 `priority 등급 -> queue_entered_at 오래된 순 -> ID`이며 담당자가 변경하면 이유/작성자/시각을 기록한다. 업무 큐 등록 시각은 보안 활동의 first_seen과 다르다. 중요 자산/지속 활동/근거 부족은 설명 배지로 제공한다.
- 자산 중요도가 미등록이면 `UNKNOWN`, risk engine이 없으면 점수를 표시하지 않는다. 임의의 0~100 점수를 만들지 않는다.
- 동일 수집 이벤트의 재전송 제거, 동일 탐지의 중복 생성 방지, 알림 억제, 사건 묶기는 서로 다른 작업이다.
- Suppression에는 적용 범위/만료/관리자/이유와 억제된 수가 필요하다. 원본 삭제나 자동 정상 판정으로 구현하지 않는다.
- 동일 공인 IP만으로 여러 Host/계정을 하나의 공격자로 확정하지 않는다. 자동 grouping은 검증된 키/기간/관계가 있을 때만 후속 도입한다.
- Alert count 감소만으로 품질 향상을 주장하지 않는다. 누락·오탐·benign·unknown과 분석 소요를 함께 평가한다.

## 7. 목표 기능과 MVP 분류

분류는 이번 문서 작업의 실행 지시가 아니라 향후 구현 제안이다.

| 기능 | 목표 제품 | MVP 등급/범위 |
| --- | --- | --- |
| 두 보안 도메인의 신뢰할 수 있는 수집 | 다중 클라우드/Endpoint/Network/Web | MUST: 제어면 Audit + workload 인증, 실제 수집은 승인 후 |
| Source Registry / lineage / 재처리 | 소스별 계약/보존/품질/실패 격리 | MUST: ID, UTC 시각, 원본 참조, durable 진행 상태 |
| Detection | single/threshold/sequence/correlation/rare/risk | MUST: single event와 grouped threshold, 실행 이력 |
| Alert | 이유/버전/Entity/근거/일치 수 | MUST: 원본까지 연결, UNKNOWN 표시 |
| Incident | 자동/수동 correlation 및 사건 관리 | MUST: 수동 생성/연결/해제, 사건별 상태/담당/판정/메모 |
| Investigation | 통합 조사 및 재현 가능한 증거 | MUST: 이유->근거->전후 이벤트->판단 흐름 |
| Mission Control | SLA/우선순위/역할별 큐 | MUST: 열린 사건과 미분류 경보, 실제 상태만 표시 |
| Entity | Host/Account/IP/Cloud/Service/Process/App | MUST: Host, Account, IP, Cloud Account/Resource의 최소 프로필; 안정 키 없는 관측은 미해결로 |
| Hunting | 가설/협업/Hunt lifecycle | MUST: Discover 재사용, 쿼리/기간/결과를 사건 메모에 보존; SHOULD: 독립 Saved Hunt |
| Coverage | Technique/Analytic/Data/Rule/시험 연결 | MUST: 작은 검증표; COULD: Matrix 시각화 |
| Health | 모든 Stage/소스와 독립 감시 | MUST: 6상태 판정 계약, 측정 가능 지표/마지막 성공/오류; SHOULD: 외부 watchdog |
| Sequence | 순서/지연/상태 복원 | SHOULD: 안정 키가 확보된 한 가지 다단계 사례 |
| 3~4번째 Source | Network/Endpoint/Web 등 | SHOULD: Linux Audit, COULD: VCN Flow. 둘 다 필수 아님 |
| 관계 그래프/자산 인벤토리 자동화 | 시간 기반 관계/풍부한 Context | COULD. 표와 수동 중요도 등록으로 시작 |
| SOAR / UEBA / ML / Threat Intel 자동 상관 | 승인 통제된 자동화/통계 모델 | OUT OF SCOPE: 졸업작품 첫 MVP |
| 대규모 멀티테넌트/HA/EDR/취약점 스캐너 | 별도 장기 제품 기능 | OUT OF SCOPE. 모델 scope만 예약 |

## 8. 기능 수용 기준

| ID | 성공 기준 | 확인 방법 |
| --- | --- | --- |
| AC-01 | 인증과 Cloud API 활동을 같은 공통 시간/Entity 계약으로 검색 | 승인된 실제 시험 이벤트와 원본 비교 |
| AC-02 | 새 Alert는 rule version/reason/matched refs를 제공 | 검토자가 각 근거에서 Raw를 열고 일치 수를 재계산 |
| AC-03 | Incident 생성/할당/연결/판단/종료 이력이 재시작 후 유지 | 두 분석 세션과 충돌 저장 시험 |
| AC-04 | 과거의 열린 사건이 기본 최근 시간 필터 때문에 사라지지 않음 | 24시간보다 오래된 미종결 업무를 큐에서 확인 |
| AC-05 | 경보 없는 정상 실행/소스 IDLE/측정 UNKNOWN/실패 구별 | 승인된 장애/복구 시험에서 실제 관측 값 확인 |
| AC-06 | Hunt 결과를 사건 근거에 연결하고 시간/쿼리를 재현 | 쿼리와 채택/반증 근거를 다른 분석자가 재검토 |
| AC-07 | Coverage는 소스 미구성·규칙 미구현·시험 미수행을 숨기지 않음 | 표시 값과 Registry/Rule/검증 기록 대조 |
| AC-08 | 재전송/재시작으로 경보가 무한 중복되지 않음 | 중단/재개, 지연 도착, 10,000건 초과 범위 시험 |
| AC-09 | 권한 밖 원본/사건 접근과 변경을 차단 | 읽기/분석/운영 역할의 권한 시험 |

UX 평가 제안: 동일한 공개/승인된 실습 로그로 과거 집계 화면과 새 workflow를 비교해 업무 완료율, 근거 정확성, 조사 시간, 클릭/컨텍스트 유실을 기록한다. 작은 학생 표본은 일반 SOC 효과로 주장하지 않는다. 실제 수집 전 숫자를 채우거나 가짜 경보로 성공 기준을 통과시키지 않는다.

## 9. 비기능 요구와 Non-goals

- UTC 원본 시각을 보존하고 화면 TZ를 명시한다. 발생/수집/탐지/업무 시각을 섞지 않는다.
- 데이터/화면 부분 실패를 정상 0건으로 치환하지 않는다. 오래된 결과에는 조회 시각과 stale 표시를 붙인다.
- HTML/명령문이 포함된 로그는 비신뢰 텍스트로 처리한다. 원본에 링크/명령이 있다고 실행하지 않는다.
- 업무 쓰기는 사용자 인증/권한/감사와 일관성 제어가 선행 조건이다. 외부 공개 및 무인 차단은 이번 범위가 아니다.
- 법적 증거보전 인증, 규제 준수 인증, 실시간 전체 클라우드 보호, SOC 인력 대체를 주장하지 않는다.
- 구현 일정/팀 역량/비용을 아직 모르므로 날짜를 확정하지 않는다. 두 소스만으로도 수직 workflow를 완성하는 것이 우선이다.

관련 문서: [Architecture](siem_architecture.md), [Telemetry](data_source_matrix.md), [Detection](detection_coverage.md), [Roadmap 및 미결정 사항](implementation_roadmap_v2.md).

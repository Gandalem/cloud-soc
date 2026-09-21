# Cloud SOC Target and MVP Architecture

2026-09-10 / 제안 v2. 이 문서는 모델/경계/처리 계약 설계다. DB, API, 인덱스, 매핑, 라이브 대시보드를 생성하지 않았다. [제품 요구사항](siem_product_requirements.md)이 우선하며 현재 코드 대조는 [로드맵](implementation_roadmap_v2.md)에 구분한다.

## 1. Target Architecture

```text
Identity | Cloud Control Plane | Network | Web/App | Host/Endpoint
                              |
                     Collection / Ingestion
                  adapters, durable buffer, source registry
                              |
                    Raw Event Store + provenance
                              |
                Parsing / Normalization / quarantine
                              |
                    Normalized Event Store
                              |
                Context / Enrichment <---- Asset/Identity/CTI
                              |
                 Detection / Correlation engines
                     |                    |
                 run history         Detection matches
                                          |
                                  Alert + evidence refs
                                          |
                           manual/automatic association
                                          |
                                Incident / Case workflow
                                          |
                         Investigation / Evidence review
                                          |
                         Response plan / approval / history

Cross-cutting:
  Search/Hunting | Entity context | Data/Pipeline Health
  Detection Coverage | Analyst Audit | Access/Retention policies
```

Search/Health는 Alert가 만들어져야 접근할 수 있는 마지막 단계가 아니다. 정상 이벤트, 파싱 실패, 미탐지 활동도 각 권한 범위에서 조사한다. Detection feedback은 규칙 검토로 돌아가되 사건 종료가 자동 규칙 비활성화를 뜻하지 않는다.

근거와 해석: QRadar의 수집/처리/Console 구분, Google의 Raw/UDM 구분, Sentinel/Elastic의 업무 객체 분리, NIST의 수명 관리 원칙을 적용한 자체 구조다. 특정 공급자의 물리 아키텍처를 복제하지 않는다. [조사 E2/G1/M2/Q1/N1](siem_reference_research.md).

## 2. MVP Architecture

```text
Cloud API Audit adapter --------+
Workload authentication agent --+--> ES Raw indices (source-scoped)
optional auditd / flow ---------+          |
                                Python parser / normalizer
                                          |
                               ES normalized-events (versioned)
                                          |
                              Single + Grouped Threshold
                                          |
                              ES security-alerts + refs
                                          |
Browser -- authenticated thin SOC API -----+--- read-only ES search
                      |
              Transactional workflow store
            Incident / links / status / notes / audit
                      |
                Source/Rule registry and run status

Kibana Discover: existing event search, saved query/session reuse
Kibana dashboards: read-only overview and optional health trends
Thin SOC UI: only workflow/Workbench missing from existing tools
```

추천은 **모듈형 단일 서비스**다. Kafka, Kubernetes, Graph DB, 별도 ML 플랫폼은 MVP 선행 조건이 아니다. durable buffer/checkpoint/retry라는 책임은 필요하지만 특정 메시지 브로커 설치를 필수화하지 않는다.

Workflow Store 선택은 미확정이다. 단일 인스턴스 학생 실습이면 SQLite 같은 트랜잭션 저장소, 다중 프로세스/여러 분석가의 실제 동시 작업이면 PostgreSQL 같은 서버 DB를 검토한다. 외부 조사만으로 Framework/DB를 임의 확정하지 않는다. ES에 업무를 저장하는 대안도 있지만 여러 문서의 원자성/변경 이력/충돌 처리를 별도 설계해야 한다.

**네이티브 Elastic Security 재사용 대안:** Cases/Timeline이 요구를 충족하고 스키마·권한·라이선스 통합이 검증되면 얇은 자체 UI를 줄일 수 있다. 커스텀 `security-alerts`와 네이티브 보안 Alert 객체의 호환을 가정하지 않는다. 이 선택은 Phase A의 검증/승인 대상이다.

## 3. 계층별 책임

| 계층 | 입력/출력 | 보장해야 하는 것 | 실패 시 |
| --- | --- | --- | --- |
| Collector | Source record -> Raw envelope | 출처, stable identity, 수집 시각, 재시도/범위 | 실패/마지막 성공/유실 가능성 기록 |
| Parser | Raw -> parsed or rejected | 형식/시간 파싱 결과와 parser version | 원본 유지, rejection reason |
| Normalizer | parsed -> normalized | 공통 타입/의미, lineage, schema version | quarantine, 잘못된 필드로 탐지 금지 |
| Enrichment | event + inventory -> context refs | 출처/유효 시각/불확실성 | enrichment unavailable, 이벤트 버리지 않음 |
| Detector | normalized + rule -> run/matches | rule snapshot, 입력 범위, 일치 기준 | 성공 0과 실패/부분 실행 구분 |
| Alert | match -> signal | dedup, immutable reason/evidence | 재시도 가능, 쓰기 실패 후 checkpoint 금지 |
| Incident | links + analyst actions -> work item | 상태/담당/판정/이력의 일관성 | optimistic conflict, 조용한 덮어쓰기 금지 |
| Search/UI | authorized query -> paged results | 범위/TZ/정렬/권한/partial 표시 | error, stale, retry; 0 대체 금지 |

## 4. 데이터 모델 계약

표의 필드는 논리 계약이다. ECS 표준이라고 선언하지 않은 업무/확장 필드는 `cloud_soc.*` 또는 별도 업무 DB 모델로 둔다. ECS와 다른 의미를 같은 필드에 넣지 않는다.

### 4.1 Event, Detection, Alert

| 객체 | 필수 필드/관계 | 핵심 불변 조건 |
| --- | --- | --- |
| Raw envelope | `raw_id`, `scope_id`, `source_id`, `source_event_id/record_locator`, original payload, `received_at`, `payload_hash`, content type, encoding | 원본 payload 불변. 동일한 텍스트만으로 서로 다른 실제 이벤트를 중복 제거하지 않음 |
| Normalized Event | `event.id`, `@timestamp`, `event.created`, `event.ingested`, `event.kind/category/type/action/outcome`, `event.dataset`, source/host/user/cloud fields, `cloud_soc.raw_ref`, schema/parser versions | 발생 시각 부재/추정은 time_quality로 표시. 필요 필드 결측은 null/quality issue |
| DetectionRun | `run_id`, `rule_id/version/hash`, planned/actual range, started/finished, input/match/alert/suppressed counts, checkpoint, status/error | SUCCESS/PARTIAL/FAILED를 구분. 처리 범위와 실제 종료 watermark가 있어야 함 |
| DetectionMatch | rule/run, grouping key, event refs, observed count, threshold/window, matched time | Alert가 억제돼도 일치/억제 통계를 추적 가능 |
| Alert | `alert_id`, scope, severity, reason, rule snapshot, `detected_at`, first/last event time, entity refs, evidence set, match_count, `dedup_key`, quality flags | 탐지 사실은 불변. 업무 상태는 별도 AlertReview/Incident에 저장 |
| AlertReview | alert_id, status, owner, verdict, rationale, registered_at, version, audit refs | `new/in_review/linked/closed`. `linked`는 실제 사건 링크를 의미 |

`event.created`는 에이전트/파이프라인이 이벤트를 처음 읽은 시각, `event.ingested`는 중앙 이벤트 저장 시각으로 계약한다. 특정 Collector가 이를 제공하지 않으면 `received_at`만 기록하고 결측을 인정한다. 파서 추정 시각을 실제 제공된 타임스탬프로 표시하지 않는다. [ECS Event fields](https://www.elastic.co/docs/reference/ecs/ecs-event), 확인일 2026-09-10. Normalized에는 동일 원본의 첫 중앙 수신 시각을 보존하고 정규화 처리 시각은 별도 기록한다.

### 4.2 Incident와 업무 기록

| 객체 | 필수 내용 | 정책 |
| --- | --- | --- |
| Incident | incident_id, scope, title, description, category, priority, priority_reason, status, owner, created/updated/closed, activity first/last, verdict, version | 사건 업무 시각과 보안 이벤트 시각 분리 |
| IncidentAlertLink | incident_id, alert_id, active, linked_by/at, reason, unlinked_by/at | Target 다대다; MVP는 Alert당 활성 사건 1개, 이력상 재연결 허용 |
| IncidentEvidenceLink | incident_id, evidence_id, relevance, supports/refutes/context | 채택 이유 없는 자동 증거 확정 금지 |
| AnalystNote | note_id, author, created_at, body, revision refs, related object | 수정은 새 revision, 로그 원문 수정 금지 |
| AnalystAudit | action_id, actor, role, object, action, before/after, server_time, request_id | 업무 변경과 같은 트랜잭션. 임의 삭제 API 없음 |
| ResponseRecord | recommended action, approver, target, executed_by, result, verification | 계획/승인/실행/성공/복구 확인은 별개. MVP는 수동 조치 기록 |

Incident 상태는 `new -> investigating -> escalated 또는 closed`; escalated는 미종결이며 인계가 끝나면 investigating으로 돌아올 수 있다. 재개는 이유와 이력 필수. Closed는 `malicious / benign / false_positive / inconclusive` 중 판정과 rationale을 요구한다. `inconclusive` 종료는 데이터 부족 등 사유와 책임자 확인을 요구하며 운영 정책 승인 대상이다.

MVP에서 Case/Incident 두 저장소를 중복 개발하지 않는다. 향후 범용 Case가 필요하면 Incident의 workflow 메타데이터를 공통 case model로 승격할 수 있다. 사건 종료로 연결 Alert 전체를 자동 종결하지 않고 선택/결과를 기록한다.

`linked` AlertReview와 실제 활성 IncidentAlertLink는 같은 트랜잭션으로 변경한다. 마지막 링크를 해제할 때 담당/사유를 확인하고 `in_review`로 되돌려 미분류 업무에서 누락되지 않게 한다. 닫힌 Incident에 붙은 경보 중 미판정 review는 별도 `검토 미완료` 보기를 제공한다. 사건 종료가 각 경보 판정의 자동 복제를 의미하지 않는다. closed AlertReview의 연결 변경은 명시적 재개/검토 이력을 요구한다.

### 4.3 Evidence 모델

| 객체 | 내용 | 불변/조회 조건 |
| --- | --- | --- |
| EvidenceRecord | evidence_id, scope, Raw/Normalized의 정확한 저장 위치/ID/버전, 원본 hash 알고리즘/값, parser/schema, source, observed/captured time, 보존 예정, availability | 원본 관측과 파생 내용을 분리. 권한 확인 후 참조 조회. hash는 진본성 인증이 아님 |
| EvidenceManifest | manifest_id, rule/run/alert refs, ordered evidence refs, match_count, retained_ref_count, complete/truncated, window/stage | 탐지 당시 집합/순서를 보존. 큰 집합은 외부 페이지로 나누되 모든 참조와 완전성 상태를 유지 |
| Investigation annotation | evidence_id, incident/alert review, supports/refutes/context, rationale, author/time, revision | 분석가의 해석이며 Raw 수정 아님. 같은 근거에 여러 해석 가능 |

MVP의 신규 경보는 정확한 일치 참조 집합을 보존하는 것이 원칙이다. 저장 상한/실패로 불완전하면 `complete=false`와 실제 보존 수/이유를 표시하고 완전한 근거 검증 기준을 통과한 것으로 판정하지 않는다. 원본이 만료돼도 참조/만료 사실을 보존하고 검색 결과로 몰래 교체하지 않는다.

### 4.3 Evidence

`evidence_id`, scope, origin type, Raw/Normalized locator, original hash, observed_at, captured_at, captured_by, parser/schema version, retention_until, availability, selection_reason, relation to alert/incident.

- 탐지 근거는 재검색 쿼리만이 아니라 **당시 일치한 문서 ID 집합**을 보존한다. 큰 집합은 manifest + paged refs로 분리한다.
- ES `_index`/`_id` 참조에는 namespace/scope와 보존 정책이 필요하다. 리인덱싱/삭제 후 깨질 수 있으므로 stable logical ID와 버전 대응을 둔다.
- `available`, `expired`, `missing`, `forbidden`, `unverified`를 구분한다. 근거가 없으면 같은 IP 주변 로그를 원래 근거로 몰래 대체하지 않는다.
- 원본 hash는 변경 탐지 수단이지 출처 진위/법적 chain of custody의 완전 보장이 아니다. 권한·수집 경로·보존/접근 감사가 함께 필요하다.
- 로그 안의 비밀번호/토큰/개인정보를 노출하지 않도록 표시/다운로드 권한을 나눈다. 원본 보존과 화면 redaction은 다른 계층이다.

## 5. Entity와 안정적인 Key

공통: `entity_id`, `scope_id`, type, stable_key, aliases, key_quality, source_of_truth, first/last_seen, valid_from/to, criticality+source. 기본 키는 `scope + type + issuer/native identity`다. 해시로 저장하더라도 충돌 회피용 원래 구성과 버전을 유지한다.

| Entity | 권장 안정 Key / 범위 | 주의 | MVP |
| --- | --- | --- | --- |
| Host | tenant + cloud instance ID 또는 자산 inventory ID | host.name은 alias. agent.id도 재설치/복제 고려 | MUST |
| User / Account | tenant + identity issuer/domain + immutable account ID | Linux local UID는 Host 범위/계정 재생성 epoch 포함. username만 있으면 unresolved observable | MUST |
| IP Address | scope + address realm/network + canonical IP + 시간 관계 | Source/Destination은 **역할**이지 서로 다른 종류의 사람/자산 아님. NAT/DHCP로 Host와 1:1 불가 | MUST |
| Cloud Account | provider + tenant/account OCID/ID | IAM principal과 tenancy는 다른 객체 | MUST |
| Cloud Resource | provider + tenant + resource native ID | region/type 별도, 이름 변경 가능 | MUST |
| Service | scope + service namespace + service ID + deployment | port 22만으로 특정 서비스 인스턴스 확정 금지 | SHOULD |
| Process | Host stable ID + boot/session scope + PID + start time | PID 재사용, auth.log의 sshd PID만으로 process tree 불가 | COULD |
| Application | scope + app registration/service catalog ID | URL/path를 애플리케이션 ID로 자동 사용하지 않음 | COULD |

Source IP와 Destination IP는 이벤트의 역할로 모두 제공한다. 내부 사설 IP는 네트워크/tenant 경계 없이는 병합하지 않는다. Account와 사람은 별도이며 HR 연동이 없으면 사람 프로필을 만들지 않는다.

관계는 `edge_id, from/to, relation, observed/source refs, valid interval, confidence/quality`를 가진다. `logged_into`, `ran_on`, `accessed`, `member_of` 같은 관계를 추측과 관측으로 구분한다. 불확실한 링크로 Incident를 자동 병합하지 않는다.

## 6. 신뢰할 수 있는 처리/재처리

1. Raw 재전송 ID는 source native event ID 또는 파일 identity/rotation epoch/offset 등 수집 위치로 만든다. payload hash 하나로 다른 시각의 동일 문자열을 합치지 않는다.
2. Raw 저장 확인 후 수집 checkpoint를 전진시킨다. 파싱 실패도 보존하고 실패 상태를 기록한다.
3. 정규화는 `(raw_id, parser_version, schema_version)`으로 버전을 구분한다. 활성 버전을 선택하며 과거 근거가 가리킨 버전을 지우지 않는다.
4. Detector는 순회 가능한 stable sort와 페이지 cursor, durable watermark를 사용한다. 사건 시각으로만 이어 읽으면 늦게 도착한 이벤트를 놓칠 수 있다.
5. 처리 진행은 ingest/sequence 기준, 탐지 시간창은 event time 기준으로 분리한다. lookback/허용 지연/재평가 범위와 지연 초과 처리 정책을 규칙마다 명시한다.
6. `(scope, rule version, grouping key, evidence/window identity)` 기반 dedup 정책을 테스트한다. 임계값 도달 뒤 cooldown 내 추가 근거의 보존/억제 집계 정책을 정의한다.
7. 처리/Alert 저장/상태 전진의 순서와 crash recovery를 시험한다. 정확히 한 번 전달을 근거 없이 보장하지 않고 **at-least-once + idempotent 효과**를 목표로 한다.
8. backfill/replay는 live와 다른 run_mode와 알림 정책을 쓴다. 오래된 데이터를 현재 공격처럼 새 실시간 incident로 노출하지 않는다.

위 방식의 구체 Elasticsearch API와 성능은 구현 전 공식 문서/현재 버전으로 검증한다. 이번에는 API를 추가하거나 실행하지 않는다.

## 7. Search와 화면 계약

QueryContext: scope, selected sources/datasets, from/to UTC, timezone, entity stable keys/roles, structured filters, query language/text, sort/cursor, incident_id, evidence selection. 필터 표현은 URL에 안전하게 인코딩하고 서버에서 scope/권한을 다시 검사한다.

- 원본/정규화 검색은 Data View를 명시한다. Kibana KQL과 Sentinel Kusto KQL은 서로 다른 언어이며 동일 쿼리를 교환하지 않는다.
- 목록은 서버 pagination을 사용한다. 전체 일치 수/표시 수/상한/approximate 여부를 구분한다.
- Mission Control의 열린 업무는 기본적으로 생성 날짜 제한 없이 조회한다. 추이만 최근 24시간으로 시작한다.
- 조사 Timeline은 관련 이벤트 earliest/latest에 전후 30분을 더한 범위로 시작하고 확장한다. 이 값은 UI 기본값 제안이지 탐지 규칙 시간창이 아니다.
- 실제 존재하는 근거의 exact ref 조회와 관련 활동 검색 결과를 분리한다. 후자는 새 근거로 채택하기 전까지 context다.
- API 부분 실패, 권한 오류, 만료된 자료를 사용자에게 구분한다. 미등록/미지원 Entity도 클릭 결과에서 설명한다.

Queue read model의 `queue_entered_at`은 Incident.created_at 또는 AlertReview.registered_at이며 이벤트의 activity first_seen이 아니다. 재개 시 최초 등록/이전 이력은 보존하고 reopened_at을 별도 제공한다. 과거 Alert를 나중에 등록하면 legacy/import 배지를 표시한다. 기존 데이터의 알려지지 않은 최초 탐지 시각을 등록 시각으로 위장하지 않는다.

priority 정렬은 `critical -> high -> medium -> low -> informational -> unknown`의 명시적 등급 순서다. 미분류 Alert 탭은 rule severity를 초기 priority로 사용하고 출처를 표시한다. 대기 Age는 등록 후 경과 시간이며 실제 조사에 쓴 시간/최초 응답 SLA와 다르다.

업무 상태/담당과 Incident 관련 메타데이터는 workflow store를 단일 원본으로 삼는다. **ES의 한 페이지를 읽은 뒤 상태 필터를 적용하면 안 된다.** 작은 MVP에서는 ES의 완전한 후보 집합과 일관된 업무 DB 읽기를 결합해 필터/정렬/합계/페이지를 계산하고 응답 시점/한도를 표시한다. 상한/시간 초과는 partial/error이지 정확한 전체 합계가 아니다. 규모가 커지면 검색용 projection/read model을 설계하되 원본 상태/동기화 지연/재조정 정책을 명시한다. ES와 업무 DB 사이 전역 원자 스냅샷이 있는 것으로 주장하지 않는다.

Alert 저장과 업무 등록은 서로 다른 저장소이므로 원자성을 가정하지 않는다. 멱등 등록과 주기적 누락 재조정이 필요하다. 새 Alert가 review 미등록이면 등록 대기 목록/불완전 카운트를 표시하고 닫힌 경보를 자동 new로 되돌리지 않는다.

## 8. Health 상태 계약

Source Registry: source_id/scope/domain, expected behavior `continuous/sparse/batch`, schedule, expected lateness, collector ID, monitored stages, expected_enabled, owner, thresholds, last configuration change. 로그를 한 번 본 것만으로 소스 목록을 만들지 않는다.

각 Stage 관측: last_probe/success/error, heartbeat, poll range/completion, input/output/rejected/skipped counts, backlog, received lag, detector watermark, run duration. 상태와 `status_reason`, `evaluated_at`, `observed_at`를 함께 저장한다.

| 상태 | 필요 근거 | 금지하는 추론 |
| --- | --- | --- |
| NOT CONFIGURED | Registry에서 미설정/의도적 비활성 | 장애로 계산하지 않음 |
| UNKNOWN | 미계측, 오래된 측정, 접근 불가, 판정 조건 미설정 | 로그 없음만으로 DOWN 또는 HEALTHY 금지 |
| DOWN | 신선한 명시적 실패 또는 독립 감시의 실패 확인 | 무활동을 장애로 단정 금지 |
| DELAYED | 신선한 관측에서 backlog/워터마크 지연/처리 지연이 정책 초과 | 오래된 이벤트 시각만으로 판정 금지 |
| IDLE | heartbeat/poll 성공, backlog 없음, 무활동이 소스 계약상 허용 | 실패한 poll의 0건을 IDLE로 표시 금지 |
| HEALTHY | 관측 신선, 필수 Stage 성공, 데이터 전달/처리 범위 정상 | 보안상 안전/공격 없음의 동의어 아님 |

평가 순서: 설정 여부 -> 관측 신선도 -> 확인된 실패 -> 지연 -> 허용된 무활동 -> 정상. Stage별 상태를 보존하며 종합 상태만으로 어느 단계의 원인인지 숨기지 않는다. 데이터 일부가 처리되지만 파싱 reject가 발생하면 reason/quality 경고를 별도 표시한다. 설정된 허용치 초과로 필수 처리 실패가 확인되면 해당 Stage는 DOWN, 계측 불충분이면 UNKNOWN이다.

Source가 sparse면 `last event 오래됨` 대신 **마지막 성공 poll과 완료 범위**를 본다. Cloud Audit에는 공급자 전달 지연도 있으므로 source time, provider available time, local received time을 가능할 때 분리한다. 전체 앱/ES가 죽으면 자체 Health 화면도 죽으므로 외부 watchdog 없이 그 가용성을 보증할 수 없다.

## 9. 보안/보존/운영 경계

- 수집 자격 증명은 read-only 최소 권한, UI는 수집 키를 받지 않는다. DB/ES 자격 증명을 브라우저에 두지 않는다.
- 인증/역할/서버 scope 검사, 감사, TLS 또는 보호된 개발 연결을 업무 쓰기 기능의 선행 조건으로 둔다.
- 원본/normalized/alert/업무/audit의 보존은 별도 정책이다. 사건 링크가 있는 원본의 만료 전에 경고하고 승인된 보존 예외 또는 명시적 만료 상태를 처리한다.
- 최대 저장량은 `EPS * 평균 bytes * 보존초 * 복제/색인/파생데이터 계수`로 추정 후 실측한다. 복제/압축비를 확정 수치로 가정하지 않는다.
- 무결성 hash, 앱 수준 append-only audit, 백업은 운영자 권한 탈취에 대한 완전 방어가 아니다. WORM/서명/외부 감사 저장은 장기 확장이다.
- 사유 없이 자동 차단/계정 잠금/클라우드 정책 변경을 하지 않는다. 대응 기록과 실제 대응 API는 다른 capability다.

현재 구현의 위치와 수정/추가 파일 후보는 [Gap Analysis](implementation_roadmap_v2.md)에 기록한다. 목표 계층을 현재 코드 부족을 이유로 삭제하지 않는다.

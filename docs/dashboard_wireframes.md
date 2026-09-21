# Cloud SOC Workspace Wireframes and Panel Contracts

2026-09-10 / 목표 UX 제안. **ASCII 설계이며 실제 Kibana Dashboard를 수정한 결과가 아니다.** 수치/행은 배치 설명용 필드 이름이고 가짜 사건/경보 데이터가 아니다.

## 1. 공통 화면/데이터 계약

- 6개 Workspace는 하나의 탐색 메뉴에서 연결한다. MC=Mission Control, IW=Workbench, EN=Entity, HT=Hunting, DC=Coverage, PH=Health.
- 1440px 내외 데스크톱을 기준으로 상대 면적을 제안한다. Queue/근거가 중심이며 좁은 화면에서는 요약->업무/근거->문맥 순서로 세로 배치한다. 넓은 표는 숨겨진 열 표시/열 선택과 가로 스크롤을 제공한다.
- 그래프/수치보다 Table, Timeline, Status, 명시적인 필터를 우선한다. 장식 지도/Gauge/대형 Donut/가짜 실시간 애니메이션/출처 없는 점수는 제외한다.
- 선택한 scope는 서버 권한으로 강제한다. 기간은 UTC 저장, 화면 TZ 표시. 날짜와 clock quality가 불명확하면 경고한다.
- `E0`: 정상 조회가 성공했지만 일치 자료 없음. `N0`: 소스/기능 미구성. `R0`: 조회 실패, 권한 오류, 시간 초과. R0를 0으로 바꾸지 않으며 재시도/마지막 성공 시각/stale 표시를 제공한다.
- 표는 pagination, total/표시 수/상한/근사 여부를 구분한다. 부분 결과는 partial 배지와 누락 범위를 표시한다.
- 모든 pivot은 QueryContext(scope, 시간/TZ, Entity key, source, query, 사건 ID)를 보존한다. evidence exact ref 조회는 외부 시간 필터와 별개다.
- 작업 저장은 성공 응답 후 반영한다. 충돌/권한 오류가 나면 입력을 유지하고 다시 확인하게 한다.
- 각 패널은 아래 계약을 따른다. 공통 탐색/필터는 패널이 아닌 페이지 chrome이다. `현재` 가능 여부는 문서 마지막의 저장소 대조 표에서 Panel ID별로 판정한다.

## 2. SOC Mission Control

질문: 지금 무엇부터 처리해야 하는가? 메인 화면은 Incident 큐이며 미분류 Alert를 별도 탭으로 남긴다.

```text
+------------------------------------------------------------------+
| MC  Scope | My work / Unassigned | Priority | Status | Owner | TZ  |
+------------------------------------------------------------------+
| MC-H: DATA CONFIDENCE / LAST CHECK / AFFECTED SOURCES               |
+------------------------------------------------------------------+
| MC-K: Open | Critical/High | New | Investigating | Unassigned       |
+------------------------------------------------------------------+
| MC-Q: [INCIDENTS] [UNTRIAGED ALERTS]  | Claim | Open | Saved view   |
| Priority | Incident / Reason | Status | Entities | Owner | Age     |
|                                                                  |
|                    MAIN ANALYST QUEUE                            |
|                                                                  |
| Total / displayed / cursor / no date limit for open work          |
+--------------------------------------+---------------------------+
| MC-T: Incident created trend         | Categories / detections    |
| Optional context, not the work list  | Click to filter            |
+--------------------------------------+---------------------------+
```

상대 면적: 탐색/필터 10%, Health 5%, KPI 10%, Queue 60%, 추이 15%. KPI 수를 늘리기 위해 Queue를 아래로 밀지 않는다.

### MC-H: Data Confidence

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 조사 전 데이터 가용성 확인 / 경보 없음의 의미를 오해하지 않기 위해 |
| 표현 / 표시 필드 | 얇은 Status strip / state, reason, affected source count, evaluated_at |
| 집계 / 정렬 | scope 내 Source Registry별 상태 count / DOWN, DELAYED, UNKNOWN 먼저 |
| 기간 / 필터 | 현재 평가값, 최근 15분 관측 보기 / scope, source domain |
| 클릭 / Drill-down | 상태/소스 선택 / PH-S, 해당 소스 영향 Rule |
| Empty / Error | Registry 없음=N0, 측정 없음=UNKNOWN / R0, HEALTHY 치환 금지 |
| Log Source / Normalized Field / Detection | DS-15 + Registry / source_id, stage, heartbeat/poll/result/time / 보안 탐지 불필요 |
| MVP | MUST: 신뢰도 경고, 측정 없는 초기 환경은 UNKNOWN |

### MC-K: Work Counters

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 실제 미처리 업무 분포 / 무엇을 인수할지 결정 |
| 표현 / 표시 필드 | compact 숫자/클릭 필터 / incident_id, priority, status, owner |
| 집계 / 정렬 | 열린 Incident distinct count, high/critical/new/investigating/unassigned / 고정 순서, 중복되는 KPI를 합산하지 않음 |
| 기간 / 필터 | **미종결 전체 기간** / scope, priority, status, owner; 선택 필터의 영향 표시 |
| 클릭 / Drill-down | KPI 조건으로 MC-Q Incident 탭 좁힘 / 같은 페이지 |
| Empty / Error | 성공 0은 0, Incident 미구현=N0 / R0, Alert 수를 대신 표시 금지 |
| Log Source / Normalized Field / Detection | Workflow DB, 연결 Alert / incident.status/priority/owner/id / 직접 탐지 불필요 |
| MVP | MUST: 실제 workflow 데이터 확보 후 |

### MC-Q: Analyst Queue

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 인수/우선 처리 대상을 선택 / Queue가 업무의 시작점 |
| 표현 / 표시 필드 | Table, Incident/Untriaged Alert 탭 / ID,title,priority+reason,status,entity summary,ATT&CK(등록 시),owner,queue_entered_at,activity first_seen,updated_at |
| 집계 / 정렬 | 한 행=한 Incident, Alert 탭은 한 행=한 Alert / priority 등급 순 -> queue_entered_at asc -> ID; 서버 pagination. Age는 업무 등록 후 경과 시간 |
| 기간 / 필터 | 열린 업무 기본 날짜 제한 없음; closed는 최근 7일 선택 / scope,owner,status,priority,entity,domain,rule |
| 클릭 / Drill-down | 행=IW, Entity=EN, Claim=담당 저장 / object type에 맞는 Workbench route |
| Empty / Error | 열린 업무 없음과 미분류 Alert 없음 각각 E0; 구현 안 됨=N0 / R0, 이전 목록 stale |
| Log Source / Normalized Field / Detection | Incident/AlertReview/Alert store / workflow 필드, alert.rule/entity refs / 배포 Rule 전체 또는 수동 사건 |
| MVP | MUST: Incident와 미분류 Alert 분리, 무근거 자동 사건 생성 금지 |

### MC-T: Operational Context

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 유입 증가/주요 업무 종류 파악 / 인력·튜닝 필요 판단 |
| 표현 / 표시 필드 | 작은 trend + ranked table / incident.created_at/category, alert.detected_at/rule.id |
| 집계 / 정렬 | 사건 생성 수와 경보 생성 수 별도 histogram, category top 5 / 시간 asc, category count desc |
| 기간 / 필터 | 최근 24h, 최대 7일 빠른 선택 / scope, category, rule, priority |
| 클릭 / Drill-down | 선택 구간의 생성 업무 필터를 **명시적으로** 적용 / MC-Q; 열린 전체 보기 복귀 |
| Empty / Error | 성공 0 빈 추이/E0; 업무 데이터 미구현=N0 / 개별 chart R0 |
| Log Source / Normalized Field / Detection | Incident/Alert store / created_at,detected_at,category,rule.id / 모든 활성 Rule |
| MVP | SHOULD: 큐/근거보다 후순위 |

## 3. Investigation Workbench

질문: 왜 탐지됐고, 어떤 근거이며, 전후 무엇이 있었는가? Incident/Alert 공통 껍데기를 쓰되 객체 유형을 명확히 표시한다.

```text
+------------------------------------------------------------------+
| IW-S: Incident/Alert ID | Title | Priority/Severity | Owner | State |
| Scope | Detection time vs Event time | Sources/Quality | Back      |
+-------------------------------------------+----------------------+
| IW-R: WHY / RULE VERSION / MATCHED VALUES  | IW-W: ANALYST WORK   |
| Linked Alerts / affected Entities         | Status / Owner       |
| Threshold / Window / missing context      | Verdict / Rationale  |
+-------------------------------------------+ Notes / History      |
| IW-T: EVENT TIMELINE                       | Evidence referenced  |
| [before] [detection window] [after]        | Escalate / Close     |
| Events / related activity / entity pivot | Save result / Errors |
+-------------------------------------------+                      |
| IW-E: EXACT EVIDENCE                       |                      |
| Event ID | Source | Match reason | Quality|                      |
| [Normalized] [Raw] [Provenance]            |                      |
| Hash / parser version / retained until    |                      |
+-------------------------------------------+----------------------+
```

상대 면적: 탐색/요약 10%, 이유/관련 경보 15%, Timeline 25%, Evidence 30%, 업무 기록 20%. 본문 너비 약 70%, 우측 기록 30%; 좁으면 근거 뒤에 기록을 배치한다. 원본은 접이식으로 제공하되 한 번의 명시적 클릭으로 접근한다.

### IW-S: Investigation Summary

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 조사 대상/영향 범위 식별 / 다른 사건과 혼동 방지 |
| 표현 / 표시 필드 | compact summary / object type/id/title, scope, owner,status,priority,severity,activity/detection/created time |
| 집계 / 정렬 | incident 링크 수/Entity distinct 수; Alert면 해당 객체 값 / 링크는 detected_at asc |
| 기간 / 필터 | 선택 객체 전체 수명 / linked alert, entity type; 사건 자체는 상위 기간 필터로 숨기지 않음 |
| 클릭 / Drill-down | linked Alert 선택, Entity profile / IW 해당 Alert, EN-P |
| Empty / Error | 객체 없음=404 안내; 연결 없음 명시 / 권한/조회 실패 R0 |
| Log Source / Normalized Field / Detection | Incident/Alert/Entity stores / 객체 ID,rule ref,entity ref,times / 해당 Alert의 Rule; 수동 사건은 없음 |
| MVP | MUST |

### IW-R: Detection Reason

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 어떤 조건이 충족됐는지 확인 / 제목만으로 악성 판단하지 않기 위해 |
| 표현 / 표시 필드 | Rule snapshot + 조건/실제값 표 / version,group key,count unit,match_count,threshold,configured window,evidence interval,ATT&CK |
| 집계 / 정렬 | Alert별 원래 탐지 값, 여러 Alert 합산 금지 / detected_at asc 또는 선택 Alert |
| 기간 / 필터 | 당시 탐지 창 고정 / linked alert, rule, match stage |
| 클릭 / Drill-down | Rule definition, 근거 집합 선택 / DC-R, IW-E |
| Empty / Error | 이유/버전 없음=legacy incomplete, 추측 생성 금지 / Rule 조회 R0와 보존 snapshot 분리 |
| Log Source / Normalized Field / Detection | Alert/Rule/DetectionRun / action,outcome,rule/version,group fields,event refs / single/threshold/sequence 등의 원래 유형 |
| MVP | MUST: 새 경보부터 완전한 계약 |

### IW-T: Event Timeline

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 탐지 전후 활동과 빈 구간 확인 / 공격 성공·후속 행동 검토 |
| 표현 / 표시 필드 | timestamp-ordered event table + 작고 선택 가능한 histogram / time,dataset,host/account/resource,action,outcome,relation,evidence ID |
| 집계 / 정렬 | event ID별 행, histogram event count / @timestamp asc -> event.id |
| 기간 / 필터 | earliest~latest evidence에 전후30분, 확장 가능 / entity,source,action,outcome,matched vs related |
| 클릭 / Drill-down | 이벤트=IW-E, Entity=EN, 범위 확장 검색=HT / QueryContext 보존 |
| Empty / Error | 해당 범위 E0와 Source 미구성 분리 / partial/timeout R0와 누락 source 표시 |
| Log Source / Normalized Field / Detection | 허용된 전체 normalized + Raw refs / @timestamp,event.id,dataset,entity keys,action/outcome / 탐지 없는 정상 이벤트도 포함 |
| MVP | MUST: Evidence vs Related 색/라벨 구분 |

### IW-E: Evidence and Raw Viewer

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 근거를 재현/반증 / 정규화 오류와 잘못된 연관을 검증 |
| 표현 / 표시 필드 | exact reference 표 + Raw/Normalized/Provenance 탭 / IDs,original,message,hash,parser/schema,match reason,retention,availability |
| 집계 / 정렬 | evidence manifest의 실제 문서/페이지 수 / event time asc -> evidence ID, 일치 수와 표시 상한 구분 |
| 기간 / 필터 | **원래 refs 전체**, 전역 기간으로 누락 금지 / evidence type,source,available/missing,supports/refutes/context |
| 클릭 / Drill-down | exact ref 열기/사건 근거 채택/원본 검토 / Raw viewer, audit; 검색 결과 대체 금지 |
| Empty / Error | no evidence/legacy missing/expired 구분 / 403,404,timeout 별도. R0를 빈 JSON으로 숨기지 않음 |
| Log Source / Normalized Field / Detection | Raw + Normalized + Evidence store / raw_ref,event.id,payload,versions / 해당 DetectionMatch의 refs, 수동 근거도 허용 |
| MVP | MUST: 원본 읽기 권한과 비신뢰 텍스트 렌더링 |

### IW-W: Analyst Decision and History

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 판단/인계/종료 기록 / 다른 분석가가 결론을 검토하기 위해 |
| 표현 / 표시 필드 | form + append/revision history / status,owner,verdict,rationale,evidence links,actor,time,version,response record |
| 집계 / 정렬 | 한 객체의 전체 action/note history / server time asc; 최신으로 이동 제공 |
| 기간 / 필터 | 사건/경보 review 전체 수명 / action type,author |
| 클릭 / Drill-down | Claim/Save/Link/Unlink/Escalate/Close/Reopen / 저장 결과, evidence 링크는 IW-E |
| Empty / Error | 아직 미판정/미배정, 기본 정탐 값 금지 / 충돌/권한/저장 실패에서 입력 유지 |
| Log Source / Normalized Field / Detection | Workflow DB/Audit / 업무 필드,version,evidence refs / 탐지 불필요 |
| MVP | MUST: 자동 차단 버튼 없음, 조치 기록만 |

## 4. Entity / Asset Investigation

```text
+------------------------------------------------------------------+
| EN  Scope | Entity type/key | Time/TZ | Source | Activity type      |
+------------------------------------------------------------------+
| EN-P: PROFILE / STABLE KEY / ALIASES / CRITICALITY / UNCERTAINTY    |
+-------------------------------------------+----------------------+
| EN-A: RELATED INCIDENTS / ALERTS           | EN-R: RELATIONSHIPS  |
|       ACTIVITY TIMELINE                    | Relation | Entity    |
| Auth / Cloud / Network / Host / Web tabs   | Time | Evidence      |
| Events | source | outcome | raw reference | Optional small graph |
+-------------------------------------------+----------------------+
```

비율: 탐색10%, 프로필20%, 관련 사건/활동50%, 관계20%. 미수집 도메인은 빈 차트가 아니라 `NOT CONFIGURED` 탭 설명을 제공한다.

### EN-P: Entity Profile

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 실제로 무엇을 식별했는지 확인 / IP와 사람, Host 이름과 자산의 혼동 방지 |
| 표현 / 표시 필드 | profile table / type,scope,stable key,aliases,source of truth,valid interval,criticality,first/last seen |
| 집계 / 정렬 | Entity 하나; alias별 유효기간 / valid_from desc |
| 기간 / 필터 | 프로필 전체 이력, 시점 선택 / alias source,entity type |
| 클릭 / Drill-down | alias/관련 native resource 선택 / EN 같은 scope, HT 정확 key 검색 |
| Empty / Error | 미해결 observable로 표시, 사람/위험 점수 발명 금지 / R0 |
| Log Source / Normalized Field / Detection | DS-13 + 관측 소스 / host.id,user.id+issuer,cloud account/resource,IP realm / 탐지 불필요 |
| MVP | MUST: Host/Account/IP/Cloud Account/Resource |

### EN-A: Related Work and Activity

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 해당 Entity의 다른 활동/업무 확인 / 조사 범위 결정 |
| 표현 / 표시 필드 | Incident/Alert table + event timeline / ID,title,status,time,dataset,action,outcome,evidence relation |
| 집계 / 정렬 | 링크된 업무 distinct ID와 exact-key 이벤트 / 업무 priority desc, event time asc |
| 기간 / 필터 | 활동 최근24h 또는 넘겨받은 범위, 열린 사건은 전체기간 배지 / source,action,outcome,domain |
| 클릭 / Drill-down | 사건/경보/이벤트 열기 / IW-S 또는 IW-E; 범위 확장=HT |
| Empty / Error | 관측 없음/미수집 별도 / 일부 source 실패 R0, 전체 없음 주장 금지 |
| Log Source / Normalized Field / Detection | Incident/Alert + 해당 도메인 소스 / stable entity refs,time,action,outcome / 탐지 필요 없음, 관련 Rule 있으면 표시 |
| MVP | MUST: 지원 두 소스만 실제 활동 표시 |

### EN-R: Related Entities

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 계정-Host-Resource 등의 연결 조사 / 오연결을 검증 |
| 표현 / 표시 필드 | relation table 기본, 그래프 선택 / from,to,relation,observed/valid time,source/evidence,key quality |
| 집계 / 정렬 | 동일 relation+기간의 evidence 수 / last_seen desc; pagination |
| 기간 / 필터 | EN-A 범위 / 관계 유형,신뢰/미해결,source |
| 클릭 / Drill-down | 이웃 Entity 또는 relation evidence 선택 / EN-P, IW-E |
| Empty / Error | 관계 미관측, 자동 관계 생성 금지 / R0; 선택 그래프 실패 시 표 유지 |
| Log Source / Normalized Field / Detection | identity/asset bindings + 관측 이벤트 / entity refs,relation,valid interval / 탐지 불필요 |
| MVP | SHOULD: 표부터, 그래프 COULD |

## 5. Threat Hunting / Event Search

```text
+------------------------------------------------------------------+
| HT-Q: Hypothesis / Scope / Time / Dataset / Entity / Query         |
+------------------------------------------------+-----------------+
| HT-R: EVENT RESULTS (Kibana Discover reuse)      | HT-S: SAVED HUNT|
| Small event histogram / Field list              | Question        |
| Time | Source | Entity | Action | Outcome | Raw | Query & range   |
|                                                | Evidence        |
|                                                | Findings/limits |
|                                                | Link to Incident|
+------------------------------------------------+-----------------+
```

비율: Query/필터20%, 결과60%, 기록20%. 별도 Search 엔진/Query editor를 먼저 만들지 않는다. Discover의 저장 검색과 사건 메모 연결로 시작한다.

### HT-Q: Hunt Question and Query

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 무엇을 검증하는 검색인지 정의 / 무목적 전체 로그 탐색 감소 |
| 표현 / 표시 필드 | Query/filter controls + hypothesis / language,text,scope,dataset,time/TZ,entity,category,outcome |
| 집계 / 정렬 | 집계 없음 / 필터 적용 순서와 조합 명시 |
| 기간 / 필터 | 최근24h 또는 조사에서 전달된 범위 / source,Host,Account,IP,Resource,category,outcome; ATT&CK는 실제 매핑된 경우만 |
| 클릭 / Drill-down | 실행/조건 재설정 / HT-R, Discover; 임의 코드 실행 아님 |
| Empty / Error | Query 비었으면 범위 내 검색 의도를 안내 / syntax/permission/timeout R0 |
| Log Source / Normalized Field / Detection | 모든 허용 raw/normalized / 해당 Data View의 필드 / Detection 불필요 |
| MVP | MUST: 기존 Discover 검색 사용 |

### HT-R: Event Results

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 미탐지 이벤트를 포함한 사실 확인 / 가설 지지·반박 근거 찾기 |
| 표현 / 표시 필드 | table + small histogram / @timestamp,event.id,dataset,entity,action,outcome,raw_ref |
| 집계 / 정렬 | event count와 실제 결과 수, 상한/근사 표시 / @timestamp desc -> ID; chronological 보기 지원 |
| 기간 / 필터 | HT-Q 그대로 / 결과에서 field filter 추가 가능 |
| 클릭 / Drill-down | 문서 펼치기/북마크/근거 채택 / IW-E, EN-P, 사건 연결 |
| Empty / Error | 조건 내 E0, 미수집/미지원 N0 / partial/shard/query 오류 R0 |
| Log Source / Normalized Field / Detection | HT-Q가 선택한 소스 / event/raw IDs와 검색필드 / Detection 불필요 |
| MVP | MUST: raw JSON 열람과 stable ref 연결; 자동 tagging 금지 |

### HT-S: Hunt Record

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 검색 결과/반증/한계를 재현 / 인계와 규칙 개선 지원 |
| 표현 / 표시 필드 | note/metadata + saved list / hypothesis,query snapshot,range,executed_at,author,refs,conclusion,limitations |
| 집계 / 정렬 | Hunt별 기록 / updated_at desc |
| 기간 / 필터 | 기록 전체, 검색 실행 범위 별도 / owner,source,conclusion |
| 클릭 / Drill-down | 저장/재실행/사건 연결/개선 요청 / HT-Q, IW-W, DC-R |
| Empty / Error | 아직 기록 없음 / 저장 실패/충돌 입력 유지, 재실행 결과 변화 표시 |
| Log Source / Normalized Field / Detection | Hunt/workflow metadata + event refs / query context,IDs / 탐지 불필요 |
| MVP | MUST: 사건 메모에 가설/쿼리 기록; 독립 Saved Hunt는 SHOULD |

## 6. Detection & Coverage

```text
+------------------------------------------------------------------+
| DC  Domain | Technique | Source | Rule state | Validation | Health |
+------------------------------------------------------------------+
| DC-K: Enabled/Disabled | Missing telemetry | Untested | Run errors |
+------------------------------------------------------------------+
| DC-R: RULE & COVERAGE TABLE                                       |
| Rule/Ver | Domain | ATT&CK | Required Source/Fields | Test | Health |
| Mapping != telemetry ready != validated != currently healthy      |
+------------------------------------------------------------------+
| DC-G: SELECTED GAP / MISSING FIELDS / TESTS / LAST RUN / NEXT STEP  |
+------------------------------------------------------------------+
```

비율: 탐색10%, compact 지표10%, 연결표60%, Gap 상세20%. Matrix는 선택 사항이며 표의 관계/시험 데이터가 완성되기 전에 만들지 않는다.

### DC-K: Coverage Summary

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 실행/데이터/검증 빈틈 파악 / Rule 수를 방어 능력으로 오해하지 않기 위해 |
| 표현 / 표시 필드 | small counts/status / rule state,readiness,validation,run health |
| 집계 / 정렬 | Registry의 distinct Rule, missing dependency와 untested 별도 / 고정 순서 |
| 기간 / 필터 | 현재 배포 상태, 최근24h 실행 / domain,source,technique,rule state |
| 클릭 / Drill-down | 해당 조건의 DC-R / 같은 화면 |
| Empty / Error | 미등록/미검증 명시, coverage 100% 표시 금지 / Registry/run query R0 |
| Log Source / Normalized Field / Detection | Rule/Source/Test/Run registry / rule ID/version,required fields,status,time / 모든 배포/계획 Rule 구분 |
| MVP | MUST: 작은 표/수동 검증 기록으로 시작 |

### DC-R: Rule and Coverage Registry

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 무엇을 어떤 데이터로 탐지하는지 확인 / 새 Source/Rule 우선순위 결정 |
| 표현 / 표시 필드 | table / rule/version/type,domain,ATT&CK version+Technique/Analytic,required source/fields,enabled,test,current health |
| 집계 / 정렬 | Rule-Analytic-local scope 관계 행 / missing dependency -> failed/untested -> rule ID |
| 기간 / 필터 | 현재 revision, 변경 이력 선택 / domain,Technique,capability,state,Source |
| 클릭 / Drill-down | Rule snapshot/Test/Missing Source 선택 / IW-R 맥락, DC-G, PH-S |
| Empty / Error | 해당 mapping 없음=N0, 추정 태그 금지 / R0 |
| Log Source / Normalized Field / Detection | Rule definition+Registry+Tests / rule.required_fields를 실제 Source와 비교 / capability별 Rule |
| MVP | MUST: 엔진 지원과 mapping을 독립 표시 |

### DC-G: Coverage Gap and Run Details

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 실패 원인과 해결 조건 확인 / 엔진/Source/필드 중 무엇이 부족한지 결정 |
| 표현 / 표시 필드 | dependency/test/run detail / required vs observed fields,last run,input/output counts,error,test refs |
| 집계 / 정렬 | 선택 Rule의 실제 실행/시험 records / finished_at desc |
| 기간 / 필터 | 최근24h run + 마지막 test, 확장 가능 / run status,version,source |
| 클릭 / Drill-down | 누락 Source/실패 run/test evidence / PH-T, HT 쿼리, evidence viewer |
| Empty / Error | 실행한 적 없음/시험 없음 명시 / R0; no alert와 구분 |
| Log Source / Normalized Field / Detection | DetectionRun/Source/Test / run_id,watermark,error,field quality / 선택 Rule |
| MVP | MUST: 마지막 실행과 시험의 확인 가능한 기록 |

## 7. Data & Pipeline Health

```text
+------------------------------------------------------------------+
| PH  Scope | Source | Stage | State | Time/TZ | Observation age     |
+------------------------------------------------------------------+
| PH-S: SOURCE REGISTRY                                              |
| Source | State/reason | Collector | Last poll/ingest | Lag | Owner |
| HEALTHY / IDLE / DELAYED / UNKNOWN / DOWN / NOT CONFIGURED         |
+-------------------------------------------+----------------------+
| PH-T: SELECTED SOURCE PIPELINE            | PH-F: FAILURES       |
| Collect -> Parse -> Normalize -> Detect   | Stage | error | time |
| input/output/reject/skip | last success   | Backlog / missed run |
| rate / delay / watermark trend            | Affected Rules       |
+-------------------------------------------+----------------------+
```

비율: 탐색10%, Source 표45%, Stage/추이30%, 실패15%. HEALTHY는 수집 처리 상태이지 보안상 안전하다는 의미가 아니다.

### PH-S: Sources and Confidence

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 소스 정상/무활동/실패/미구성 판별 / 경보 부재의 의미 확인 |
| 표현 / 표시 필드 | state table / source_id,domain,state,reason,collector,observed_at,last_success,last_ingested,lag,owner |
| 집계 / 정렬 | Registry 한 행=한 source instance; domain 수로 대체하지 않음 / DOWN,DELAYED,UNKNOWN 우선 |
| 기간 / 필터 | 현재 평가, 최근15분/24h 관측 선택 / scope,domain,source,state,owner |
| 클릭 / Drill-down | 소스 선택/영향 규칙 / PH-T, DC-R |
| Empty / Error | Registry 없음 N0, 측정 없음 UNKNOWN / R0, 전체 건강함 표시 금지 |
| Log Source / Normalized Field / Detection | DS-15/Registry / heartbeat,poll range,result,expected schedule,time / 별도 Health 평가 정책 |
| MVP | MUST: 상태 근거와 신선도 |

### PH-T: Pipeline Stages and Delay

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 지연/유실이 생긴 단계 식별 / 데이터 엔지니어가 해결하기 위해 |
| 표현 / 표시 필드 | stage table + trend / collect/parse/normalize/detect counts,success/error,backlog,watermark,duration,delay |
| 집계 / 정렬 | 동일 run/range의 입력과 결과 대조; 이벤트 속도 시간 bucket, 지연 분포 / stage order 및 시간 asc |
| 기간 / 필터 | 최근1h, 24h 확대 / source,stage,run status,parser/rule version |
| 클릭 / Drill-down | Stage 실패/지연 구간 / PH-F, DC-G, 권한 있는 실패 Raw 조회 |
| Empty / Error | 미계측 UNKNOWN, no run 명시 / metric 조회 R0; 누락 지표를 0으로 대체 금지 |
| Log Source / Normalized Field / Detection | DS-15 + ingest timestamps / run/range IDs,input/output/rejected/filtered,ingest/event times / detector run 포함, Alert 생성 불필요 |
| MVP | MUST: 최소 stage counters/last success, 고급 histogram SHOULD |

### PH-F: Failure and Impact

| 항목 | 계약 |
| --- | --- |
| 목적 / 보는 이유 | 운영 장애와 영향 분석 / 어떤 조사/Rule을 신뢰할 수 없는지 전달 |
| 표현 / 표시 필드 | ranked failure list / error class,message,stage,time,retry,affected rule/source,assigned owner |
| 집계 / 정렬 | 동일 오류 signature+source+stage 그룹, 실제 발생 수 / active first -> newest |
| 기간 / 필터 | 최근24h와 미해결 전체 / source,stage,error class,active |
| 클릭 / Drill-down | 실패 상세/검증 근거/운영 인계 / PH-T, DC-G, 업무 메모; 자동 재배포 없음 |
| Empty / Error | 성공 조회에 실패 없음, 검사 신선도 병기 / R0, 오류 목록 조회 실패를 장애 없음으로 표현 금지 |
| Log Source / Normalized Field / Detection | pipeline errors + dependency registry / source/run/stage/error/time / Health evaluator, 보안 Rule과 별도 |
| MVP | MUST: 비밀값을 제거한 오류와 영향 관계 |

## 8. 구현 가능성 대조

외부 조사/목표 화면 정의 후 2026-09-10 작업 트리의 Python, Rule, 설정 및 Kibana export를 정적으로 대조했다. **이번 작업에서는 라이브 화면/데이터를 재조회하지 않았다.** 현재 근거: [Alert builder](../src/cloud_soc/main.py), [Engine](../src/cloud_soc/detection/engine.py), [Normalizer](../src/cloud_soc/normalizers/ecs.py), [Kibana 정의](../kibana/operations.dashboard.json), [기존 검증 기록](kibana_setup.md).

`부분`은 기존 데이터로 일부 읽기 기능이 가능하다는 뜻이며 아래 목표 패널 구현 완료가 아니다. 현재 Kibana의 7개 패널은 선택 기간 경보 수/High/경보 목록/발생 추이/규칙별 집계/설명이며 Incident 업무는 없다.

| Panel ID | 현재 구현 가능 여부 | 현재 재사용 가능한 데이터/기능 | 추가로 필요한 것 |
| --- | --- | --- | --- |
| MC-H | 미지원 | 한계 안내 Markdown만 있음 | Source registry + 실제 Stage 관측, 6상태 판정 |
| MC-K | 미지원: Incident 수 없음 | 선택 기간 Alert/High count는 존재하지만 대체 불가 | Incident status/priority/owner와 전체 미종결 집계 |
| MC-Q | 부분: 읽기 전용 Alert 목록 | severity,rule,source.ip,count,window; 최신 500건까지 | Incident/AlertReview, 담당/우선순위/전체 페이지/권한 |
| MC-T | 부분 | Alert @timestamp 발생 추이/규칙별 수 | Incident.created_at와 Alert.detected_at. 현재 발생 추이를 생성 추이로 오기 금지 |
| IW-S | 부분: Alert 문서만 | ID,rule,severity,source IP,탐지 창 | Incident/링크/Entity/담당/업무 및 탐지 생성 시각 |
| IW-R | 부분 | threshold,count,window,rule name,mitre,고정 message | 당시 rule snapshot/version, 전체 그룹 값, 실제 조건과 근거 |
| IW-T | 부분: 수동 검색 | N의 time/host.name/user.name/IP/action/outcome | 경보 exact refs, context 전달, Cloud 소스, 근거/관련 구분 |
| IW-E | 부분: 원문 문자열 열람 | N의 event.original/message, 경보 JSON 펼치기 | Alert->N->Raw 정확한 index/ID, manifest/보존/버전/권한. 경보 JSON은 Raw 인증 로그 아님 |
| IW-W | 미지원 | 저장 가능한 분석가 업무 없음 | Incident/AlertReview/Note/Audit DB, API/인증/충돌 처리 |
| EN-P | 부분: 이름/IP만 | N의 host.name/user.name/source.ip | stable key/issuer/realm/alias/자산 중요도와 Cloud account/resource |
| EN-A | 부분: SSH 이름/IP 검색 | 인증 event와 IP별 Alert 조회 가능 | scoped Entity, 사건 링크, Cloud Audit, 기간/권한 보존 |
| EN-R | 부분: 같은 N 문서의 동시 관측 | host/user/source 필드 조합 | 시간 범위 관계 레코드, 안정 key, edge evidence; 임의 교차 조합 금지 |
| HT-Q | 부분: Discover 검색 재사용 가능 | 기존 ES 필드의 Query/시간 필터 | Source 범위/가설/Entity key/context adapter |
| HT-R | 부분: Discover 문서 결과 | Raw/N의 독립 검색과 JSON | 정규화 원본 ref, 근거 채택/사건 연결, 전체 결과/상한 안내 |
| HT-S | 미지원: 업무 기록 | Discover의 일반 저장 검색을 보조 활용 가능 | 사건 메모에 query/time/가설/결론 보존; 독립 Hunt 저장소는 SHOULD |
| DC-K | 부분: 설정 정적 확인 | authentication.yml의 한 enabled Rule | 전체 Rule/Source/Test/Run registry와 count |
| DC-R | 부분: Rule YAML만 | ID/name/severity/조건/T1110 metadata | 버전/도메인/필요 Source·필드/Analytic/검증 연결표 |
| DC-G | 미지원 | 콘솔 출력은 영속 run/test 상세가 아님 | DetectionRun, 품질/실패/검증 evidence |
| PH-S | 미지원 | Filebeat input/labels와 Docker ES healthcheck | source registry/poll/heartbeat/수신 시각/신선도. ES 살아 있음은 전체 정상 아님 |
| PH-T | 미지원 | main의 processed/skipped/detection 콘솔 수 | Stage별 input/output/reject/skip/watermark/backlog의 영속 관측 |
| PH-F | 미지원 | 예외 print, 일부 부적합 이벤트는 건너뜀 | 오류 class/run/source/영향 Rule/해결 이력, 조회 실패 표시 |

Cloud/Network/Web/Host 상세 활동은 실제 해당 Telemetry 도입 전 `미수집/NOT CONFIGURED`다. 기존 필드 이름이 mapping에 있다는 이유만으로 값이 있다고 판단하지 않는다. 정확한 계약까지 완성된 목표 패널은 아직 없으며, 현재 읽기 전용 화면을 삭제하거나 새 이름만 붙여 완료 처리하지 않는다.

코드 수준 Gap과 파일별 재사용/추가 경계는 [로드맵](implementation_roadmap_v2.md)을 따른다. 기존 Dashboard 패널 수나 현재 데이터 양을 이유로 목표 기능을 제거하지 않는다.

## 9. UX 수용 체크

1. MC의 큐에서 IW 이유/근거까지 이동하고 다시 돌아올 때 담당/정렬/필터가 유지되는가?
2. 같은 IP만 가진 다른 Host/tenant를 잘못 합치지 않고 Entity key의 불확실성이 보이는가?
3. IW의 5분 탐지 창과 30분 전후 조사 범위가 시각적으로 구분되는가?
4. 사건/경보/로그/일치 이벤트 수를 같은 의미로 표시하지 않는가?
5. 원본 만료, 403, timeout, 미수집, 성공 0건이 서로 다르게 보이는가?
6. 한 패널 실패가 다른 정상 패널을 지우지 않고 전체 미완성 상태를 알리는가?
7. 위험 점수/ATT&CK/세계지도 등 데이터 근거 없는 표현이 없는가?
8. 모바일/좁은 폭에서는 Queue/근거/판정이 우선이고, 표가 잘려 접근 불가능하지 않은가?

이 체크는 향후 실제 UI 시험 계획이며 이번 문서 작업에서 UI 테스트를 통과했다는 뜻이 아니다.

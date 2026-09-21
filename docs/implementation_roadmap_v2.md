# Cloud SOC Implementation Roadmap v2 and Gap Analysis

2026-09-10 / 외부 조사 기반 제품 설계 제안. **이번 산출물은 새 설계 문서뿐이며 아래 개발 작업을 실행하지 않았다.** 사용자 승인 전 기존 문서를 대체하지 않는다.

선행 기준: [제품 요구사항](siem_product_requirements.md), [조사](siem_reference_research.md), [Architecture](siem_architecture.md), [Workflow](analyst_workflow.md), [Wireframes](dashboard_wireframes.md), [Telemetry](data_source_matrix.md), [Detection](detection_coverage.md).

## 1. 조사 순서와 현재 상태의 범위

SOC 업무/상용 SIEM/표준/논문을 조사하고 목표 업무·화면·모델·탐지·소스를 정의한 다음, 현재 코드와 기존 문서를 읽기 전용으로 대조했다. 기존 기능은 목표를 제한하는 요구사항이 아니라 재사용 가능한 구현 자산이다.

비교 기준: 로컬 HEAD `342cbb59a6c259cb91ca8c924b785ba85fa32795` 및 작업 디렉터리의 현재 파일. 기존 README/설계 3개에는 작업 전부터 수정이 있었고 `docs/kibana_setup.md`, `kibana/`도 이미 존재했다. 이 변경을 이번 신규 문서 작성과 구분하고 그대로 보존한다.

현재 판정은 코드/설정/export 파일의 정적 검토다. 이번 작업에서는 ES/Kibana API로 현재 문서 수나 서비스 상태를 조회하지 않았고 Python 파이프라인/모듈 내부 예제도 실행하지 않았다. 기존 문서의 53,826/1,276/9건 및 UI 검증 기록은 **이전 관측**이지 이번 작업의 실측이 아니다. 기존 DOCX는 이번 재설계의 요구사항으로 채택하지 않았다.

## 2. 기존 구현의 목표 계층 배치

```text
Ubuntu auth.log                -> Authentication telemetry (one domain)
Filebeat + reverse tunnel      -> Collection / transport
raw-logs-*                     -> Raw storage
parsers/linux_auth.py          -> Source-specific parsing
normalizers/ecs.py             -> Partial common normalization
normalized-events             -> Searchable event layer
YAML + threshold/window/group -> Detection capability foundation
AUTH-001                      -> One authentication analytic
security-alerts                -> Alert layer, not Incident storage
Kibana SOC Operations          -> Read-only alert overview
Kibana Discover               -> Event search / investigation aid

Not implemented:
Cloud control-plane telemetry | durable processing / run health
Exact evidence lineage | Incident / analyst workflow
Stable Entity registry | coverage/test registry | integrated pivots
```

재사용할 장점은 Raw/Normalized/Alert 분리, Parser/Normalizer/Engine/Repository 모듈 경계, YAML 검증과 순수 탐지 함수, ECS 형태의 검색 필드, raw index/ID 기반 정규화 ID, 실제 읽기 전용 Kibana export다. 전면 재작성이나 새 검색 엔진 도입은 권장하지 않는다.

## 3. Capability Gap Matrix

P1=핵심 업무 신뢰성과 MUST 구현을 막는 선행 과제, P2=기본 흐름 이후 개선. 취약점 심각도 등급이 아니다. `미지원`은 이 저장소에서 구현 근거를 찾지 못했다는 뜻이다.

| Capability | Target | Current | Gap | Priority | 필요한 변경 |
| --- | --- | --- | --- | --- | --- |
| Telemetry breadth | Cloud/IAM/Identity/Host/Network/Web | Filebeat Linux auth 한 경로 | Cloud API 주체/자원/변경 관측 불가 | P1 | 한 클라우드 Audit adapter와 필드 계약, 2개 도메인 최소 구성 |
| Ingestion identity | 등록 Source와 전송/재시도 추적 | Filebeat input ID/조직/labels, raw 저장 | 중앙 Source registry/관측 시각/품질 계약 없음 | P1 | source_id와 수집 위치/native ID, ingestion 계측 |
| Complete processing | 페이지/재개/지연 도착 처리 | raw/N 각각 오래된 최대 10,000건 | 신규 데이터 누락, 반복 재처리 | P1 | 완전 조회, durable checkpoint, window/cooldown 복원 |
| Normalization/time | 공통 의미와 원본/버전/시간 품질 | SSH 일부 형식, 현재 연도와 UTC 기본 | 다른 형식/연말 재처리/수신 시각 구분 부족 | P1 | source별 시간 계약, parse result/error, 메타데이터 전달 |
| Context/Entity | 안정 ID/alias/시간 관계/중요도 | N의 host.name/user.name/IP | 자산·계정 식별과 Cloud 관계 없음 | P1 | scoped key, 미해결 observable, 최소 inventory/Entity 조회 |
| Single event | 중요 변경 개별 탐지 | 독립 유형 없음, threshold=1로 일부 흉내 가능 | 그룹/창/cooldown 의미가 남음 | P1 | 타입별 Rule contract와 single evaluator |
| Grouped threshold | 검증된 범위/집계/창 | AND/임계값/창/다중 필드 group/cooldown | 조직 자동 격리·실행 간 상태·정답 시험 없음 | P1 | 기존 로직 재사용, scope/경계/재시작 계약 보강 |
| Sequence/correlation | 순서·다중 신호 관계 | 미지원 | 성공 후속 활동 및 자동 사건 묶기 불가 | P2 | 한 sequence는 SHOULD; 자동 correlation은 후속 |
| Detection health | 실행 범위/성공0/실패/억제 구분 | 결과 목록과 콘솔 출력 | 실행하지 않은 0과 정상 0 구분 불가 | P1 | Rule/Run/Test registry와 실행 기록 |
| Explainable Alert | snapshot/reason/exact refs/Entity | count/threshold/window/IP/rule/name/mitre | 당시 조건 버전/일치 문서 집합 없음 | P1 | DetectionMatch->Alert 근거 manifest, 생성 시각 불변 |
| Incident/Case | 조사 업무와 신호 분리 | Alert 저장에서 종료 | 사건/링크/담당/판정/이력 없음 | P1 | 수동 Incident, AlertReview, links, workflow store/API |
| Evidence/raw | 당시 근거와 원본까지 정확 추적 | N에 event.original/message; ID는 raw에서 hash | Alert->N->Raw 참조 연결 없음 | P1 | exact refs, 버전/보존/만료/권한 계약 |
| Mission Control | 전체 미종결 Incident/미분류 Alert 큐 | 기간 내 경보/High 집계와 목록 | 상태/담당 없음, 500건 표시 상한 | P1 | workflow 기반 전체 정렬/집계/페이지, Health strip |
| Investigation | 이유->전후->근거->판단 | 경보 JSON 펼치기, 수동 검색 | 통합 Workbench 및 보존된 판단 없음 | P1 | IW-S/R/T/E/W와 QueryContext |
| Entity investigation | Host/Account/IP/Cloud 중심 조사 | 이름/IP로 수동 필터 가능 | 안정 key/관계/사건 pivot 없음 | P1 | EN-P/A 최소 구현, 관계 표는 SHOULD |
| Hunting | 가설/검색/근거 채택/인계 | Kibana Discover 활용 가능 | 사건 연결/가설/검색 snapshot 없음 | P1 | Discover 재사용+사건 메모; 독립 Hunt는 SHOULD |
| Coverage | Technique->Analytic->Data->Rule->Test | AUTH-001의 T1110 문자열 | 최신 객체/필드/시험/건강도 연결 없음 | P1 | 작은 실제 registry 표, 검증 범위/미지원 표시 |
| Pipeline health | 6상태와 영향 Rule | Docker ES healthcheck, 콘솔 | 수집/정규화/탐지 측정과 registry 없음 | P1 | Stage 계측/기대 주기/오류/신선도/소스 상태 |
| Response/workflow | 승인/인계/결과/감사 | 미지원 | 조치 기록 및 권한 없음 | P1 | 인증된 수동 업무 변경과 감사; 자동 차단 제외 |
| Security/retention | 최소 권한/보존/복구/감사 | localhost 바인딩, ES 인증 off, 볼륨 | 운영 인증/TLS/보존/백업 검증 미완 | P1 | 업무 쓰기/외부 공개 전 권한 경계와 백업 시험 |

패널별 세부 가능 여부는 [Wireframes §8](dashboard_wireframes.md), 엔진 유형별 판정은 [Detection §7](detection_coverage.md)에 있다.

## 4. 코드에서 확인한 우선 보완점

### G01: 10,000건 조회 제한과 재실행

[repository.py](../src/cloud_soc/elastic/repository.py) 417~454행과 [engine.py](../src/cloud_soc/detection/engine.py) 465~502행은 `match_all`, `size=10000`, `@timestamp asc`로 한 페이지만 읽는다. 앞선 문서가 유지되고 한도를 넘으면 이후 문서를 계속 놓칠 수 있다. 단순히 size를 늘리거나 desc로 바꾸는 것은 완전 처리 보장이 아니다. `--watch`는 전체 경로 반복이지 증분 수집 완료의 증거가 아니다.

향후 완전 페이지 조회와 진행 상태를 도입하되 페이지마다 window를 초기화하지 않는다. 영속 checkpoint와 PIT 안의 페이지 cursor를 혼동하지 않고, 동일 시각/지연 도착/실패 복구를 시험한다. 기능 추가 전에 필요한 신뢰성 게이트다.

### G02: 탐지 근거가 결과에서 사라짐

[engine.py](../src/cloud_soc/detection/engine.py) 512행에는 N 문서 ID를 `_cloud_soc_meta`에 넣지만 389~426행의 Detection에는 전달하지 않는다. [main.py](../src/cloud_soc/main.py) 69행의 Alert builder도 정확한 evidence/Host/User/규칙 버전을 저장하지 않는다. N의 원문 문자열 보존은 장점이지만 원래 Raw의 index/ID 및 수집 metadata를 추적하는 것과 다르다.

같은 IP/기간 재검색은 related activity다. 이를 당시 일치 근거라고 표시하면 늦게 들어온 로그/규칙 수정 후 결론이 달라질 수 있다. 과거 경보는 `legacy incomplete`로 남기고, 검증된 복원만 `reconstructed`로 별도 표시한다.

### G03: scope/ID/업무 상태 분리

[authentication.yml](../rules/authentication.yml) 56행은 Source IP만 그룹화하고 [main.py](../src/cloud_soc/main.py) 118행은 Alert 조직을 고정한다. 여러 조직을 넣으면 같은 IP의 이벤트를 합산하고 잘못된 조직에 표시할 수 있다. 현재 단일 실습 환경의 성공을 다중 조직 격리로 확대 해석하지 않는다.

main 269행의 raw index/ID hash는 동일 Raw 재처리 중복 방지 기반이므로 유지하되 parser/schema 버전과 과거 참조 정책을 추가해야 한다. 323행의 Alert ID에는 rule version이 없고 창 시작/끝이 바뀌면 ID가 바뀐다. [repository.py](../src/cloud_soc/elastic/repository.py) 192행의 `client.index` 재저장은 불변 증거/최초 생성 보장과 다르다. Incident/메모를 그 문서에 섞으면 재탐지가 업무를 덮어쓸 위험이 있다.

### G04: 시간/로그 수의 의미

[ecs.py](../src/cloud_soc/normalizers/ecs.py) 16행은 수집 기준 시각이 전달되지 않으면 실행 시점 연도로 classic syslog를 해석한다. [main.py](../src/cloud_soc/main.py) 255행은 Raw 수집 기준/소스 TZ를 전달하지 않는다. 장기 보존 로그 재처리와 비 UTC 소스에서 조사 시간축을 잘못 만들 수 있다. 수신 당시 기준과 불확실성을 보존해야 한다.

[linux_auth.py](../src/cloud_soc/parsers/linux_auth.py)에는 Invalid user와 Failed password가 모두 failure로 정규화되는 경로가 있다. 한 인증 시도에 여러 줄이 생길 수 있으므로 AUTH-001의 10은 **일치 로그 10건**이며 사용자 로그인 시도 10회라고 확정하면 안 된다. ISO timestamp/PAM/sudo 등은 현 파서 전체 지원 대상이 아니다.

### G05: 건강도와 실패 신호

[main.py](../src/cloud_soc/main.py) 496행은 처리 예외를 출력하고 재발생/명시적인 실패 종료를 하지 않는다. 따라서 이 처리 구간에서 발생해 잡힌 오류는 정상 종료 코드로 끝날 수 있다. [client.py](../src/cloud_soc/elastic/client.py)의 직접 연결 시험은 이미 성공/실패에 따라 0/1로 종료하므로 두 문제를 혼동하지 않는다.

skipped_count는 비지원 소스/메시지/파싱 불가를 섞는다. Raw/N 누적 건수 차이를 파싱 실패 수로 계산할 수 없다. Docker ES healthcheck도 Collector/터널/Parser/Detector 생존을 보증하지 않는다. 새 계측 전 건강도는 UNKNOWN이다.

### G06: 확장 전 검증과 설정

[rule_loader.py](../src/cloud_soc/detection/rule_loader.py)는 safe_load/필수 값/연산자/중복 ID를 검증한다. 다만 cooldown, severity, group 값 타입 등 계약을 보강해야 하며 새 single/sequence를 현재 threshold 형식에 억지로 넣지 않는다. [engine.py](../src/cloud_soc/detection/engine.py) 74행 `not_equals`는 필드가 없을 때도 참일 수 있으므로 새 규칙의 결측 정책을 명시하고 시험해야 한다.

[config/app.yml](../config/app.yml)은 실행 코드에서 읽지 않으며 raw_index도 실제 main 패턴과 다르다. [requirements.txt](../requirements.txt)는 버전 미고정이고 독립 `tests/`/assertion 기반 회귀 suite는 확인되지 않았다. 모듈의 출력 예제를 회귀 시험 통과로 간주하지 않는다. 기존 인덱스에는 ensure 함수가 mapping을 갱신하지 않으므로 향후 명시적 migration/legacy read adapter/복구 계획이 필요하다.

## 5. 기존 세 문서 처리 제안

세 문서 모두 삭제/덮어쓰기하지 않는다. 아래 `폐기`는 **승인 후 새 제품 기준으로 사용하지 않을 결정**이라는 뜻이며 기존 파일에서 내용을 지운다는 뜻이 아니다.

| 기존 문서 | 유지할 내용 | 수정할 내용 | 폐기할 전제/결정 | 새 문서로 이동할 내용 |
| --- | --- | --- | --- | --- |
| [dashboard_requirements.md](dashboard_requirements.md) | Queue 중심, 전체 미종결 접근, 시간/0/실패 구분, exact evidence, Discover 재사용, 보안 경계 | 4화면을 6 Workspace로 확장, Alert 상태 중심을 Incident+AlertReview로 분리, Cloud 자원/계정 포함 | Alert-only를 최종 업무 모델로 보는 전제, 4개 화면을 제품의 최종 경계로 고정 | 제품 목적/MoSCoW는 product_requirements, 절차는 analyst_workflow, 패널은 dashboard_wireframes |
| [dashboard_data_requirements.md](dashboard_data_requirements.md) | 당시 실측 기록, 조회 제한/원본/Entity/time/워크플로 분리의 Gap, 무근거 필드 금지 | 실제 현재 HEAD/export 상태와 과거 관측 구분; 안정 account ID/Entity 관계, Incident/Run/Test 모델 | `새 소스보다 SSH 기반 보강만 먼저`를 모든 제품 단계에 적용하는 결론; Alert workflow 3테이블만으로 최종 업무 충족 | 필드/lineage/ID는 siem_architecture, Source 가치평가는 data_source_matrix, 현황은 roadmap v2 |
| [dashboard_implementation_plan.md](dashboard_implementation_plan.md) | 작고 검증 가능한 작업, migration/재처리/충돌/권한 시험, 기존 UI 보존 | Health 기본 계측/2번째 보안 도메인을 초기 게이트로 앞당김; Incident 수동 업무 추가 | Cloud Audit를 항상 마지막 선택 확장으로 두는 순서; SQLite/템플릿 웹 파일 구조를 승인 없이 확정한 구현 기준 | 의존성/우선순위/승인/검증 계획은 implementation_roadmap_v2 |

기존 문서도 이미 SSH를 제품 전체가 아니라고 정의하고 Health 선행 데이터/증분 안정화를 고려했다. 문제는 전부 잘못됐다는 것이 아니라, **외부 근거·Incident 업무·독립 Hunting/Coverage·클라우드 최소 도메인**이 최종 기준으로 충분히 연결되지 않았다는 점이다.

`docs/kibana_setup.md`와 `kibana/`는 현재 읽기 전용 산출물/재설치 기록으로 유지한다. 기존 대시보드를 새 Mission Control로 이름만 바꾸지 않는다. 500건 표본 목록과 전체 미종결 업무 큐는 다르다.

승인 후 별도 문서 정리 작업에서 v2를 기준으로 채택하고 기존 문서 첫머리에 역사 문서 안내/상호 링크를 추가하는 안을 제안한다. 이번에는 README를 포함한 기존 파일을 수정하지 않았다.

## 6. 제품 의존성 기반 로드맵

```text
A. Product/UX/data decisions approved
                  |
B. Reliable evidence foundation + basic Health
                  |
C. Two-domain data + explainable Detection/Alert + Rule/Run registry
                  |
D. Authenticated Incident/AlertReview + Workbench vertical slice
                  |
E. Mission Control + Entity/Hunt/Coverage integration + acceptance
                  |
F. Optional sequence / auditd / flow after MUST acceptance
```

Health는 E 이후에 붙이는 장식이 아니다. B에서 계측하고 C에서 Source별 판정을 검증하며 D/E에 업무 경고로 연결한다. Cloud Audit는 F의 선택 기능이 아니라 C의 최소 2도메인 게이트다. 화면 레이아웃 검토는 A부터 가능하지만 실제 업무 기능 완료는 그 데이터/권한 의존성을 따라 판정한다.

| 단계 | 분석가가 얻는 결과 | 주요 산출물/변경 후보 | 완료 게이트 | 범위 |
| --- | --- | --- | --- | --- |
| A 설계 승인 | 무엇을 조사하고 어떤 증거로 판단할지 합의 | 이번 8문서 검토, UI 재사용/저장소/보호 대상 결정, Source/Rule/Entity contract | MC/IW walkthrough, 필드별 생산자/결측/시간/권한 확정, 승인된 수집 대상 | MUST |
| B 신뢰 가능한 원본 기반 | 정보가 빠졌는지/왜 믿을 수 없는지 알 수 있음 | Repository 완전 조회, config 단일화, parser/time/lineage, 버전/체크포인트/격리, Source registry/Stage 계측 | 10,000건 초과, 동일 시각/재시작/부분 실패, Raw 참조/시간 재처리 검증 | MUST |
| C 2도메인 탐지 | 인증과 클라우드 변경을 같은 조사 모델로 읽음 | 한 Cloud Audit adapter, single evaluator, 기존 threshold 개선, Alert snapshot/manifest, DetectionRun/Test registry | 두 소스 원본/정규화/근거 일치, 정상 변경과 의심 활동 비교, 실패0 구분, scope/cooldown 복원 | MUST |
| D 조사 업무 완결 | 한 건을 인수하고 판단/인계/종결할 수 있음 | 인증/인가, Incident/AlertReview/링크/메모/감사 store/API, IW-S/R/T/E/W, 최소 Entity pivot/Discover link | exact evidence->Raw, 두 사용자 충돌/권한, 수동 연결/해제/재개, 재시작 후 이력 유지 | MUST |
| E 관제 시작점·완성도 | 전체 업무 우선순위와 관측 공백을 파악 | MC-H/K/Q, EN-P/A, HT-Q/R/메모, DC-K/R/G, PH-S/T/F; 실제 데이터 UX 확인 | 큐/KPI 전체 범위 일치, 오래된 업무/미분류 Alert 접근, 검색 context, 6상태/coverage 검증 | MUST 핵심; 추이/관계표 확장은 SHOULD |
| F 선택 심화 | 후속 행위 또는 연결 범위 확대 | 안정적 sequence 한 사례, auditd 3번째 소스, Flow 4번째 소스, 독립 Saved Hunt | 추가 소스마다 값/비용/보존/health/테스트 계약 검증, MUST 회귀 통과 | SHOULD/COULD |

### 6.1 작업 크기와 순서

한 단계 전체를 한 번에 변경하지 않는다. 예를 들어 B를 `기존 동작 assertion 고정 -> 완전 조회/오류 처리 -> lineage/time 계약 -> durable 복구와 health`로 나눈다. 각 단위는 입력/출력과 실패 시나리오가 있어야 한다. 전체 조회 중간 버전은 가능하지만 계속 운영할 MVP는 bounded resource/증분 복구 게이트를 통과해야 한다.

C는 실제 Cloud 작업의 필드 검증부터 시작한다. 민감 변경 후보가 실제 Audit로 관측되고 주체/자원/결과를 해석할 수 있어야 single Rule을 정한다. 승인된 시험에서도 과금/노출/권한 변경을 수반하는 작업은 별도 허가가 필요하며, 단순 API 성공을 악성으로 라벨링하지 않는다.

D의 첫 화면 구현은 차트가 아니라 `사건/경보 선택 -> 이유 -> exact evidence -> 원본 -> 판단 저장` 수직 흐름이다. Mission Control의 전체 큐는 이 상태 모델이 검증된 후 확장한다. 6개 메뉴가 존재하는 것과 6개 업무가 완료되는 것은 다르다.

### 6.2 파일/모듈별 재사용 방향

아래 새 경로는 향후 후보이며 이번에 생성하지 않았다. 세부 파일명/Framework는 A의 결정 이후 확정한다.

| 구분 | 기존 자산/추가 경계 | 제안 |
| --- | --- | --- |
| 유지·보강 | `parsers/linux_auth.py`, `normalizers/ecs.py` | 기존 메시지 해석 재사용, 시각/메타데이터/오류 분류 보강 |
| 유지·보강 | `detection/engine.py`, `rule_loader.py` | 순수 evaluator 유지, 타입별 계약/버전/근거/실행 상태 추가 |
| 유지·보강 | `elastic/repository.py`, `main.py`, `config/app.yml` | 조회/처리/설정/실패/체크포인트 책임 분리; 명시적 migration |
| 유지 | `elastic/client.py` | 기존 연결/close/실패 코드 기능 유지. 현재 직접 실행 실패 처리의 재수정 불필요 |
| 추가 | collectors 및 source-specific normalization 경계 | 한 공급자 Cloud Audit, 필요하면 auditd/Flow 후속 |
| 추가 | entities/evidence/pipeline state 경계 | ID/관계/manifest/원본/버전, durable 처리 상태 |
| 추가 | workflow/service/repository/API 경계 | Incident/AlertReview, 감사/충돌/멱등 업무 변경 |
| 추가 | queries/UI/health/coverage 경계 | 허용된 검색, 인증, 얇은 Workbench/큐, Discover adapter |
| 추가 | 독립 tests와 승인된 fixtures | 기본 오프라인, ES 쓰기 통합 시험은 격리/명시적 opt-in |
| 보존·재사용 | `kibana/operations.*`, `docs/kibana_setup.md` | 읽기 전용 Alert 개요; 별도 승인 없이 라이브 객체 수정 금지 |

인덱스/필드 변경은 dry-run/백업/호환성/참조 보존을 포함한 별도 승인 작업이다. `event_count` 등을 논리 모델의 `match_count`로 설명했다고 바로 기존 필드를 바꾸지 않는다. 기존 `mitre.*`도 read adapter로 읽고 매핑 revision 없이 과거 문서를 덮어쓰지 않는다.

## 7. MVP 컷라인과 검증

최소 배포는 한 보호 환경, 한 Cloud 공급자, 2개 보안 소스, single+grouped threshold, 수동 사건 업무, Evidence/Raw 조사, 최소 Entity, Discover 검색, Coverage 표, Health 6상태다. Context inventory/내부 health를 별도 보안 소스로 세어 `다중 로그 수집`을 부풀리지 않는다.

일정이 부족하면 sequence, 3~4번째 소스, 관계 그래프, 독립 Hunt 저장소, 추이 차트부터 줄인다. **원본 근거/정확한 조회/권한/판정 이력/실패 표시를 버리고 차트 수를 지키는 선택은 하지 않는다.** Cloud Audit가 불가능하면 클라우드 SIEM MVP 완료라고 하지 않고 범위/명칭을 다시 승인받는다.

| 검증 축 | 최소 시험 | 연결 수용 기준 |
| --- | --- | --- |
| 데이터 신뢰성 | 10,001건 이상, 같은 시각, 재전송/중간 종료/늦은 도착, Raw/버전 참조 | AC-01/02/08 |
| 탐지 | single 조건, threshold 9/10/11, 300초 포함/초과, cooldown/재시작, 교차 scope 분리, 결측 | AC-02/08 |
| 조사/업무 | Incident 연결/해제, 미분류 경보 유지, 정확 근거와 related 구분, 상태/판정/이력/재개 | AC-02/03/06 |
| 큐/검색 | 24h보다 오래된 열린 사건, 전체 KPI/필터/페이지 일치, query/TZ/context 보존 | AC-04/06 |
| 신뢰도/coverage | 소스 미구성, heartbeat 정상 무활동, 지연, 명시 실패, stale 관측, 정상 처리; Rule enabled와 테스트 구분 | AC-05/07 |
| 보호/복구 | 권한 밖 사건/원본 차단, 악성 HTML 로그 렌더링, 저장 충돌, 비밀값 누출, DB/ES 백업 복구 | AC-03/09 |

이번에는 시험 계획만 작성했다. 후속 테스트용 합성 fixture가 필요하면 테스트 데이터로 명시하고 운영 인덱스/제품 증거와 분리한다. 졸업 시연의 실제 수집/탐지 주장에는 허가된 실습 원본과 검증 기록을 사용한다. 새 샘플이나 가짜 실시간 경보를 이번 작업에서 만들지 않는다.

성능 목표 숫자는 아직 확정하지 않는다. 예상 EPS/보존/사용자/호스트 수를 승인한 뒤 완전 조회 범위, p95 조회 시간, 처리 lag, 저장량을 실측한다. 팀원 수나 마감이 없는 상태에서 달력 일정/완료 주차를 단정하지 않는다.

## 8. 중요한 미결정 사항

| 선택 | 필요한 사용자 정보/승인 | 영향 |
| --- | --- | --- |
| 보호 대상/보안 질문 | 어떤 클라우드 계정·자원·워크로드의 어떤 위험을 보여줄 것인가 | Audit 작업/Entity/우선순위/시연 정답 |
| 일정/인력/평가 기준 | 제출/시연 마감, 구현 인원, 교수 평가에서 자체 엔진/UI 요구 | SHOULD/COULD 컷라인, 개발 방식 |
| UI 재사용 범위 | 자체 Workbench + Discover 권장안 vs Elastic Cases/Timeline 통합 검증 | 구현량/라이선스/사용자 인증/호환성 |
| 저장소/배포/인증 | 단일 로컬 시연인지 동시 분석/서버 배포인지, 사용할 계정 체계 | SQLite/PostgreSQL 선택, TLS/권한/백업 |
| 실제 수집 권한/비용/보존 | Cloud 공급자/계정의 read 권한, 허가된 시험 작업, 예산, 개인정보/원본 보존 | Source 도입 및 저장량/비식별 정책 |
| 판정/인계 정책 | 누가 높은 우선순위를 인계받고 inconclusive 종료를 승인하는가 | 상태 전이, 수용 기준, 책임 범위 |

위 항목은 미확정으로 남겨 두며, 문서 제안이 사용자 승인이나 서비스 변경 권한을 대신하지 않는다. 다음 실제 작업은 A의 제품/MC-IW walkthrough 승인 후 작게 진행한다. commit/push는 별도 요청 전 수행하지 않는다.

# Cloud SOC Phase A UI Specification

작성일: 2026-09-10. 대상: `prototype/`의 HTML/CSS/Vanilla JavaScript 정적 화면.

### 한국어 표시 변경 (2026-09-14)

사용자 요청에 따라 화면 표시 언어를 한국어로 변경했다. 아래 본문의 영문 UI 명칭은 최초 도식과의 대응을 위한 설계 용어이며, 실제 화면에는 다음 한국어 문구가 우선한다.

- Mission Control / Investigation Workbench: 관제 현황 / 사건 조사.
- Overview / Timeline / Evidence / Raw Event / Entities / Analyst Work: 개요 / 시간 흐름 / 탐지 근거 / 원본 이벤트 / 관련 대상 / 분석 기록.
- Normalized / Raw / Provenance: 정규화 필드 / 원문 로그 / 출처 정보.
- Critical / High / Medium / Low: 긴급 / 높음 / 보통 / 낮음. New / Investigating / Triage / Escalated / Closed: 신규 / 조사 중 / 초기 분류 / 상위 이관 / 종결.
- Malicious / Benign / False Positive / Inconclusive: 악성 / 정상 / 오탐 / 판단 유보.
- 고정 안내: A단계 화면 프로토타입 / 데모 데이터 / 백엔드 미연결. 미확인 KPI는 N/A 대신 미확인으로 표시한다.
- 저장 안내: 프로토타입 전용 / 업무 저장용 백엔드가 연결되지 않았습니다. / 아무 내용도 저장되지 않았습니다.

메뉴, 표, 필터, 차트, 상태 선택기, 모달, 접근성 이름을 함께 번역한다. select의 내부 value, CSS 상태 키, URL 매개변수, 사건/규칙/원문 ID는 유지한다. `demo-data.js`의 데이터와 원문 로그, 정규화 필드명/필드값은 변경하지 않는다. 검색은 기존 영문과 한국어 표시명(예: 무차별 대입, 클라우드, 분석가 01, 미배정)을 모두 지원한다. 한국어 선택에 따라 저장 기능이나 실제 백엔드 연결이 추가되지는 않는다.

시각 기준은 사용자가 첨부한 **Cloud SOC Mini SIEM 아키텍처 및 대시보드 도식화 이미지**다. 업무 의미는 기존 제품 요구사항, 분석가 흐름, 와이어프레임, 데이터 소스/탐지 커버리지, 아키텍처, 로드맵 문서를 따른다. 이 문서는 실제 API 또는 데이터 스키마가 구현되었다는 선언이 아니다.

## 1. 파일 및 공통 구성

2026-09-21 변경: 사용자 요청으로 세 번째 정적 화면인 **통합 로그**를 추가했다. 아래 파일/공통 구성은 최신 상태이며, 2026-09-10 검증 기록의 두 화면은 당시 범위다. 상세 동작은 7절을 따른다.

| 파일 | 역할 |
| --- | --- |
| `prototype/index.html` | Mission Control 구조, 큐/필터/차트 영역 |
| `prototype/workbench.html` | Investigation Workbench 구조, 조사 탭 |
| `prototype/logs.html` | 통합 로그 검색, 엑셀형 표, 행별 상세 패널 |
| `prototype/logs.css` | 로그 표, 고정 열/헤더, 상세 패널, 반응형 |
| `prototype/logs.js` | 로그 필터/정렬/페이지 이동 및 상세 렌더링 |
| `prototype/logs-data.js` | 사건/경보와 독립된 90건 합성 로그와 로컬 검색 함수 |
| `prototype/tests/logs.test.cjs` | 의존성 설치 없는 Node 기본 테스트 |
| `prototype/styles.css` | 공통 셸, 다크 관제 화면, 밝은 조사 본문, 반응형 |
| `prototype/app.js` | DOM 렌더링, 로컬 검색/필터, 탐색, 입력, 상태 예시, 모달 |
| `prototype/demo-data.js` | 운영 자료와 분리된 합성 사건/경보/근거/차트 fixture |
| `prototype/assets/mark.svg` | 로컬 Cloud SOC 마크 및 favicon |

- Header: Cloud SOC, 현재 Workspace, Production **(DEMO)**, UTC+9 / Asia/Seoul, 현재 UI 시각, 사용자 아이콘. 통합 로그에서는 환경을 다중 환경 **(데모)**로 표시한다.
- Sidebar: 기본 204px, 고정 배치. 관제 현황, 통합 로그, 사건 조사, 관련 대상, 위협 헌팅, 탐지 범위, 시스템 상태, Kibana, 설정 순서.
- 고정 배너: `PHASE A UI PROTOTYPE`, `DEMO DATA`, `NO BACKEND CONNECTION` 및 Demo State 선택기.
- 구현된 정적 화면은 관제 현황, 통합 로그, 사건 조사다. 나머지 메뉴와 사용자 아이콘은 설명 모달이다.
- Kibana 모달은 기존 read-only dashboard / Discover 연결 지점임을 설명한다. 실제 Kibana 이동이나 Saved Object 변경은 하지 않는다.
- 색상: Navy/Slate 바탕, Blue 선택 상태, 얇은 경계, 4~5px 모서리. Severity/Status는 텍스트 배지를 함께 표시한다.
- 글꼴은 로컬 Bahnschrift / Malgun Gothic, 원문은 Cascadia Mono / Consolas 계열이다. CDN, 차트 라이브러리, 빌드 과정은 없다.

## 2. Mission Control

목적: 분석가가 지금 조사할 업무를 고른다. 도식의 순서를 유지한다.

| 순서 | 영역 | 표시와 목적 |
| --- | --- | --- |
| 1 | Data Confidence | HEALTHY, Log Sources 3/3, Last Ingest 2m ago, Pipeline OK, Detection Engine OK. 모두 `DEMO STATUS / NOT LIVE` |
| 2 | KPI 5개 | Open, Critical / High, New, Investigating, Unassigned |
| 3 | Queue Tabs | Incidents 5건, Untriaged Alerts 3건을 구분 |
| 4 | Search / Filters | 로컬 데모 업무를 좁혀 선택 |
| 5 | Analyst Queue | 원인, 중요도, 상태, 관련 대상, 담당자, 경과 시간을 확인 |
| 6 | Context Charts | Alert Trend, Top Detection Rules, Top Source IP의 배치 확인 |

### 2.1 큐 컬럼

| 컬럼 | 의미 |
| --- | --- |
| Priority | Critical / High / Medium / Low. Medium은 `MED`로 축약 |
| Incident 또는 Alert | 제목과 `INC-DEMO-*` 또는 `ALT-DEMO-*` ID |
| Reason | 탐지/조사 이유를 짧게 표현. 긴 값은 말줄임 및 title 제공 |
| Status | New / Investigating / Triage / Escalated / Closed |
| Entities | 계정, 호스트 또는 대상 자원, Source IP의 요약 |
| Owner | analyst01 / analyst02 / Unassigned |
| Age | 고정 데모 스냅샷 기준 분/시간. 실제 현재 시각과 무관 |

마지막 화살표는 행 이동의 시각적 힌트다. 제목 링크는 키보드로 접근 가능하고 행의 나머지 영역도 클릭할 수 있다. 정렬은 Priority 우선, 동일 중요도에서는 오래된 업무 우선이다.

### 2.2 필터와 집계 범위

- Search: ID, 제목, 이유, host/대상 자원, user, IP, rule, owner, domain을 대소문자 구분 없이 부분 일치 검색한다.
- Priority: All Priority / Critical / High / Medium / Low.
- Status: All Status / New / Investigating / Triage / Escalated / Closed.
- Time: All Time / Last 1 hour / Last 24 hours. 기준은 실제 시계가 아닌 fixture의 Age다.
- More Filters: Owner와 Domain(Authentication / Cloud / Host), Clear filters.
- 서로 다른 필터는 AND 조건이다. 서버 질의나 수집 데이터 검색은 하지 않는다.
- KPI는 현재 필터에 일치하는 **Incident만** 집계한다. Alert 탭에서도 Incident 지표이며 큐 하단에 이를 명시한다.
- Open은 Closed 제외, 나머지 KPI는 해당 Open 집합의 부분집합이다. 필터 없는 기본 값은 `5 / 2 / 2 / 2 / 3`이다.
- 탭의 `(5)`와 `(3)`은 데모 원본 총수다. 큐 하단은 `표시 건수 of 원본 총수`를 표시한다.
- KPI 클릭은 Incident 탭으로 이동해 기존 필터를 초기화한 후 해당 데모 조건을 적용한다. 현재 fixture에는 Critical/Closed 행이 없다.
- 하단 3개 차트는 **서로 독립적인 배치 샘플**이다. 큐 집계, Evidence 수, 현재 필터와 통계적으로 연결되지 않으며 필터 변경 시 숫자가 변하지 않는다. 각 차트에 `DEMO VISUALIZATION`을 표시한다.
- Refresh는 현재 로컬 화면을 다시 그린 뒤 backend request가 없었다는 안내만 표시한다.

### 2.3 화면 이동

`workbench.html?id=INC-DEMO-001`처럼 선택한 ID로 이동한다. Alert는 `ALT-DEMO-*`를 유지하며 Incident로 자동 변환하지 않는다.

`return`에는 현재 탭, Demo State, 검색/필터만 전달한다. Back to Mission Control은 같은 조건을 복원한다. 임의 외부 return URL을 따라가지 않는다. Sidebar의 Mission Control은 기본 큐, Investigation은 기본 데모 사건을 연다.

## 3. Investigation Workbench

목적: 선택한 업무의 이유를 확인하고, 탐지 일치 근거와 관련 활동을 구분한 뒤 판단 입력 흐름을 검토한다.

상단에는 Back 링크, 선택한 사건/경보의 제목, Severity, 임시 Status/Owner 선택, Environment, Scope, ID, Created, Last activity를 배치한다. 첫 사건의 제목은 `Possible Account Compromise`이며 큐와 일치하도록 New / Unassigned로 시작한다.

### 3.1 탭

| 탭 | 구조 및 동작 |
| --- | --- |
| Overview | 밝은 본문 2열. 왼쪽 Detection Reason + Related Entities, 오른쪽 Summary + Key Questions + Analyst Notes + Verdict / Save |
| Timeline | BEFORE, DETECTION WINDOW, AFTER. 실제 일치 근거를 뜻하는 `EVIDENCE`와 맥락 예시인 `RELATED`, 데모 `TRIGGER`를 구분 |
| Evidence | Time, Source, Host, User, Action, Outcome, Evidence Type, Quality 표. 행/시간 버튼 클릭으로 상세 펼침 및 접기 |
| Raw Event | 선택한 근거 ID/시각과 Normalized / Raw / Provenance 하위 탭 |
| Entities | Host / User / Source IP / Cloud Account / Cloud Resource 카드. 조사 열기는 미구현 모달 |
| Analyst Work | Status, Owner, Verdict, Rationale, Notes, 읽기 전용 DEMO History, 미저장 Save |

### 3.2 Overview 및 조사 근거

Detection Reason은 Rule, Type, Condition, Threshold, Window, Observed, First Evidence, Last Evidence의 표다. 기본 사건은 AUTH-001, Grouped Threshold, 동일 Source IP의 실패, 300초 안의 기준 10건, 관측 12건을 표현한다. 실제 규칙 실행 결과가 아니라 `DEMO RULE SNAPSHOT`이다.

기본 근거 12건의 시작/끝은 `13:01:12 / 13:04:37`이고 Timeline, Evidence, Normalized, Raw에서 같은 fixture를 사용한다. 다른 사건을 선택하면 해당 사건의 ID, 대상, 이유, 시각과 근거로 바뀐다. Cloud/Host 예시는 실제 구현된 탐지 방식이 아니라 별도의 single-event 합성 자료다.

Summary는 침해 확정이 아닌 조사 필요성과 대안 가설을 설명한다. Key Questions는 계정의 다른 활동, IP의 다른 대상 접근, 후속 Cloud API, 정상 관리 작업 가능성을 제시한다. 도식의 Cloud Resource 연결도 합성 관계이며 실제 자산 식별 결과가 아니다.

Evidence 상세에서 Open Raw Event 또는 View Normalized를 누르면 **선택한 그 근거**가 열린다. Provenance는 Source, demo Parser, 검증되지 않은 ECS-compatible 필드 예시, `DEMO-RAW-*` 참조, Prototype 상태, 미검증 보존/무결성을 보여준다. Elasticsearch `_index/_id`를 생성하거나 조회하지 않는다.

### 3.3 입력과 미저장

- Status: New / Investigating / Triage / Escalated / Closed. Triage는 도식의 큐 상태를 그대로 조사 화면에서도 표현하기 위한 UI 후보값이다.
- Owner: Unassigned / analyst01 / analyst02. 로그인된 실제 계정이 아니다.
- Verdict: Malicious / Benign / False Positive / Inconclusive. 초기값은 미선택이다.
- Notes와 Rationale은 일반 텍스트 입력이며 HTML로 해석하지 않는다.
- 현재 페이지 안에서는 Overview와 Analyst Work 사이에 Notes/Verdict를 공유하고, Status/Owner는 상단과 동기화한다.
- 새로고침 또는 페이지 이동 후 보존은 제공하지 않는다. localStorage, sessionStorage, IndexedDB, 쿠키를 사용하지 않는다.
- History는 고정 DEMO activity다. 입력/Save로 추가되거나 실제 감사 이력으로 저장되지 않는다.

Save 결과는 항상 다음 모달이며 성공 안내가 아니다.

```text
Prototype only
Workflow backend is not connected.
Nothing was saved.
```

## 4. 상태 표현

세 화면 모두 고정 Demo State 선택기로 아래 상태를 확인한다. 외부 장애/권한을 실제 측정하거나 재현하는 기능은 아니다.

| 선택 | 화면 의미 |
| --- | --- |
| Normal | 고정 데모 데이터 표시 |
| Loading | 요청 진행 화면 예시. 실제 요청 없음 |
| Empty | 정상적으로 결과가 없는 화면 예시. 실제 보안 이벤트 0건 판정이 아님 |
| Unknown | 신뢰도 판단에 필요한 관측값 없음 |
| Not Configured | 필요한 소스 미구성 예시 |
| Not Implemented | Phase A 미구현 기능 안내 |
| Partial | 일부 자료만 있는 UI 예시와 합계 미확인 표시 |
| Query Failed | 조회 실패를 0건 성공으로 오해하지 않도록 별도 안내 |
| Permission Denied | 접근 불가 UI 예시. 실제 인증/인가 없음 |
| Evidence Expired | 만료된 참조를 주변 이벤트로 대체하지 않는 안내 |

Mission Control은 Normal 외의 경우 건강도를 UNKNOWN으로 바꾸고 차트 숫자를 숨긴다. Empty만 KPI 0, 나머지는 N/A다. Workbench는 활성 탭의 본문을 상태 카드로 바꾼다. 복구 버튼은 Normal 데모로 돌아간다. 검색 결과가 없는 경우에는 필터 초기화 동작을 제공한다.

존재하지 않는 Workbench ID는 `Unknown demo ID`로 표시하며 다른 사건의 근거로 대체하지 않는다.

## 5. 반응형 및 접근성

- 1440px 기준: 204px Sidebar, 5 KPI 가로 배치, 하단 차트 3열, Workbench Overview 2열.
- 1190px 이하: Sidebar 184px, 패널 간격 축소, 일부 보조 Header 정보 숨김.
- 980px 이하: Sidebar 64px 아이콘 모드. 메뉴 접근성 이름/title은 유지. 차트는 Trend 전폭 + 나머지 2열.
- 720px 이하: 고정 데모 배너 2줄, 필터 줄바꿈, KPI 2열, 차트와 Workbench 본문 1열, 조사 탭 가로 스크롤.
- 표는 자체 스크롤 영역을 사용한다. 긴 제목은 말줄임, 원문은 monospace와 줄바꿈 처리한다.
- 본문 바로가기, 버튼/링크 포커스 표시, 탭 aria-selected/tabpanel 연결, 방향키/Home/End 이동, 상세 열기 aria-expanded를 제공한다.
- 모달은 native dialog의 포커스 관리/Escape를 사용한다. 근거 펼침/접기와 원문 하위 탭 재렌더링 후 포커스를 복원한다.
- 완전한 모바일 제품, 스크린리더 전체 감사, 모든 브라우저 호환성 인증은 이번 범위가 아니다.

## 6. 실행 및 검증

### Windows에서 열기

가장 단순한 방법은 탐색기에서 `D:\cloud-soc\prototype\index.html`을 더블클릭하는 것이다. 외부 데이터 fetch나 JS module import가 없어 설치/빌드가 필요하지 않다. 브라우저별 로컬 파일 제한이 있으면 다음 정적 서버를 사용한다.

```powershell
cd D:\cloud-soc
python -m http.server 8765 --bind 127.0.0.1 --directory D:\cloud-soc\prototype
```

브라우저에서 `http://127.0.0.1:8765/index.html`을 연다. 종료는 실행 터미널의 Ctrl+C다. 이 서버는 정적 데모 파일만 제공하며 기존 Python 애플리케이션이나 API 서버가 아니다. 저장소 루트 전체를 공개하거나 `0.0.0.0`으로 바인딩하지 않는다.

이번 환경에서는 `.venv\Scripts\python.exe`의 프로세스 생성이 실패하여 PATH의 Python 표준 라이브러리 서버로 검증했다. 가상환경/requirements는 수정하지 않았다. 앱 내 브라우저의 `file://` 접근은 정책상 제한되어 직접 파일 열기의 브라우저 실증은 하지 못했다.

### 2026-09-10 검증 기록

검증 환경: Codex 앱 내 Chromium 브라우저, localhost 정적 서버. 표의 PASS는 아래 정적 UI 범위에만 해당한다.

| 검증 | 결과 |
| --- | --- |
| Mission Control 로드, 이미지 대비 셸/상태/KPI/큐/3개 차트 배치 | PASS |
| Incident / Alert 탭 전환, 각기 다른 데모 목록 | PASS |
| 검색, Priority/Status/Time/Owner/Domain 결합, 필터 초기화 | PASS |
| Queue 행 클릭, 선택 ID의 Workbench, Back 시 검색 조건 복원 | PASS |
| 6개 Workbench 탭, EVIDENCE / RELATED Timeline | PASS |
| Evidence 행 펼침/접기, 선택 근거 Raw / Normalized / Provenance | PASS |
| Entity 조사 및 Sidebar의 미구현 메뉴, Kibana 설명 | PASS |
| Notes 입력, Verdict 선택, Status/Owner 동기화, 미저장 Save | PASS |
| 탭 간 입력 유지, 새로고침 후 기본 상태/빈 메모 복귀 | PASS |
| 두 화면의 9개 비정상/빈 상태와 Normal 복귀 | PASS |
| 1440px / 900px / 560px 배치 및 표 내부 가로 스크롤 | PASS |
| 탭 Home 키, Evidence 키보드 펼침/접기와 포커스 | PASS |
| 5개 Incident의 ID별 근거, Alert 조사 후 원래 Alert 탭 복귀 | PASS |
| 존재하지 않는 ID의 별도 안내 및 외부 return URL 미사용 | PASS |
| 두 JavaScript 파일의 Node 문법 검사, 8개 업무/41개 근거 ID와 시각 일관성 | PASS |
| HTML의 로컬 자산 참조, 네트워크/브라우저 저장 API 미사용 정적 검사 | PASS |
| 브라우저 콘솔 error/warn 확인 | 관측 오류 없음 |
| 작업 전 기존 파일 35개의 SHA-256 비교 및 `git diff --check` | PASS, 기존 파일 변경 없음 |

발견한 좁은 화면 가로 넘침은 스크롤 표의 containing block을 지정해 수정했다. 데모 사건 생성 시각이 마지막 근거보다 늦도록 고정 스냅샷을 조정했다. 위 자동 검사는 추가 의존성 없이 기존 Node와 PowerShell로 수행했으며 테스트 러너나 빌드 체인은 설치하지 않았다. 실제 Elasticsearch, 탐지, 인증/인가, 저장 성공 여부는 검증하지 않았다.

## 7. 통합 로그 추가 (2026-09-21)

목적: 경보 발생 여부와 무관하게 여러 환경의 일반 로그, 오류, 파싱 실패를 같은 목록에서 탐색한다. 관제 현황은 조사할 업무를 고르는 화면, 통합 로그는 원본과 해석된 필드를 확인하는 읽기 전용 화면이다.

### 7.1 데이터와 범위

- 전체 환경은 연결·승인된 수집 범위다. 모든 환경/서비스를 자동 발견하거나 수집한다는 의미가 아니다.
- 운영·테스트·개발 각 30건, 총 90건의 독립 합성 로그를 사용한다. 파싱 완료 78건, 일부 필드 누락 6건, 파싱 실패 6건이다. Windows/Linux 확장은 7.4절을 따른다.
- 온프레미스/OCI/AWS/기타와 인증/호스트/클라우드 감사/웹/애플리케이션/미분류 소스는 UI 분류 예시다. 실제 공급자 연동, 지원 파서 또는 수집 범위를 선언하지 않는다.
- 파싱 결과는 고정 fixture이며 실제 파서를 호출하지 않는다. 실패한 로그도 원문과 수집 메타데이터를 유지한다. 일부 누락 예시에는 `@timestamp`, `event.outcome`이 없고 수집 시각으로 대체하지 않는다.
- 스냅샷은 `2026-09-21 12:00 KST`다. Header의 현재 시각과 별개이며 기간 필터는 스냅샷 대비 수집 시각 기준이다.
- 파싱 완료는 안전하거나 정상이라는 판정이 아니다. 이벤트 결과, 파싱 품질, 보안 경보를 분리한다.

### 7.2 표와 조작

화면은 범위 안내, 접을 수 있는 OS별 수집 대상, 검색/필터, 작은 집계 띠, 엑셀형 표, 페이지 이동 순서다. 표 컬럼은 행 번호, 로그 ID, 수집 시각(KST), 환경, 운영체제, 플랫폼, 로그 소스, 파싱 상태, 채널/파일/저널, 호스트/자원, 사용자, 출발지 IP, 행위, 결과, 메시지다. 상세 패널에서 전체 ISO 시각을 확인한다.

- 검색은 ID, 호스트/자원, 사용자, IP, 행위, 표시명, 메시지, 원문, 필드에 대한 대소문자 구분 없는 부분 일치다.
- 환경/운영체제/플랫폼/소스/파싱 상태/이벤트 결과/수집 기간을 AND로 결합한다. 기간은 전체/최근 1시간/최근 3시간이다.
- 집계는 현재 필터 결과 전체 기준이며 현재 페이지 행 수와 구분한다.
- 열 제목으로 오름차순/내림차순 정렬한다. 기본은 최신 수집 시각 순이며 결측 값은 양쪽 정렬 모두 마지막이다.
- 페이지 크기는 10/25/50행이다. 필터·정렬·페이지 크기 변경 시 첫 페이지로 이동한다. 조건과 페이지는 새로고침/다른 화면 이동 후 유지하지 않는다.
- 표 내부 가로·세로 스크롤, 고정 헤더와 행 번호/로그 ID 열을 사용한다. 긴 메시지는 상세에서 확인한다.
- 행 클릭 또는 로그 ID 버튼의 Enter로 상세를 연다. 파싱 필드/원문 로그/수집 정보 탭, 방향키 탭 이동, Escape 닫기와 원래 버튼으로 포커스 복귀를 제공한다.
- 원문은 HTML로 해석하지 않고 텍스트로 표시한다. 표와 상세 모두 읽기 전용이며 셀 편집, CSV/XLSX 내보내기는 이번 범위가 아니다.
- 빈 검색 결과는 필터 초기화를 제공한다. 공통 오류 상태에서는 표를 숨기고 수치를 미확인으로 표시한다. 결과 없음 상태만 0건이다. 실제 장애·권한 검증은 아니다.

### 7.3 실행과 검증

6절의 정적 서버에서 `http://127.0.0.1:8765/logs.html`을 연다. 자동 검사는 저장소 루트에서 다음과 같이 실행한다. 새 패키지는 필요하지 않다.

```powershell
node --test prototype/tests/logs.test.cjs
node --check prototype/logs-data.js
node --check prototype/logs.js
node --check prototype/app.js
```

자동 검사는 fixture의 ID/분포, 원문과 결측 보존, 결합 필터, 한영 검색, 수집 기간, 정렬/비변경성, 로컬 자산과 미연결 설정을 대상으로 한다. 실제 수집·파싱, Elasticsearch, RBAC 및 대용량 성능은 검증 대상이 아니다.

2026-09-21 최초 48건 버전 검증 결과 (OS 확장 전):

| 검증 | 결과 |
| --- | --- |
| Node 기본 테스트 7개, 변경된 JavaScript 3개 문법 검사 | PASS |
| 환경/플랫폼/소스 결합, 원문 검색, 빈 결과, 기간 필터, 양방향 정렬 | PASS |
| 페이지 이동, 페이지 크기와 필터 변경 시 첫 페이지 복귀, 전체 필터 집계 | PASS |
| 파싱 완료/누락/실패 상세, 원문 텍스트 보존, 누락 필드 미보충 | PASS |
| 키보드 상세 열기, 방향키 탭 이동, Escape 닫기, 버튼 포커스 복귀 | PASS |
| 비정상/빈 상태 9개, 오류의 미확인 집계, 초기화 복귀 | PASS |
| 기본 1280px와 560px 화면, 표 내부 스크롤, 좁은 화면 상세 패널 | PASS, 문서 가로 넘침 없음 |
| 기존 관제 현황 목록, 사건 이동, 원본 이벤트, 미저장 안내 | PASS |
| Chromium 콘솔 error/warn | 관측 오류 없음 |
| 작업 전 기존 파일 41개 SHA-256 비교 | 공통 `app.js`와 UI 문서 2개만 변경, 다른 기존 변경사항 유지 |

브라우저 검증은 앱 내 Chromium과 정적 서버에서 수행했다. 외부 서비스 접속, 실제 로그 저장 또는 파서 실행 성공을 의미하지 않는다.

### 7.4 Windows / Linux 범위 확장 (2026-09-21)

사용자 요청에 따라 수집 목표를 Windows/Linux의 OS·보안·서비스·애플리케이션 로그로 구체화했다. 수집 대상·제약·향후 검증 계약은 [OS 로그 수집 범위](os_log_collection_scope.md)를 따른다. 현재는 A단계 데모 범위만 확장한다.

운영체제 필터와 컬럼, 채널/파일/저널 출처 검색·정렬·상세를 추가했다. Windows 24건, Linux 54건, 클라우드 API 6건, 미확인 6건을 구분한다. 이벤트 채널 예시에는 `winlog.channel`, 파일 예시에는 `log.file.path`가 있으며 원문은 실제 수집 결과가 아니다. 로그에 없는 사용자/IP/결과는 미관측/미확인이다. 수집 기간은 기존 고정 스냅샷을 유지하므로 Windows 예시는 전체 기간에서 확인할 수 있다.

확장 자동 테스트 9개 PASS: 운영체제 결합 필터, 출처 검색, 채널/파일 필드 대응, OS/출처 정렬 및 기존 검색·정렬·결측 보존을 검사했다. 브라우저에서 Windows 이벤트 상세, Linux 저널 필터, 조합 결과 없음, Windows 파일 경로 검색을 확인했다.

# Cloud SOC Phase A UI Decisions

작성일: 2026-09-10. 상태: 사용자 검토용 A-1 명세 및 A-2 정적 프로토타입 구현.

2026-09-14 추가 결정: 사용자의 한국어 표시 요청에 따라 두 화면의 표시 언어를 한국어로 변경한다. 관제 현황/사건 조사, 모든 메뉴·탭·필터·상태·미저장 안내를 한국어로 제공하되 최초 도식의 배치는 유지한다. 기존 영어 용어는 아래 설계 기록의 참조 명칭이다. 내부 상태 코드, URL 값, 규칙 ID, 로그 원문 및 정규화 데이터는 번역하지 않는다. 기존 데모/미연결 표시의 의미와 A단계의 저장 불가 범위는 그대로 유지한다.

2026-09-21 추가 결정: 사용자 요청으로 **통합 로그** 정적 화면을 추가한다. 화면 3개, 메뉴 9개로 확장하며 이 범위에 한해 아래 최초 두 화면/8개 메뉴 결정을 대체한다. A-1/A-2 화면 검토 범위만 확장하고 백엔드·수집·실제 파서 구현은 시작하지 않는다. 상세는 8절을 따른다.

## 1. 결정 기준

시각 디자인과 패널 배치의 최우선 기준은 사용자가 첨부한 **Cloud SOC Mini SIEM 아키텍처 및 대시보드 도식화 이미지**다. 새로운 디자인을 제안하거나 6개 업무 페이지를 동시에 구현하지 않는다.

의미/업무 흐름 검토에는 아래 기존 문서를 사용한다. 기존 문서와 코드, 현재 Kibana 화면은 변경하지 않는다.

- `siem_product_requirements.md`: 제품 목적, 업무 객체, 수용 기준.
- `siem_reference_research.md`: SIEM/SOC 제품의 업무 패턴.
- `analyst_workflow.md`: 업무 선택, 이유, 근거, 관련 활동, 판단의 흐름.
- `dashboard_wireframes.md`: 패널 의미와 데이터 계약.
- `data_source_matrix.md`, `detection_coverage.md`: 실제 관측 가능성과 탐지 범위의 구분.
- `siem_architecture.md`: 수집/저장/처리/시각화/업무 계층 분리.
- `implementation_roadmap_v2.md`: B 이후 데이터/업무 기능의 의존성 및 게이트.

## 2. 이미지에서 반영한 UI 결정

| 결정 | 구현 |
| --- | --- |
| 분석가 업무의 시작점은 Mission Control | 건강도와 작은 KPI 다음에 큐를 먼저 배치하고 차트는 하단 맥락으로 제한 |
| 조사 화면은 Investigation Workbench | 사건 제목/Severity/Status/Owner, 6개 조사 탭, 밝은 본문 |
| Overview는 2열 | 왼쪽 Detection Reason + Related Entities, 오른쪽 Summary + Questions + Notes + Verdict |
| Navigation은 8개 메뉴 | Mission Control/Investigation만 실제 화면, 나머지는 Placeholder |
| Compact Enterprise UI | Navy/Slate, Blue 선택, 얇은 경계, 작은 Radius, 표 중심. Neon/지도/대형 게이지 없음 |
| Evidence와 Related는 다름 | Timeline에 별도 배지, 근거 선택 후 동일 참조의 Raw 표시 |
| 분석가가 판단을 입력 | 입력 자체는 가능하나 실제 상태 변경/저장은 없으며 Save에 NOT SAVED 안내 |
| Kibana와 SOC 업무 화면 분리 | Kibana는 기존 읽기 전용 분석/Discover의 연결 지점 |

화면별 필드, 컬럼, 필터, 탭, 클릭 동작, 결측 상태, 반응형 규칙은 `ui_specification.md`에 기록한다.

## 3. 도식과의 의도적인 차이

- 도식의 예시 숫자를 그대로 복사하지 않고, 실제 fixture 5개 Incident와 일치하는 기본 KPI `5 / 2 / 2 / 2 / 3`을 쓴다. Alert는 별도의 3개다.
- 데모/미연결 배너와 Demo State 선택기를 추가한다. Production은 반드시 `(DEMO)`를 함께 표시한다.
- 도식의 첫 사건은 큐의 New / Unassigned 상태로 조사 화면에 들어간다. 화면 이동만으로 Investigating / analyst01이 되었다고 가장하지 않는다.
- 도식의 우선순위/오래된 업무 선택 취지에 따라 큐를 Severity, Age 순서로 정렬한다. 따라서 그림과 행의 순서는 다를 수 있다.
- 오해할 수 있는 표현을 조사 가설로 바꾼다. 정책 변경 사례의 제목/이유도 일치시킨다. Summary는 침해 확정문을 쓰지 않는다.
- 실제 공격자처럼 보이는 IP 대신 `192.0.2.*`, `198.51.100.*`, `203.0.113.*` 예시를 쓴다.
- Raw/Timeline의 시간은 선택한 근거와 맞춘다. 기본 사건은 13:01:12~13:04:37의 근거 12건과 이후 합성 맥락으로 표현한다.
- Cloud 자원을 Host로 추정하지 않는다. 해당 Evidence의 Host는 Not observed, Entity의 Host는 관측되지 않았다는 안내다.
- 작은 도식보다 큰 브라우저 화면에 맞춰 설명, 데모 ID, 입력의 비영속성, 오류 상태를 읽을 수 있는 여백을 둔다. 패널의 업무 순서는 바꾸지 않는다.

## 4. 데모 데이터 계약

이번 사용자 요청은 행/차트/근거를 포함한 합성 데이터를 명시적으로 허용한다. 따라서 이전의 보수적인 빈 화면 중심 방향보다 **이번 정적 Prototype 요청**을 우선한다. 운영 데이터와의 혼합이나 실제 데이터로 위장하는 것은 허용하지 않는다.

- `demo-data.js`에는 5개 Incident, 3개 미분류 Alert가 있고 각각 별도 ID/대상/이유/근거를 갖는다.
- 스냅샷은 `2026-08-31 13:17:00 +09:00`이다. Header 시계만 실제 현재 UI 시각이며 사건 Age/원문 시각과 구분한다.
- Linux 인증 형식도 합성 문자열이다. Cloud/Host 원문은 명시적인 `prototype: true` JSON이며 실제 OCI Audit payload나 수집된 Host 로그가 아니다.
- AUTH/CLOUD/SYSTEM Rule 이름 전체가 UI fixture다. 기존 AUTH-001과 이름이 같아도 실제 평가 결과나 배포 상태를 뜻하지 않는다.
- Data Confidence 3/3, 2m, OK는 건강도 계측이 아닌 `DEMO STATUS`다. 실제 소스 3개가 구현되었다고 주장하지 않는다.
- 차트 숫자와 severity 분할은 레이아웃 샘플이다. 큐나 근거에서 계산한 통계가 아니며 쿼리 필터와 연결되지 않는다.
- 관측 근거는 `DEMO-RAW-*` 참조이며 Elasticsearch 식별자로 사용하지 않는다. 무결성, 보존 기간, 수집 출처 검증은 미연결이다.
- History는 `DEMO ACTIVITY` 두 줄이다. 실시간 작업 이력이나 감사 로그가 아니다.
- Summary의 관련 활동과 Cloud Resource 관계는 연구할 화면 흐름을 위한 가설이다. 동일 사람/동일 자원 또는 인과관계가 확인된 것으로 해석하지 않는다.

## 5. 범위와 미연결 영역

이번 구현은 `prototype/`과 문서 2개로 끝난다. 프레임워크, 빌드 체인, 패키지 설치, Python 코드, API, DB, 규칙, 매핑, 수집 설정은 추가하지 않는다. commit/push/reset/rebase도 수행하지 않는다.

| 영역 | Phase A 동작 | 실제로 없는 기능 |
| --- | --- | --- |
| 데이터 조회 | JS 배열 검색/필터 | Elasticsearch 또는 SOC API 호출 |
| 수집 건강도 | 고정 데모 값 또는 상태 카드 | Source registry, heartbeat, pipeline 계측 |
| 탐지 설명 | 합성 Rule snapshot과 근거 | Rule 평가, DetectionRun, 재현 검증 |
| Incident/Alert | 독립 fixture와 페이지 이동 | 실제 생성/그룹화/수동 연결/중복 방지 |
| Workflow | 페이지 메모리의 입력 | 담당자 인수, 서버 상태 변경, 저장/재개/충돌 제어 |
| Notes/Verdict/History | 입력 및 NOT SAVED 모달 | 영속 저장, 감사 이력, 사용자 서명 |
| 권한 | Permission Denied 화면 예시 | 인증, RBAC, tenant 권한 검증 |
| Entity/Hunting/Coverage/Health | 메뉴/설명 | 검색 서비스, 엔티티 해소, 실제 커버리지 측정 |
| Kibana | 역할 설명 | 실제 Discover deep link 또는 Saved Object 수정 |

HTML에는 `connect-src 'none'` CSP를 설정해 스크립트의 네트워크 연결을 차단한다. Form 제출, 외부 base/object도 금지한다. 이는 프로토타입의 미연결 범위를 유지하는 보조 장치이지 실제 제품의 보안 설계 완료를 뜻하지 않는다. 서버/브라우저의 로컬 정적 파일 읽기는 별개다.

## 6. 이후 단계의 의존성만 기록

아래 내용은 기존 로드맵의 기능 경계이며 **이번에 구현하거나 자동 착수하지 않는다**.

| 단계 | 실제 UI를 뒷받침할 기능 |
| --- | --- |
| B | 완전/증분 조회, 시간과 lineage/Raw 참조, 재시작/부분 실패 처리, Source registry와 기본 Health 계측 |
| C | Authentication + Cloud Audit 2도메인 실데이터 검증, 설명 가능한 Detection/Alert snapshot 및 근거 manifest, Rule/Run registry |
| D | 인증/인가, Incident/AlertReview와 연결 모델, 메모/판단/감사 저장, 두 사용자 충돌, exact evidence에서 Raw까지의 Workbench 수직 흐름 |
| E | 실제 큐/KPI 범위 일치, Mission Control, Entity/Hunting/Coverage/Health 통합 및 사용자 수용 검증 |

Prototype의 `Triage`/Owner 후보값, fixture 필드, 예시 규칙을 실제 backend 계약으로 그대로 복사하지 않는다. 업무 상태 전이, AlertReview와 Incident 분리, 데이터 생산자/시간/권한/보존 계약, 승인된 Cloud 수집 범위는 별도 합의가 필요하다.

## 7. Phase A 판정과 검토 요청

| 대상 | 판정 | 근거/한계 |
| --- | --- | --- |
| A-1 UI Specification | PASS | 두 화면의 도식 기반 구조/역할/클릭/상태/반응형 명세를 작성하고 구현과 대응. 최종 UX 승인은 사용자 검토 대기 |
| A-2 Static Prototype | PASS | 브라우저에서 큐에서 조사/근거/원문/입력까지의 흐름 및 NOT SAVED 동작 검증. 실제 SOC 기능 완료 판정이 아님 |
| 로드맵 A 전체 승인 | 미판정 | 수집 대상, 데이터 생산자/권한, 저장소, 실제 업무 계약까지 모두 승인된 것으로 간주하지 않음 |
| Phase B 이후 | 미착수 | Backend/수집/탐지/저장 기능 변경 없음 |

다음 단계는 사용자가 Prototype을 열어 **업무 큐의 정보 우선순위, 조사 탭 순서, Detection Reason 가독성, Notes/Verdict 위치**를 검토하는 것이다. 검토 피드백 없이 Phase B를 시작하지 않는다.

## 8. 통합 로그 화면 확장 결정

사용자의 여러 환경 로그를 파싱된 엑셀형 목록으로 확인하고 싶다는 요청을 기존 정적 UI 범위에 적용한다. 일반 활동, 오류, 파싱 실패까지 함께 탐색하며 탐지된 경보 목록으로 제한하지 않는다. 관제 현황과 사건 조사의 목적은 바꾸지 않는다.

| 결정 | 현재 구현과 한계 |
| --- | --- |
| 별도 통합 로그 페이지 | 기존 셸에 메뉴 하나 추가, 한국어 UI와 네이비 디자인 유지 |
| 엑셀형 읽기 전용 표 | 필터, 열 정렬, 페이지 이동, 고정 ID 열, 가로 스크롤. 스프레드시트 편집기/파일 내보내기는 아님 |
| 행별 상세 | 파싱 필드, 원문, 수집 정보 탭. 파싱 실패도 원문 유지 |
| 여러 환경과 소스 | Windows/Linux 확장 후 90건 독립 합성 fixture. 실제 OCI/AWS 또는 다른 플랫폼 수집 지원을 뜻하지 않음 |
| 파싱 품질 구분 | 완료/일부 필드 누락/실패. 파싱 완료와 안전 판정은 별개 |
| 결측 보존 | 이벤트 시각/결과 누락을 숨기거나 수집 시각으로 임의 대체하지 않음 |
| 기존 구현 보호 | Python, Elasticsearch, API, Filebeat, Docker, 탐지 규칙 및 기존 사건/경보 fixture 변경 없음 |

실제 연동 단계에서는 승인된 환경/계정/서비스별 수집 소스 목록, 인증과 접근 범위, 파서별 필드 계약, 원문 참조, 보존 기간, 민감정보 마스킹, 실패 로그 처리와 조회 권한을 먼저 정해야 한다. 대용량 검색은 서버 필터/정렬/페이지 이동과 집계 범위 일치가 필요하며 클라이언트 데모의 성능을 운영 성능으로 해석하지 않는다. 이 의존성을 이유로 이번에 수집기나 백엔드를 자동 구현하지 않는다.

2026-09-21 후속 요구: Windows/Linux의 다양한 OS·보안·서비스·애플리케이션 로그를 수집 대상으로 삼는다. OS와 클라우드 플랫폼을 분리하고 OS 필터·출처 컬럼·수집 대상 설명을 UI에 반영했다. 상세 요구사항은 [OS 로그 수집 범위](os_log_collection_scope.md)에 기록했다. 미생성/비활성/접근 불가 로그까지 수집한다고 보장하지 않는다. 실제 수집기 설치, 감사 정책 변경, 권한 확대, 파서 또는 Python/API 수정은 이번에 하지 않는다.

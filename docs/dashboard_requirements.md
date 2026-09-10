# Cloud SOC 대시보드 요구사항

기준일: 2026-09-10. 상태: 구현 전 검토안. 이번 작업은 문서 작성만 수행한다.

관련 문서: [데이터 요구사항 및 Gap Analysis](dashboard_data_requirements.md), [단계별 구현 계획](dashboard_implementation_plan.md).

## 1. 제품 목적과 범위

Cloud SOC는 클라우드 환경의 보안 이벤트를 조사하는 소규모 SIEM이다. SSH Brute Force는 첫 번째 탐지 사례이지 제품 전체가 아니다. 대시보드의 목적은 공격 그래프 전시가 아니라 **우선 처리할 경보 선택, 근거 조사, 판단 기록, 수집 이상 확인**이다.

설계 순서: 분석가의 질문 -> 화면/업무 흐름 -> 데이터 -> 필드 -> 탐지 조건 -> 필요한 소스 -> 기존 코드 확장 -> 화면 구현.

| 분석가의 질문 | 업무 화면 | 완료 행동 |
| --- | --- | --- |
| 지금 무엇부터 확인해야 하는가? | SOC Operations | 우선순위 경보 선택 및 담당자 배정 |
| 왜 발생했고 공격 전후에 무엇이 있었는가? | Alert Investigation | 근거와 주변 이벤트를 비교 |
| 같은 시스템/계정/IP에 다른 활동이 있는가? | Entity Investigation | 관련 경보와 이벤트를 추가 조사 |
| 정탐인가, 오탐인가? | Alert Investigation | 판단 이유와 처리 상태 저장 |
| 로그가 안 오는 것인가, 활동이 없는 것인가? | Data Source Health | 수집기/전송/정규화/탐지 문제 구분 |

현재 소스는 Ubuntu SSH 인증 로그다. OCI Audit는 클라우드 계정의 관리 작업을 조사할 필요가 생기는 단계에서 추가한다. 웹 공격, 자동 차단, SOAR, 머신러닝, 지도 중심 화면, 근태/출퇴근 권한 시스템은 이번 범위에 넣지 않는다.

## 2. 화면 구조와 구현 경계

```text
SOC Operations
  -> Alert Investigation
     -> Host / User / Source IP Entity Investigation
        -> Event Timeline
           -> Normalized Event -> Raw Event
     -> 판단, 상태, 담당자, 메모 저장

Data Source Health
  -> 특정 수집원/단계의 상태
     -> 수집 이벤트와 처리 실패 근거
```

- 첫 단계는 기존 Kibana로 읽기 전용 운영 화면을 검증한다. 기본 대시보드가 있다는 사실과 분석가 워크플로가 구현되었다는 사실은 다르다.
- 최종 4개 업무 화면은 공통 탐색/필터를 가진 얇은 SOC 웹 화면으로 연결하는 안을 권장한다. ES 조회는 기존 Python 계층을 재사용하고, Kibana Discover는 원본 탐색 도구로 남긴다.
- 상태/담당자/메모를 저장하는 기능에는 별도 서버와 저장소가 필요하다. 일반 Kibana 시각화만으로 현재의 사용자 정의 `security-alerts`와 분석 이력이 자동 연결된다고 가정하지 않는다.
- 프런트엔드 프레임워크, 메시지 브로커, 별도 검색 엔진을 지금 추가하지 않는다. 화면을 먼저 검증한 뒤 필요한 최소 웹 계층만 구현한다.

## 3. 공통 표시·조회 규칙

### 필터와 시간

전역 필터: 조직, Time Range, Severity, Alert Status, Host, User, Source IP, Data Source, Rule. 조직은 서버에서 강제하는 조회 범위이며 UI 필터만으로 격리하지 않는다.

- 기본 탐색 시간은 최근 24시간. 저장/조회는 UTC, 화면은 표시 시간대와 절대 시각을 함께 제공한다. 기본 표시 시간대는 Asia/Seoul이다.
- 경보의 발생 시각은 현재 `@timestamp`, 최초/최종 근거 시각은 `cloud_soc.window_start/window_end`다. 생성 시각과 혼동하지 않는다.
- 운영 화면은 기본적으로 **모든 미종결 경보**를 대상으로 한다. 이 모드에서는 경보 큐, Open/Critical/High/Investigating KPI, Entity 우선순위 표에 시간 제한을 적용하지 않고 `전체 미종결` 배지를 표시한다.
- 사용자가 `선택 기간의 경보` 모드로 전환하면 큐와 해당 KPI에 동일한 발생 시간 조건을 적용한다. 오래된 미종결 경보가 화면 밖에 남아 있다는 안내를 유지한다.
- 추이는 선택 기간, New Alerts는 고정 최근 1시간, Health는 현재 상태다. 각 패널의 시간 기준을 제목/배지로 구분한다.
- `New Alerts - Last 1H`는 상태가 New인 건수가 아니라 **최초 생성된 경보 수**다. 상태 필터를 적용하지 않는다는 점을 표시한다.
- 원본/정규화 이벤트에는 경보의 Status/Assignee 필터를 그대로 적용하지 않는다. 페이지 이동 시 적용 불가능한 필터를 숨겨서 버리지 말고 비적용 목록으로 알린다.
- Drill-down에서는 조직, Entity 식별자, UTC 절대 시간 범위, 원래 화면의 필터를 전달한다. 상대 시간 `now`를 매 페이지에서 새로 계산하여 조사 범위가 움직이지 않게 한다.

### 값의 의미와 품질

- `0`은 정상 조회 결과가 실제 0일 때만 사용한다. 필드 없음은 `미수집`, 미구현은 `미지원`, 조회 실패는 `조회 실패`, 부분 결과는 `불완전`으로 표시한다.
- 경보의 `event_count`는 현재 **규칙에 일치한 로그 이벤트 수**다. 인증 시도 수, 공격자 수, 피해 건수로 바꿔 부르지 않는다.
- SSH 로그의 `from ... port ...`는 클라이언트 Source Port다. Destination Port를 22로 임의 채우지 않는다.
- 경보의 타깃이 여러 개이면 `복수 Host (N)`/`복수 User (N)`와 목록을 표시한다. 첫 번째 대상을 대표 타깃으로 단정하지 않는다.
- 위험 점수 산정은 아직 없다. 초기에는 `Risk Score: 미산정`으로 표시하고 심각도/미종결 경보 수/최근 활동을 보여준다. 알 수 없음을 점수 0으로 바꾸지 않는다.
- High Risk Entity 패널의 초기 명칭은 `우선 조사 Host/User/Source IP`로 한다. 정렬 기준은 최고 미종결 심각도, 해당 심각도 경보 수, 전체 미종결 경보 수, 최근 활동 순이다. 공격 성공 확률을 뜻하지 않는다.
- `인증 실패 후 성공`이라는 시간적 연관만으로 침해 성공을 단정하지 않는다. 동일 계정/호스트 여부, 정상 사용자 설명, 원본 근거를 확인한다.
- 검색 결과에는 조회 기준 시각, 데이터 최신 시각, 완료/부분 여부를 제공한다. 수집 또는 탐지 지연이 있으면 경보 0건 옆에도 경고를 표시한다.

### 사용성과 보호

- 텍스트 심각도와 상태 배지를 함께 사용한다. 색상만으로 구분하지 않는다.
- 표는 열 고정, 정렬, 페이지 이동, 복사 가능한 식별자, 키보드 접근을 지원한다. 작은 화면에서는 필수 열을 우선하고 상세 정보는 펼친다.
- 자동 갱신은 설정 가능하게 하고 마지막 갱신 시각을 표시한다. 선택한 행이나 작성 중인 메모를 갱신 때문에 잃지 않는다.
- 로그/메모는 신뢰할 수 없는 텍스트로 렌더링한다. HTML 실행, 토큰 노출, 임의 ES 쿼리 실행을 허용하지 않는다.
- 외부 공개 전 인증, 역할별 인가, ES 최소 권한, TLS를 적용한다. 현재 localhost 개발 구성의 인증 비활성화는 운영 배포 허용을 의미하지 않는다.

## 4. SOC Operations

**목적:** 교대 근무 중 미처리 경보를 분류하고 조사할 사건을 선택한다.

**사용자:** 관제 분석가, 담당자 배정 및 진행 상황을 확인하는 리더.

**업무 흐름:** 수집 이상 배지 확인 -> 미종결 큐 확인 -> 심각도/관련 Entity/시각 확인 -> 경보 선택 -> 조사 화면 이동.

레이아웃: 전역 필터와 범위 배지 -> 소형 KPI -> 낮은 높이의 추이/순위 -> 화면의 주 영역인 Active Alert Queue. 큐를 접힌 영역이나 긴 그래프 아래에 숨기지 않는다.

| ID | Panel | Visualization Type | 표시 필드·필요 데이터 | 필터·클릭 동작 |
| --- | --- | --- | --- | --- |
| OPS-01 | Open Alerts | 숫자 + 범위 배지 | New/Investigating 상태의 경보 수 | 현재 큐 범위 적용; 클릭 시 미종결 큐 |
| OPS-02 | Critical / High Alerts | 숫자 2개 + 심각도 텍스트 | 현재 큐 중 critical/high 경보 수 | 각 심각도로 큐 필터; severity 선택 시 교집합임을 표시 |
| OPS-03 | New Alerts - Last 1H | 숫자 + 생성 기준 안내 | 최초 생성 시각 기준 최근 1시간 경보 수 | Status/발생 시간 필터 제외; 클릭 시 생성 시각 범위 검색 |
| OPS-04 | Investigating | 숫자 | 현재 큐 범위 중 Investigating 경보 수 | 해당 상태 큐로 이동 |
| OPS-05 | Data Source Health | 상태 요약 + 경고 링크 | 등록 수집원 수, 이상/미확인 수, 처리 단계 상태 | 조직만 공유; Health 화면으로 이동 |
| OPS-06 | Alert Trend | 시간대별 막대 또는 선 | 선택 기간 경보 수, 심각도, 발생 시각 | 시간 구간 선택 시 큐를 선택 기간 모드로 전환 |
| OPS-07 | Top Detection Rules | 순위 표 또는 가로 막대 | Rule ID/Name, 선택 기간 경보 수, 최고 심각도 | 규칙 클릭 시 같은 조건의 경보 큐 |
| OPS-08 | 우선 조사 Hosts | 순위 표 | Host 식별자/이름, 미종결 경보 수, 최고 심각도, 최근 활동 | Host Entity Investigation |
| OPS-09 | 우선 조사 Users | 순위 표 | 계정 식별 범위/이름, 미종결 경보 수, 최고 심각도 | User Entity Investigation; 동명이인 계정 분리 |
| OPS-10 | 우선 조사 Source IPs | 순위 표 | IP/네트워크 범위, 미종결 경보 수, 관련 타깃 수 | Source IP Entity Investigation |
| OPS-11 | Active Alert Queue | 정렬·페이지 이동 가능한 표 | Severity, 발생 시각, Status, Rule Name, Source IP, Target Host, User, Event Count, First/Last Seen, Assignee | 행 클릭 시 경보 조사; Entity 링크는 해당 Entity 조사 |

큐 기본 정렬: critical -> high -> medium -> low -> informational -> 미지정, 각 단계 안에서는 오래 대기한 생성 시각 우선. 생성 시각이 없는 과거 경보는 발생 시각으로 정렬하되 기준 차이를 표시한다.

초기 읽기 전용 검증에서는 OPS-06/07 및 OPS-11의 기존 필드만 제공할 수 있다. 상태가 없으므로 이때 표 이름은 `경보 목록`이다. Open/Investigating/담당자 기능이 있는 것처럼 보이지 않게 비활성화한다.

**완료 기준:** KPI와 큐의 동일 범위 합계 일치, 오래된 미종결 경보 접근 가능, 페이지를 넘겨도 누락 없음, 경보와 Entity 링크의 조직/시간 범위 보존.

## 5. Alert Investigation

**목적:** 하나의 경보가 발생한 이유를 검증하고 판단과 처리 이력을 남긴다.

**사용자:** 담당 분석가, 검토자.

**업무 흐름:** 요약 확인 -> 탐지 근거 확인 -> 전후 이벤트 비교 -> Entity 확장 조사 -> 원문 확인 -> 판단/메모/상태 저장.

필터: 경보 ID는 고정. Timeline에는 시간 확대/축소, Host, User, Source IP, 결과, `탐지 근거만/주변 이벤트 포함`을 제공한다. 경보 선택 당시의 탐지 근거는 주변 이벤트 필터로 조용히 사라지지 않게 별도 탭으로 유지한다.

| ID | Panel | Visualization Type | 표시 필드·필요 데이터 | 클릭·Drill-down |
| --- | --- | --- | --- | --- |
| INV-01 | Alert Summary | 필드 표 + 심각도 배지 | Alert ID, Rule ID/Name, Severity, Risk Score, First/Last Seen, 생성 시각, Source IP, Target Host/User, Service, Destination Port, Event Count | Entity 값 선택 시 해당 조사 화면; 미수집 값은 링크 없음 |
| INV-02 | Detection Reason | 설명 + 조건 표 | 규칙 설명/버전, 실제 그룹 값, 일치 이벤트 수, 임계값, 시간창, MITRE 정보 | 근거 이벤트 목록으로 이동 |
| INV-03 | Event Timeline | 시간순 목록 + 선택적 시간축 | 발생 시각, action/outcome, Source IP, Host/User, 근거 여부 | 이벤트 상세; 기본 근거 구간 앞뒤 5분, 사용자가 확장 |
| INV-04 | Related Events / Raw Evidence | 검색 표 + 원문 패널 | 정규화 문서와 원본의 index/ID, message, event.original, 원본 수집 메타데이터 | 정확한 원본 문서 열기; Kibana Discover 보조 링크 |
| INV-05 | Analyst Workflow | 입력 폼 + 변경 이력 표 | Status, Verdict, Assignee, Notes, 변경자/시각/이전 값 | 저장 결과/충돌 안내; 담당자가 큐로 복귀 |

Source Geo는 선택 기능이며 GeoIP 보강 없이는 표시하지 않는다. IP 위치는 공격자의 실제 위치를 입증하지 않는다.

### 탐지 이유 계약

현재 규칙은 같은 Source IP의 300초 이내 인증 실패 이벤트 10건 이상을 찾는다. 후속 구현에서는 조직을 추가로 격리하되, 여러 Host에 걸친 Source IP 집계라는 의미를 몰래 변경하지 않는다.

이유 문장은 저장된 조건/실제 값으로 만든다. 예: `조직 A의 IP X에서 300초 창 안에 일치 이벤트 12건이 관측되어 임계값 10건을 충족함`. 현재 고정 메시지만으로 상세 근거를 대체하지 않는다.

`탐지 근거`는 탐지 당시 사용한 문서 참조와 규칙 스냅샷이고, `주변 이벤트`는 현재 검색 결과다. 둘을 구분해야 늦게 들어온 이벤트나 규칙 수정으로 과거 경보의 이유가 바뀌지 않는다. 증거가 보존 기간 경과로 삭제되면 해당 사실과 남아 있는 참조를 표시한다.

### 분석 상태 계약

| 항목 | 규칙 |
| --- | --- |
| Status | New, Investigating, Closed |
| Verdict | True Positive, False Positive, Benign; 조사 중에는 미정 허용 |
| 상태 전환 | New -> Investigating -> Closed; 필요하면 New -> Closed; 재개는 Closed -> Investigating |
| 종결 조건 | Verdict와 판단 이유 필수. True Positive는 대응 결과 또는 인계 내용을 메모에 기록 |
| Verdict 의미 | True Positive: 보안 위협 판단; False Positive: 탐지 조건/데이터 문제; Benign: 조건은 맞지만 승인된 정상 활동 |
| Assignee | 서버에 등록된 분석가 ID, 미배정 허용; 임의 문자열을 실제 사용자 신원으로 간주하지 않음 |
| Notes | 작성자/시각을 포함한 추가형 이력; 수정은 정정 항목으로 기록 |
| 재개 | 이전 판단을 이력에 남기고 현재 Verdict는 미정으로 변경; 재개 사유 필수 |
| 충돌 | 버전 비교로 동시 수정 감지; 다른 분석가의 변경을 덮어쓰지 않음 |
| 기존 경보 | 상태 미등록과 New를 구분; 명시적인 초기 등록/마이그레이션 후 New 부여 |

자동 차단이나 외부 메시지 전송은 상태 저장의 부수 효과로 실행하지 않는다. 탐지 엔진이 재실행되어도 분석 상태와 메모를 덮어쓰면 안 된다.

**완료 기준:** 저장된 경보 하나에서 정확한 근거 문서와 원본까지 도달, 주변 이벤트와 근거 구분, 새로고침/프로세스 재시작 후 처리 이력 유지, 동시 수정 충돌 검증.

## 6. Entity Investigation

**목적:** 경보를 넘어 동일한 시스템·계정·IP의 활동을 연결한다.

**사용자:** 추가 조사를 수행하는 분석가.

**업무 흐름:** 식별 범위 확인 -> 인증 활동과 관련 경보 확인 -> 관련 Entity 선택 -> 시간대 확장 -> 원본 확인.

필터: Entity 종류/키, 조직, 시간 범위, 데이터 소스, action/outcome. 경보 탭에만 Severity/Status/Rule을 추가 적용한다.

| ID | Panel | Visualization Type | 표시 필드·필요 데이터 | 클릭·Drill-down |
| --- | --- | --- | --- | --- |
| ENT-01 | Entity Profile | 요약 표 | 종류, 안정적인 키, 이름, 식별 범위, 최초/최종 관측, Risk Score 또는 미산정 | 식별 정보 복사; 범위 변경 시 별도 Entity로 이동 |
| ENT-02 | Authentication Activity | 숫자 + 결과별 시간 추이 | 인증 이벤트 전체 수, ssh_login 성공/실패 이벤트 수, invalid_user 이벤트 수 | 해당 이벤트 조건으로 Timeline 필터 |
| ENT-03 | Recent / Open Alerts | 표 + 미종결 수 | 경보 ID, Rule, Severity, Status, First/Last Seen | Alert Investigation |
| ENT-04 | Related Entities | 연관 목록 표 | Host에서는 User/IP, User에서는 Host/IP, IP에서는 대상 Host/User; 관계별 이벤트/경보 수 | 선택한 Entity Investigation |
| ENT-05 | Event Timeline | 시간순 표 | 발생 시각, Host, User, IP, action/outcome, service, 소스, 경보 근거 연결 | 정규화 상세 -> 원본; 기간 확장 |

### Entity별 해석

- Host: `organization.id + host.id`가 기본 키다. 이름만 있는 기존 데이터는 조직/수집원/이름 기반 임시 키로 표시하며 이름 변경·중복을 해결했다고 주장하지 않는다.
- User: SSH의 로컬 계정은 조직 + Host 키 + 사용자명 범위로 구분한다. 서로 다른 서버의 `root`를 동일 인물로 합치지 않는다. 존재하지 않는 계정 시도는 `대상 계정명, 존재 미확인`으로 표시한다.
- Source IP: 조직 + 네트워크 범위 + 정규화된 IP 주소로 묶는다. 사설 IP는 서로 다른 네트워크에서 충돌할 수 있고, 공인 IP도 NAT/프록시 때문에 한 사람을 뜻하지 않는다.
- First/Last Seen은 **조회 기간 내 관측값**이다. 전체 보존 기간을 조회하지 않았다면 생애 최초/최종 활동이라고 쓰지 않는다.
- 한 경보가 Host 여러 개와 연결되면 각 Host의 경보 수에 포함될 수 있다. Entity별 수의 합은 전체 경보 수와 같지 않을 수 있다.

**완료 기준:** 동일 이름의 서로 다른 Host/User가 섞이지 않음, 관계 쌍 보존, 경보/이벤트 집계의 범위와 중복 의미 설명, 원본 Drill-down 가능.

## 7. Data Source Health

**목적:** 무활동, 수집 장애, 정규화 오류, 탐지 지연을 분리하여 관제의 신뢰도를 판단한다.

**사용자:** 관제 분석가와 수집 파이프라인 운영자.

**업무 흐름:** 등록된 수집원 확인 -> 마지막 수신/Heartbeat/처리 결과 비교 -> 이상 단계 확인 -> 해당 이벤트/실패 근거 조사.

필터: 조직, 수집원, Host, 데이터셋, 상태, 시간 범위. Severity/Alert Status는 적용하지 않는다.

| ID | Panel | Visualization Type | 표시 필드·필요 데이터 | 클릭·Drill-down |
| --- | --- | --- | --- | --- |
| HEALTH-01 | Data Source Status | 상태 표 | Data Source, Host, Dataset, Status, Last Event Time, Last Ingested Time, Events/Minute, Total Events, Delay, Heartbeat | 수집원 상세, 원본 이벤트 검색, 설정된 기대 주기 확인 |
| HEALTH-02 | Event Ingestion Trend | 수집원별 시간 추이 | 중앙 수신 시각 기준 원본 건수, 분당 이벤트 수, 관측 공백 | 구간 클릭 시 해당 소스/수신 시간의 원본 목록 |
| HEALTH-03 | Pipeline Health | 단계별 상태 표 | Collector/Transport/Normalizer/Detector 최근 확인 시각, 처리 성공·미지원·실패 수, 대기량/체크포인트 | 실패 참조, 최근 실행 요약; 로그 없음과 프로세스 장애 구분 |

### 지표 정의

| 지표 | 정의 |
| --- | --- |
| Last Event Time | 해석 가능한 원본 발생 시각의 최댓값. 미파싱 소스는 미확인 |
| Last Ingested Time | 중앙 저장소에서 기록한 마지막 수신 시각 |
| Events/Minute | 원본의 중앙 수신 시각 기준 직전 완료된 60초 구간 문서 수 |
| EPS | 별도 표시할 때만 같은 구간 건수 / 60; Events/Minute와 단위를 섞지 않음 |
| Total Events | 선택 기간의 원본 문서 수. 평생 누계 아님 |
| Delay | 소스 발생 -> 중앙 수신 지연의 최근 구간 p95. 발생 시각/시계 신뢰성 없으면 N/A |
| 수신 경과 | 현재 시각 - Last Ingested Time; 전송 지연과 다른 지표 |
| 처리 실패율 | 실패 / 처리 시도. 미지원 로그는 별도 집계; 시도 0이면 N/A |

### 상태 판정

소스 등록 정보에는 고유 ID, 조직, Host, 데이터셋, 활성 여부, 수집 방식, 기대 주기, 무활동 허용 시간, Heartbeat 정책, 시간대를 둔다. 아직 한 건도 안 온 수집원도 목록에 있어야 한다.

| 상태 | 판정 조건 |
| --- | --- |
| NOT_CONFIGURED | 계획만 있고 연동되지 않음. 정상/이상 수집원 분모에서 제외 |
| NEVER_SEEN | 등록·활성 상태지만 첫 수신이 아직 없음 |
| UNKNOWN | Heartbeat/주기 정보 등 판정 근거 부족 |
| HEALTHY | 기대한 수신 또는 독립적인 생존 확인이 있고 지연 기준 이내 |
| IDLE | Heartbeat는 정상이며 활동 기반 소스에 이벤트만 없음 |
| DELAYED | 설정된 수신 주기/지연 한계를 초과했지만 생존 근거가 있음 |
| DOWN | 독립 생존 확인 실패 또는 명시적인 수집/전송 오류 근거가 있음 |

SSH 인증 로그가 5분간 없다는 이유만으로 DOWN이라고 표시하지 않는다. Heartbeat 없이 오래된 데이터만 있는 경우 UNKNOWN과 `마지막 수신 오래됨`을 함께 표시한다. 한 소스의 지원하지 않는 auth.log 메시지를 모두 Parser 장애로 취급하지 않는다.

OCI Audit/Web Access는 실제 연동 전 HEALTHY 예시 행으로 표시하지 않는다. 예상 수집량·Heartbeat·임계값은 소스별 설정이며 보편적인 정상 기준으로 하드코딩하지 않는다.

**완료 기준:** 0건 소스 표시, 유휴/장애 분리, 원본 수신과 Python 처리 지연 구분, 재처리로 수집량이 부풀지 않음, 부분 실패가 건강한 상태로 숨지 않음.

## 8. OCI Audit가 필요한 이유

현재 SSH 로그는 VM 내부 인증을 설명하지만, 클라우드 콘솔/API를 통한 권한·리소스 변경의 행위자와 대상은 설명하지 못한다.

| 업무 질문 | 사용하는 Panel | 필요한 데이터 | 도입 조건 |
| --- | --- | --- | --- |
| 의심 계정이 중요 리소스나 권한을 변경했는가? | ENT-05의 클라우드 관리 활동, INV-03의 주변 이벤트 | 클라우드 계정, 행위자 ID, 작업명, 대상 리소스, 발생 시각, 결과 | 수집할 관리 작업 목록과 정상 작업 사례 확정 |
| 누가 어떤 IP에서 변경 API를 호출했는가? | ENT-01/04/05, INV-04 | 행위자 식별자, Source IP, 요청 ID, 원본 Audit 이벤트 | API 필드의 존재/민감정보/결과 의미 검증 |
| Audit 수집이 중단되었는가? | HEALTH-01/02/03 | 수집 실행 시각, 페이지 커서, 체크포인트, 오류, 중앙 수신 시각 | API 주기와 지연 허용값 설정 |

초기에는 관리 활동 Timeline을 제공한다. 모든 변경을 공격 경보로 만들지 않는다. 특정 중요 변경에 대한 분석 요구와 정상/비정상 판정 기준을 합의한 뒤 관련 규칙 하나를 추가한다. AWS 이전 시 같은 업무 요구에 CloudTrail을 대응시키되, 공급자별 원본과 식별 범위는 보존한다.

## 9. 설계 근거

화면 분리와 경보에서 Timeline/Entity로 이동하는 작업 방식은 [Elastic Security UI](https://www.elastic.co/docs/solutions/security/get-started/elastic-security-ui)를 참고했다. 이는 현재 저장소에 Elastic Security의 기능이 이미 구현되었다는 뜻이 아니다.

클라우드 관리 활동의 수집 목적은 [OCI Audit 개요](https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm)의 API 활동·행위자·대상·결과 범위에 근거한다. 실제 수집 필드와 지원 작업은 Phase 6에서 샘플로 검증한다.

# SOC Operations 사용 및 재설치

구성 대상: Kibana 9.5.2. 2026-09-10에 실제 저장 경보를 이용해 검증한 읽기 전용 첫 화면이다. Python 파이프라인의 수정이나 새 로그 소스 추가는 포함하지 않는다.

## 1. 열기

[SOC Operations 열기](http://localhost:5601/app/dashboards#/view/e9dc5bf4-d104-44d1-b775-eceb5cfeff68)

- 대시보드 ID: `e9dc5bf4-d104-44d1-b775-eceb5cfeff68`.
- Data View: `security-alerts`, 시간 필드 `@timestamp`.
- 공통 검색식: `event.kind: "alert"`.
- 기본 기간: 2026-08-31 00:00 ~ 2026-09-01 00:00 KST. 기존 경보가 있는 날짜를 명시적으로 선택했다.
- 저장된 UTC 범위: `2026-08-30T15:00:00.000Z` ~ `2026-08-31T15:00:00.000Z`.
- Kibana의 시각 표시는 브라우저/사용자 설정을 따른다. UTC와 KST를 혼동하지 않는다.
- 자동 갱신은 일시 정지 상태다. 최근 데이터 확인 시 기간을 최근 24시간 등으로 바꾸고 필요할 때 갱신한다.

기존 `Cloud SOC 통합 보안관제 대시보드`는 수정하지 않았다. 첫 화면은 선택 기간의 저장 경보를 보여주며, 현재 공격 발생 여부나 수집 정상 여부를 보증하지 않는다.

## 2. 구성

상단 공통 필터는 심각도(`cloud_soc.severity`), 규칙(`rule.id`), Source IP(`source.ip`)다. 같은 조건이 두 KPI, 경보 목록, 추이, 규칙별 집계에 적용된다.

| Panel | 방식 | 의미 |
| --- | --- | --- |
| 선택 기간 경보 | Lens Metric, Count | 필터에 맞는 경보 문서 수 |
| High 경보 | Lens Metric, Count + high 조건 | 현재 필터와 high 조건의 교집합 |
| 조회 범위와 현재 한계 | Markdown | 과거 기간, 수집 상태 미확인, 업무 상태 미지원 안내 |
| 경보 목록 | 내장 Discover session | 최신 발생 시각순, 10행/페이지, 최대 500건 |
| 시간대별 경보 발생 | Lens 시간 막대 | `@timestamp` date histogram + 경보 Count |
| 탐지 규칙별 경보 | Lens 가로 막대 | `rule.id`별 Count, 상위 10개 |
| 지표 읽는 방법 | Markdown | 경보 수/이벤트 수/표본 한도/파이프라인 한계 안내 |

경보 목록의 열:

| 필드 | 표시 의미 |
| --- | --- |
| `cloud_soc.severity` | 경보 심각도 |
| `@timestamp` | 탐지를 촉발한 마지막 이벤트 시각 |
| `rule.id`, `rule.name` | 규칙 식별자/이름 |
| `source.ip` | 관측된 출발지 IP, 공격자 개인 식별자가 아님 |
| `cloud_soc.event_count` | 규칙에 일치한 로그 수, 로그인 시도 수가 아님 |
| `cloud_soc.window_start`, `cloud_soc.window_end` | 해당 탐지의 첫/마지막 근거 이벤트 시각 |

오른쪽 열이 보이지 않으면 목록을 가로로 스크롤한다. 행의 펼치기 버튼으로 **경보 문서**의 필드/JSON을 확인할 수 있다. 이것은 `raw-logs-*`의 인증 로그 원본까지 연결한 기능이 아니다.

## 3. 저장소 파일

- [operations.ndjson](../kibana/operations.ndjson): Kibana 공식 export API의 응답 원본. 대시보드와 참조 Data View를 포함한다. 로그 문서 데이터는 포함하지 않는다.
- [operations.dashboard.json](../kibana/operations.dashboard.json): 공식 Dashboard API용 편집 가능한 화면 정의. 내부 saved object 구조를 손으로 만든 파일이 아니다.

`operations.ndjson`은 직접 편집하지 않는다. 화면을 수정한 뒤 Kibana에서 다시 export한다. `operations.dashboard.json`은 선언형 정의이며, Kibana에서 수동 변경했다면 이 파일도 의미가 일치하도록 별도로 검토한다.

## 4. 다른 환경으로 가져오기

1. 같은 버전의 Kibana를 준비하고 `security-alerts` 데이터가 있는지 확인한다. export 파일은 실제 경보를 복사하지 않는다.
2. Kibana 검색에서 `Saved Objects`를 열고 Import를 선택한다.
3. `kibana/operations.ndjson`을 가져온다. 대시보드와 Data View 두 객체가 대상이다.
4. 기존 객체와 충돌하면 자동 덮어쓰지 말고 대상 ID/참조를 확인한다. 검증용 별도 Space 또는 새 복사본을 우선 사용한다.
5. `SOC Operations`를 열고 데이터가 있는 기간으로 변경한다. 다른 환경의 데이터가 8월 31일에 없다면 기본 화면이 0건인 것은 자연스럽다.

기존 Data View ID는 `367c8884-7e37-41c9-81ec-b63c5430c76f`다. 선언형 JSON에는 이 ID가 들어 있다. 새로운 환경에서는 NDJSON import로 참조를 함께 가져오거나, 대상 Data View ID로 선언형 정의의 모든 참조를 맞춘 뒤 API를 사용한다.

버전이 낮은 Kibana로의 import는 보장되지 않는다. 같은 버전에서 먼저 검증한다. [Saved objects export API](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-saved-objects-export).

## 5. 수정 후 다시 내보내기

프로젝트 루트에서 아래 명령은 화면 설정을 내려받아 export 파일을 갱신한다. 로그 데이터나 기존 대시보드를 수정하는 명령이 아니다. 다른 환경에서 복사본 ID가 달라졌으면 `$dashboardId`를 그 값으로 바꾼다.

```powershell
$dashboardId = 'e9dc5bf4-d104-44d1-b775-eceb5cfeff68'
$body = @{
    objects = @(@{ type = 'dashboard'; id = $dashboardId })
    includeReferencesDeep = $true
    excludeExportDetails = $false
} | ConvertTo-Json -Depth 4

Invoke-WebRequest `
    -Uri 'http://localhost:5601/api/saved_objects/_export' `
    -Method Post `
    -Headers @{ 'kbn-xsrf' = 'true' } `
    -ContentType 'application/json' `
    -Body $body `
    -OutFile '.\kibana\operations.ndjson'
```

공식 Dashboard API로 새 화면을 생성할 때는 `POST /api/dashboards`에 `operations.dashboard.json`을 전달한다. 기존 화면 수정은 `GET /api/dashboards/{id}`로 현재 상태를 읽고 검토한 뒤 `PUT`한다. **PUT은 전체 교체**이므로 기존 패널을 생략하지 않는다. 실제 서비스에 반복 POST하여 같은 이름의 화면을 중복 생성하지 않는다. [공식 Dashboard API](https://www.elastic.co/docs/api/doc/kibana/operation/operation-create-dashboard).

## 6. 검증 결과와 한계

2026-09-10 확인:

- 기본 기간의 ES 집계: 전체 9건, High 9건. 대시보드 KPI/목록과 일치했다.
- 시간대별 막대 차트와 규칙별 집계의 정상 표시를 확인했다. 현재 규칙별 집계는 AUTH-001 9건이다.
- Source IP 필터 적용 시 KPI 두 개와 목록이 같은 4건으로 변경되었다.
- Critical 검색 조건에서는 두 KPI가 0이고 일치 결과가 없었다. 검증 후 기본 검색식과 필터를 복원했다.
- 경보 상세에서 `_id`, `_index`, threshold 10, window 300초와 JSON 탭을 확인했다.
- saved object export는 대시보드/Data View 2개이며 누락된 참조가 0개였다.
- 기존 대시보드의 변경 버전과 수정 시각은 유지되었다.
- 다른 환경/새 Space로의 실제 import, 500건 초과 UI 동작, 모바일 화면 검증은 이번에 수행하지 않았다.

이 화면은 Phase 1의 **읽기 전용 화면 부분만** 구현한 것이다. 다음 제약은 해결되지 않았다.

- raw/normalized 조회 코드의 10,000건 제한으로 최신 이벤트가 탐지되지 않을 수 있다.
- 목록은 최신 500건의 표시 한도가 있다. KPI 전체 건수와 다르면 기간/필터를 좁혀 조사한다. 전체 미종결 업무 큐 구현이 아니다.
- 상태/담당자/판단/메모/위험 점수, Host/User와 근거 원본 연결은 미구현이다.
- 수집 건강도는 로그 존재만으로 판정하지 않는다. 별도 Data Source Health 기능은 아직 없다.
- 보안 기능 비활성화는 기존 localhost 개발 설정이다. 외부 공개 전 인증/TLS/최소 권한을 별도 적용해야 한다.

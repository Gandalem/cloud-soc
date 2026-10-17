# Security Mall 5-A Portal 연동

2026-10-16: 기존 Portal API·UI 연동 및 관련 검증 완료. 운영 배포와 Portal 서버 기동은 하지 않았다.

## 기존 API 확장

- `GET /api/operations?start=...&end=...`: 기존 `sections.alerts` 목록·집계에 Mall 경보를 표시한다.
  `sections.security_mall`은 같은 기간·조직에서 `WEB-ACCESS-01`/`WEB-AUTH-01`만 집계한 전체 건수다.
  최신 50건 표본의 길이로 전체 건수를 계산하지 않는다.
- `GET /api/alerts/detail?id=...`: 기존 규칙 스냅샷·조건·위험도·증거 페이지를 재사용한다.
- `GET /api/alerts/detail?id=...&evidence=N`: 정규화 해시, 원본 참조, 조직 일치와 Mall 이벤트 ID·서비스·가명·키 버전·행동·결과·IP·권한 사유를 확인한다.
- 기존 `/api/logs/detail`과 감사가 남는 `/api/logs/source`를 재사용한다. 새 중복 경보/원본 API는 만들지 않았다.

목록 행에는 `rule`, `title`, `reason`, `timestamp`, `organization`, `service`, `severity`,
`risk_score`, `risk_level`, `event_count`, `status`를 제공한다. `status=stored`는 저장 상태이며
사건 업무의 신규/조사 중/종결 상태를 뜻하지 않는다. 서비스는 검증된 Mall 증거에서 확인한다.
원문 `message`를 API에 복사하지 않고 규칙 스냅샷의 `alert.message`를 탐지 사유로 사용한다.

## 서버 허용 목록과 조직 권한

실습 모드 설정 파일 예시는 `config/security-mall-portal-lab.example.json`이다.
서버 설정 `SOC_MALL_LAB_SCOPE_FILE`로 파일을 지정한다. 키는 `alerts`, `normalized`, `raw`이며
각각 하나의 정확한 인덱스 이름만 받는다. wildcard·쉼표·운영 `security-alerts`·합성 인덱스는
실습 범위로 설정할 수 없다. 합성 조회를 여는 요청 파라미터도 없다.

실습 모드의 경보 및 원본 조회는 이 세 인덱스에 한정된다. 운영 인덱스가 자동 추가되지 않으며
기존 정상 운영 모드는 설정을 생략하면 기존 `security-alerts`와 기존 원본 정책을 유지한다.
실습에서 처리 기록·전역 워커·품질 상태는 미확인으로 표시하며 운영 인덱스 조회로 대체하지 않는다.

조직은 인증된 서버 principal에서 얻는다. 목록·건수의 ES 조직 필터와 응답 조직 재검사,
상세·증거·원본 조직 검사를 유지한다. 타 조직 상세는 없는 문서와 같은 404이며,
원본 protected fields는 기존 investigator/source 조직 권한과 감사 기록이 필요하다.
`organization`, `index`, `include_synthetic`을 경보 API에 추가하면 400이다.
원본 상세의 index 파라미터는 기존 API 형식을 유지하되 실습 허용 목록 밖이면 ES GET 전에 차단한다.

## 화면과 위험도

기존 홈, 개인 대시보드 경보 표 및 Operations 목록에 규칙 ID·제목·서비스·시각·계산 위험 등급·상태·관측 건수를 표시한다.
기존 Operations 상세/사건 조사 상세는 공통 `mall-alerts.js`를 사용한다.
규칙 조건, 차단 해석, 사건 순서·시각, 가명·키 버전, 이벤트 ID와 원본/정규화 참조를 표시한다.
원본 메타데이터 링크는 기존 권한 검사 API를 사용한다. DOM은 textContent로 구성한다.

- ACCESS: 타인 주문 접근 시도 차단이며 정보 유출 성공으로 표시하지 않는다.
- AUTH: 의심 인증 시퀀스이며 계정 탈취 확정으로 표시하지 않는다.
- `severity`는 규칙 severity, `risk_score`/`risk_level`은 계산된 대응 우선순위다.
  medium 규칙의 60/high를 그대로 구분하며 기존 계산식을 바꾸지 않는다.
- Mall 감사 스키마 v1은 HTTP 응답 코드를 기록하지 않는다. UI는 403을 추정하지 않고 HTTP 상태를 **미관측**으로 표시한다.
- 기존 개인 위젯 카탈로그에 `security-mall-count`를 추가했다. 저장 레이아웃/템플릿을 자동 변경하지 않는다.

## 검증 결과

관련 Python 45건 및 하위 검증 3건, DOM 8건 통과. JavaScript 구문·diff 공백 검사 통과.
전체 Python/UI, 기존 49건 탐지 시험, 쇼핑몰·Filebeat·3-C 검증은 반복하지 않았다.

초기 실행은 기존 Windows pytest 임시 디렉터리 권한 때문에 8건이 실행되지 않았고,
목록에 일반 `message`가 포함되는 회귀 1건을 발견했다. 별도 basetemp와 규칙 스냅샷 사유로 수정한 후
해당 9건만 재검증해 통과했다. DOM 조건·원본 링크를 보완할 때도 영향받은 사례만 재검증했다.
검증 의존성은 Git 제외 로컬 venv에만 설치했다.

기존 실습 ES에 독립 조회 스크립트로 실제 `Operations.summary/detail`을 실행했다.
4-C API Key를 보호 파일에서 읽어 TLS 검증 상태로 **조회 요청만** 수행했으며 키·인증 설정을 바꾸지 않았다.
ACCESS 1건, AUTH 0건, 서비스 security-mall·규칙 low·계산 20/low,
정규화 해시/원본 증거 일치, 타 조직 0건/상세404를 확인했다. 합성 인덱스는 서버 범위에서 제외됐다.
조회 전후 원본4·정규화4·실제 경보1의 본문/버전/seq_no/primary_term은 동일했다.

증적: 로컬 `state/security-mall-portal-5a-20261016/es-readonly-result.json`,
VM `/home/kopo/soc-mall-lab/portal-5a-readonly/result.json`.
실제 Flask HTTP는 임시 상태 DB와 모의 ES로 검증했고, 실제 ES는 같은 조회 계층으로 확인했다.
실제 Portal 서버 및 브라우저의 종단 간 화면 검증은 이번 범위 밖이다.

## 다음 실습 Portal 기동 준비

다음 설정은 예시이며 이번 작업에서 배포하거나 실행하지 않았다.

```text
SOC_MALL_LAB_SCOPE_FILE=/보호된/실습설정/security-mall-portal-lab.json
SOC_INTERNAL_ES_URL=https://127.0.0.1:19200
SOC_CA_FILE=/home/kopo/soc-mall-lab/es-lab/runtime/certs/ca.crt
SOC_PORTAL_READ_API_KEY_FILE=/보호된/실습설정/portal-read-api-key
```

읽기 키 파일은 인코딩된 API Key 한 줄을 0600으로 저장한다. 새 Portal용 키는 예시에 적힌 세 인덱스에만
`read`, `view_index_metadata`를 부여하고 cluster 관리·쓰기·수집 권한은 주지 않는다.
4-C의 임시 키는 만료되므로 장기 Portal 인증으로 가정하지 않는다. 새 키 발급은 이번에 수행하지 않았다.
기존 Portal 사용자/세션·로그 접근 정책과 issuer/관리 설정도 별도로 준비해야 하며 운영 자격 증명을 재사용하지 않는다.
표시할 조회 기간은 평가 실행 시각이 아니라 경보의 실제 이벤트 시각을 포함하도록 선택한다.
독립 Portal 상태 디렉터리와 localhost 접속 구성을 확인한 뒤 다음 단계에서 기동·화면을 검증한다.

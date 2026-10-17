# 수동 탐지 룰 관리 MVP — 8단계

> 최신 상태(2026-10-17): [8-C 실제 반영·브라우저 인수 완료](rule_management_8c_validation.md). 아래 미배포/승인 대기 표기는 해당 문서 작성 당시 기록이다. AI 미연동·운영 룰 비활성은 유지한다.

2026-10-17: **수동 MVP 로컬 구현·격리 검증 완료 / AI 보조 미연동 / 실제 배포·적용 대기**.

기존 Portal의 설정 → 탐지 규칙 관리(`settings-rules.html`)를 사용한다. 자연어 입력은 메모로만 저장한다. AI 연결이 없어 자동 YAML 생성 버튼·외부 요청·새 API Key는 추가하지 않았다. 임계값 예시는 고정 수동 입력 예시이며 AI 생성 결과가 아니다.

## 검증·승인·적용 경계

- 기존 `validate_rule()`와 고정 `profiles.catalog()`를 재사용한다. 한 문서에 `rules` 한 개, 기존 엔진의 threshold/single 형식만 받는다. description과 alert 정보, 명시적 enabled/severity를 요구한다. 나머지 sequence/ordered/diversity/cardinality는 이번 관리 MVP에서 지원하지 않는다.
- 허용 필드는 API의 fields, 연산자는 기존 SUPPORTED_OPERATORS로 공개한다. 모든 중첩 객체의 필드를 제한하고 organization.id equals 조건·그룹을 필수로 검사한다. threshold 1~10000, window 1~3600초, cooldown 0~86400초다. 기존 엔진 검증기에도 통과해야 한다. 스키마 검증은 실제 탐지 효과 검증이 아니다.
- YAML은 SafeLoader 기반으로 처리하고 태그·anchor/alias·중복 키·과도한 깊이/복잡도를 거부한다. YAML UTF-8 4KiB, 자연어 메모 1KiB 및 기존 Portal 요청 크기 제한을 유지한다. 원문 오류를 응답에 포함하지 않는다. 비밀정보·개인정보를 입력하면 안 된다.
- draft → validated → approved 또는 draft/validated → rejected. 검증 실패는 draft로 남는다. 초안은 수정 API 없이 새 초안으로 다시 작성하므로 승인할 내용이 중간에 바뀌지 않는다. 모든 상태 변경에 현재 version/content_hash가 필요하다. 승인 시 엔진 검증·중복 ID·내용 무결성을 다시 확인한다.
- approved는 `awaiting_application`, 적용 요청 이후는 `pending_deployment`다. 둘 다 **active=false**다. 승인 전 적용 요청·내보내기를 거부하며, 승인 후에도 서비스/활성 YAML/기존 프로필에는 쓰지 않는다. 승인자·시각·규칙 ID·SHA-256과 검증/승인/거부/적용 요청 이력을 보존한다.

기존 엔진은 고정 프로필/규칙 ID를 명시적으로 로드한다. 단순히 새 YAML 파일을 rules 폴더에 복사하거나 Portal에서 승인해도 운영 탐지기에 반영되지 않는다. 내보낸 YAML은 기존 `load_rules(path)`/`detect_events()`에 입력 가능한 형식이다. 실제 반영은 별도 검토에서 고정 프로필의 새 ID 등록·실제 탐지 효과·조직 제한·중복/위험도 호환을 확인하고, 필요한 배포/프로세스 적용을 별도 승인받아야 한다. 이번 단계에는 자동 배포/재시작 기능을 만들지 않았다.

## 권한·저장·API

기존 Portal 관리자 인증, same-origin·JSON·CSRF 검사를 그대로 적용한다. 일반 사용자/분석가는 화면·JS·조회·승인·내보내기 모두 403이다. 관리 대상 조직은 기존 LogAccessPolicy에 설정된 조직만 사용하며, 스코프가 제한된 관리자도 해당 조직만 볼 수 있다. 다른 조직 ID는 없는 초안과 동일한 404다. 조직 정책이 비어 있으면 초안 생성은 비활성화한다. 브라우저가 정책/인덱스/저장 경로를 지정하지 않는다.

새 DB 없이 기존 `cases.sqlite`에 `rule_drafts`, `rule_history` 두 테이블만 추가한다. 초안 상태와 승인 감사의 원자적 저장을 위해 필요하며 기존 cases 테이블과 사건 수동 priority는 변경하지 않는다. 규칙 ID는 승인된 초안 간에도 전역 중복을 차단한다. 실패한 트랜잭션은 상태와 이력을 함께 롤백한다. 초안 최대 200개이며 별도 삭제·수정·자동 보존기간 기능은 만들지 않았다.

| 기존 Portal 하위 경로 | 동작 |
| --- | --- |
| GET /api/settings/rules | 조직 범위 목록·AI 미연동·지원 필드/연산자 |
| POST /api/settings/rules | organization/yaml/intent로 초안 저장 |
| GET /api/settings/rules/{id} | YAML·검증 결과·내용 해시·승인/적용 이력 |
| POST /api/settings/rules/{id}/{validate,approve,reject,apply} | version/content_hash 기반 상태 변경 |
| GET /api/settings/rules/{id}/export | 승인된 원문 YAML만 다운로드 |

기존 관리자 메뉴·인증 transport·스타일을 재사용하고 새 문자열은 textContent로 표시한다. YAML/메모는 관리자만 접근하는 민감 관리 데이터로 취급한다. 이력은 SQLite 트랜잭션으로 보존하지만 서명된 변조 방지 저장소라고 주장하지 않는다.

## 실행한 검증과 제한

- 관련 Python **25건 통과**, 변경 Python4파일 문법/Pyflakes 진단0, 신규 JS 문법 검사 통과. YAML/미지원 필드·연산자/중복 ID/임계값/조직 조건, 관리자·일반 사용자·다른 조직·CSRF, 미승인 적용/내보내기, 승인 후 내용 변조·오래된 버전, SQLite 감사 실패 시 원자적 롤백을 확인했다. 동일 기존 규칙6파일 SHA와16개 카탈로그를 보존했다.
- 내보낸 합성 승인 규칙을 실제 기존 load_rules/detect_events로 실행해 실패10회는 탐지1건,9회 및 다른 조직 입력은0건을 확인했다. 이는 격리 합성 검증이며 실제 공격·실제 운영 적용 결과가 아니다.
- 기존 Edge155.0.4283.45로 별도 localhost18188·합성 계정·임시 SQLite에서 수동 초안/검증/승인/배포 대기/내보내기/이력 및 다른 조직의 일반 사용자 차단을 확인했다. 신규 화면3검사군 성공·pageerror0·스크린샷 확인. 임시 미리보기는 종료했다. VM Portal/ES에는 접속하거나 배포하지 않았다.
- 최초 pytest 임시 부모 경로 누락으로7개 setup 오류가 있었고 폴더 준비 후 해당7개만 통과했다. 이미 통과한18개를 반복하지 않았다. 미리보기 launcher의 issuer 테스트 대역 누락도 대역 지정만 보완했으며 외부 ES 연결은 없었다. 기존7단계/전체 pytest/UI·Docker·쇼핑몰 검증은 반복하지 않았다.

비밀 없는 근거는 Git제외 `state/rule-management-08-20261017/`의 browser-result.json·manual-rules-preview.png·verification.json에 보존한다. 실제 AI 초안 생성·실제 VM 배포·승인 규칙의 운영 적용/효과는 미검증 또는 미구현이다. 다음 최소 작업은 수동 MVP 배포를 별도 승인받아 실습 Portal에서 인수하는 것이다. AI 연결은 별도 공급자·비밀 관리·비용 승인이 준비된 뒤 검토한다.

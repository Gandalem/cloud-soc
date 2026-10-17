# 8단계 수동 룰 관리 — 실습 Portal 배포 사전점검

> 최신 상태(2026-10-17): [8-C 실제 반영·브라우저 인수 완료](rule_management_8c_validation.md). 아래 미배포/승인 대기 표기는 해당 문서 작성 당시 기록이다. AI 미연동·운영 룰 비활성은 유지한다.

2026-10-17. **사전점검 완료, 실제 반영은 조건부 가능. 배포·재시작·DB 백업/변경은 수행하지 않았다.**

## 확인한 배포본과 차이

- 실습 Portal: `/home/kopo/soc-mall-lab/portal-lab`, `soc-mall-portal.service`, PID892692, enabled 이력의 현재 active/running, 시작 UTC11:28:48. `/login` HTTP200. 기존 localhost18081·venv·WSGI·세션/조직 정책을 유지한다.
- 7-A/B의 correlation/triage 및 7-C의 operations/mall_investigation, 기존 detection profiles/loader/engine/patterns/behavior는 로컬과 VM SHA-256이 일치했다. 이 파일들은 배포 대상이 아니다. WSGI의 기존 7-C snapshot 설정도 존재하며 수정할 필요가 없다.
- app.py/auth.py를 AST로 대조해 8단계 추가를 제외한 기존 코드가 동일함을 확인했다. shell.js는 관리자 메뉴 1항목, auth-client.js는 해당 페이지 식별자만 추가된다. 검증된 로컬 7개 파일의 SHA도 이전 25건/로컬 Edge 검증본과 같다. 신규 API 다섯 경로/메서드의 정적 충돌0이다. 이전 테스트는 반복하지 않았다.
- **중요한 누락:** VM `portal-lab/code/rules/`에 고정 카탈로그 YAML6개가 없다. 새 검증기는 `profiles.catalog()`를 호출하므로 코드/UI7개만 배포하면 형식 검증이 `rule_catalog_unavailable`로 실패한다. 아래 Portal 전용 읽기 카탈로그6개를 배포 승인 범위에 반드시 포함해야 한다. 기존 탐지기 실행 경로의 활성 YAML을 교체하는 작업이 아니다.

## 정확한 반영 대상 — 총13파일

모두 로컬 `D:\cloud-soc\` → VM `/home/kopo/soc-mall-lab/portal-lab/code/` 하위 동일 상대 경로다.

| 구분 | 상대 경로 | 현재 VM |
| --- | --- | --- |
| 교체 | src/cloud_soc/portal/app.py | 기존7-C + 8단계 추가분만 |
| 교체 | src/cloud_soc/portal/auth.py | 관리자 전용 파일 제한 추가 |
| 교체 | prototype/shell.js | 공통 메뉴 1항목 추가 |
| 교체 | prototype/auth-client.js | 새 페이지 메뉴 권한 표시 |
| 추가 | src/cloud_soc/portal/rule_management.py | 없음 |
| 추가 | prototype/settings-rules.html | 없음 |
| 추가 | prototype/settings-rules.js | 없음 |
| 추가·검증 참조 전용 | rules/authentication.yml | 없음 |
| 추가·검증 참조 전용 | rules/authentication_sequence.yml | 없음 |
| 추가·검증 참조 전용 | rules/attacks.yml | 없음 |
| 추가·검증 참조 전용 | rules/cloud.yml | 없음 |
| 추가·검증 참조 전용 | rules/metadata_patterns.yml | 없음 |
| 추가·검증 참조 전용 | rules/security_mall.yml | 없음 |

SHA-256 전체와 기존 VM 해시/없음 기준은 Git제외 `state/rule-management-preflight-20261017/deployment-manifest.json`에 기록했다. 새 승인 시 해당 기준에서 달라진 파일만 다시 검토한다. 다른7-A/B/C 파일·탐지 엔진·WSGI·unit·사용자/키/조직 설정을 일괄 덮어쓰지 않는다. 카탈로그 파일 추가만으로 새 사용자 규칙이 활성화되지 않는다. Portal 내보내기/승인은 기존 파일을 수정하지 않는다.

## 인증·조직·데이터 영향

현재 구성은 관리자1/분석가1/조회자1, 정책 조직은 `mall-isolated`, `mall-lab-foreign`다. 기존 관리자는 전역 관리자이므로 설정된 두 조직을 관리할 수 있다. 일반 사용자/분석가에게는 자기 조직을 포함한 전체 룰 관리 기능을403으로 차단한다. 제한 관리자에 대한 타 조직404는 로컬 저장소 테스트 범위이며, 현재 VM에 그런 관리자 역할이 존재한다고 주장하지 않는다.

관리 API는 `/api/settings/rules` GET/POST, `/{id}` GET, `/{id}/{validate,approve,reject,apply}` POST, `/{id}/export` GET이다. 기존 세션·same-origin·JSON·CSRF 경로는 유지되고 관리자 경로만 추가된다. 일반 사용자에게 URL/조직/헤더 조작으로 권한을 부여하지 않는다. 원문/증거 링크는 7-C 기존 정책을 그대로 사용한다.

승인·적용은 현재 version/content_hash 및 저장 내용 재검증이 필요하다. 조직 equals 조건·그룹, 필드 allowlist, 안전 YAML, 기존 민감 문자열 검사를 유지하며 YAML은 관리자만 내보낼 수 있다. 자유 입력에 임의 비밀값이 없는지 사람의 검토도 필요하다. 비밀번호·키·실제 개인정보를 시연 초안에 넣지 않는다. AI는 미연동이며 적용 요청도 `pending_deployment`, `active=false`로 끝난다.

## SQLite 스키마와 백업 계획 — 다음 승인 이후에만 실행

현재 `state/`는0700, SQLite 네 파일은0600·journal_mode=delete·WAL/SHM 없음이다. 실제 DB에는 새 테이블/인덱스 이름 충돌0이다.

| 파일 | 바이트 | 현재 역할 |
| --- | ---: | --- |
| cases.sqlite | 49152 | 사건·연결·이력·멱등 요청 |
| dashboards.sqlite | 20480 | 개인 대시보드 |
| sessions.sqlite | 20480 | 세션·로그인 제한 |
| log-access.sqlite | 8192 | 보호 원문 열람 감사 |

새 Portal 시작 시 **cases.sqlite에만** `rule_drafts`, `rule_history` 테이블 및 `rule_approved_id` 고유 partial index를 추가한다. 기존 사건 테이블의 ALTER/DROP/행 변경은 없다. 동일 DB의 룰 상태·감사는 하나의 트랜잭션으로 저장한다. 기존 사건 쓰기와 짧게 잠금 경쟁할 수 있어 저장 오류 시 성공으로 표시하지 않고 중단해야 한다.

별도 승인 후 다음 순서를 따른다.

1. 비공개 `portal-lab/backups/8-manual-<UTC>`를0700으로 준비한다. 기존 교체4파일, WSGI, unit, 환경/설정 파일을 원래 소유자·권한과 함께 백업한다. 새9파일은 기존에 없었다는 사실도 manifest에 기록한다. 비밀 설정 백업은 VM에만0600으로 보관하며 출력/Git/SCP 반출하지 않는다.
2. SQLite 각 파일은 **Python sqlite3 Online Backup API**로 별도의 새0600 파일에 복제한다. 원본은 URI `mode=ro`, 백업 대상은 백업 디렉터리로 고정한다. `Connection.backup(pages=128, sleep=0.05, progress=...)`의 진행 콜백에서 시간 상한을 두고 잠금·읽기 실패가 나면 배포를 중단한다. 단순 cp나 WAL/SHM의 임의 복사를 일관성 있는 백업이라고 간주하지 않는다.
3. 대상 연결을 닫은 후 백업만 `mode=ro`로 열어 `PRAGMA integrity_check`의 `ok`, 스키마·필요 테이블·기존 사건/연결/이력 수량 및 검증용 해시를 확인한다. 백업 SHA-256·UTC·크기·권한·소스 경로를 기록한다. 원본/계정/사건 내용은 출력하지 않는다. 여러 DB의 개별 백업이 하나의 전역 원자적 시점을 보장한다고 주장하지 않는다. 필요하면 승인된 유지보수 구간에 Portal만 정지한 상태에서 추가 일관성 백업을 확보한다.
4. 기존 사건 데이터/수동 priority와 대시보드 설정의 논리 기준선을 남긴다. 이후 추가되는 룰 테이블과 정상 로그인/원문 조회 감사 때문에 DB 파일 SHA가 변할 수 있으므로 기존 전체 DB 바이트 해시 동일성을 성공 조건으로 사용하지 않는다. 기존 사건 테이블 정의/레코드와 보호 설정을 비교한다.
5. 새13파일을 private staging으로 전송·SHA 대조하고 기존 venv로 import/카탈로그16개 읽기/미지원 YAML 거부를 서비스와 격리해 확인한다. 신규 카탈로그 경로에 심볼릭 링크나 예상치 못한 기존 파일이 생겼다면 중단한다. 검증에 실패한 상태에서 실행 파일을 교체하거나 서비스를 재시작하지 않는다.

현재 단계에서 위 백업·마이그레이션·staging 전송은 실행하지 않았다. 각 DB의 실제 스키마 해시는 로컬 `vm-report.json`에 메타데이터로만 보존했다.

## 승인 후 반영·인수 순서

1. 위 백업/기준선/13파일 의존성 점검 통과 후 Portal 전용 파일만 반영한다. WSGI의 7-C snapshot 경로와 기존 config·venv·unit은 유지한다.
2. `systemctl --user restart soc-mall-portal.service`를1회 실행한다. localhost18081·enabled/active/running·신규 PID·login200을 확인한다. 다른 unit은 변경하지 않는다. 현재 unit은 정상 종료60초, 기동180초 한도이며 무한 재시도/강제 종료하지 않는다.
3. 기존 관리자/정상 사용자 로그인과 관리자 메뉴·AI 미연동 표시를 확인한다. 기존 정책에는 새 사용자나 권한을 추가하지 않는다.
4. 테스트는 전용 식별자 `DEMO-MANUAL-<날짜>-<접미사>`와 가상 문자열을 사용한다. 기존 AUTH/ACCESS ID를 재사용하지 않는다. 룰 자료는 새 두 테이블에만 저장하며 기존 사건·활성 YAML과 분리한다. 테스트 내보내기는 private 결과 폴더에 보관하고 실제 탐지기에 전달하지 않는다.
5. 초안 저장→미승인 apply/export409→검증→명시 승인→배포 대기→승인 YAML 다운로드 및 승인자/시각/해시/이력 확인. 별도 초안 거부, 잘못된 YAML/미지원 필드·중복 ID 거부, CSRF 없는 변경403을 확인한다. `active=false`와 기존 룰 참조 SHA/탐지기 상태 불변을 대조한다.
6. 일반 사용자/타 조직 사용자로 화면·JS·API·이력·approve/export403을 확인한다. 기존 전역 관리자에게 허용된 두 조직 접근을 오류로 취급하지 않는다. 제한 관리자 범위 부정 시험은 격리 테스트 근거로 구분한다.
7. 기존 ACCESS 목록·사건 조사·증거 링크·20/low/severitylow·조사20low/limited를 확인하고, 타 조직 증거/보호 원문 차단도 유지되는지 확인한다. 기존 사건 수동 priority/대시보드 구성·7-C snapshot·ES 문서는 변경하지 않는다. 전역 수집 상태 일부 미확인은 기존 최소 읽기 범위대로 남긴다.

위 결과가 실제로 확인되기 전 VM 배포/운영 인수를 성공으로 기록하지 않는다. 전체25테스트나7-A/B/C 통합 검증은 반복하지 않고 신규 기능·공통 인증/메뉴 영향만 확인한다.

## 실패 시 복구

- 추가 적용 시도 없이 Portal 한 서비스만 대상으로 한다. 중단/복구가 필요한 경우 승인된 복구 범위에서 Portal만 정상 종료하고 잔류 PID/포트를 확인한다. Mall/WAF/ES/수집기는 건드리지 않는다.
- 기본 롤백은 백업한 기존4파일을 복구하고 같은 unit으로 정상 기동하는 **코드 롤백**이다. 실패한 신규 파일은 이전 코드에서 참조/노출되지 않으므로 무조건 삭제하지 않는다. WSGI/config/unit은 변경하지 않는 계획이므로 다른 값으로 초기화하지 않는다.
- 추가된 두 테이블/인덱스는 기존 코드가 사용하지 않는 부가 구조라 이전 코드와 호환된다. **테이블 DROP 또는 전체 cases.sqlite 자동 복원은 하지 않는다.** 신규 승인 이력과 배포 이후 정상 사건 변경을 보존한다.
- 실제 손상/비호환 증거가 있으면 현재 상태도 보호 백업하고, 원본·백업 integrity와 배포 이후 사건 변경을 분석한 뒤 필요한 DB만 별도 승인으로 복구한다. 세션 DB를 과거 시점으로 무조건 되돌려 폐기된 세션/로그인 제한을 복원하지 않는다. 개별 DB 복구가 필요한 경우 Portal이 완전히 정지한 상태와 파일 권한을 확인하며 자동 덮어쓰지 않는다.
- 복구 후 HTTP/login·기존 조직 권한·ACCESS/증거·기존 사건/대시보드·7-C snapshot을 확인하고 실패 원인·복구 PID·유지한 룰 이력을 기록한다.

## 승인과 결론

**조건부 반영 가능**: 코드/UI7개에 Portal 전용 카탈로그6개를 추가하는 총13파일, 사건 DB의 부가2테이블/1인덱스, 일관성 백업, Portal1회 재시작 및 실패 시 Portal 단독 복구까지 승인 범위를 명시해야 한다. 현재 요청은 사전점검만 허용하므로 이를 실행하지 않았다.

예상 영향은 Portal의 짧은 로그인/조회 중단과 진행 중 요청 실패 가능성이다. 보통 수초~수십초 수준을 예상하되 readiness의 실제 시간을 보장하지 않는다. 세션 비밀·DB를 유지하지만 로그인 지속 여부는 실제 인수로 확인한다. AI/자동 룰 적용/다른 서비스 변경·재부팅·Git commit/push는 범위에 포함하지 않는다.

# Cloud SOC 작업 목록

## 2026-10-17 runtime-v2 + Security Mall 안전 통합

- [x] INTEGRATE-RUNTIME-V2-MALL-20261017 로컬 통합·최소 검증 완료: 최신 main9d97ee2 기반 별도 통합 브랜치에서 runtime51d201a와 Mall4b5c1ed를 통합한다. 미추적87파일은 로컬 codex/preserve-local-lab-20261017의5b21f90에 별도 보존하고 원본 폴더/브랜치는 변경하지 않는다. 작업 기록의 양쪽 이력을 합치며 소스·인증·조직/CSRF·탐지/위험도/CI 검사를 삭제하지 않는다. 주요 import/문법·관리CLI·Portal 권한·YAML/공통 모듈 관련 검사만 수행한다. 운영 배포·서비스/Docker/ES/운영SQLite 변경·전체 테스트는 하지 않는다. 9-B 실제 배포/SQLi/ES 검증과 AI8-D 미실행을 유지하며 push/PR만 승인 범위다.

2026-10-17 새 검증 근거: 충돌은 docs/work_tracker.md 한 파일뿐이며 양쪽 추가 기록을 모두 보존했다. Mall 원본99파일과 runtime 원본18파일은 각 부모 브랜치와 Git 내용이 동일하고 CI의 기존/신규 검사도 그대로 유지했다. 관련 Python16건(백업/WAL·자원·키 재발급 거부·실패복귀·신규기동 대역·Portal 관리자/CSRF/조직·조사/원문·WAF 상세) 통과, 주요 import8·실제 manage.py --help 종료0·YAML17 및 Mall3명시선택 통과다. 운영 IO는 대역/임시SQLite로 한정하며 실제Docker/ES/VM·전체검사는 반복하지 않았다. 원본 runtime51d201a의 기존 Actions38679093442 success를 읽기 확인했다. 통합본 push/PR의 신규 CI·main 병합·운영 인수는 별도이며 main 자동 병합은 하지 않는다. 원본87파일 SHA/HEAD와 원래 개발 브랜치를 유지한다. 실제 commit/PR 식별자는 Git 이력·원격 PR 기록과 최종 보고를 따른다.

## 2026-10-17 누적 7~9단계 Git 보존 검토

- [x] GIT-REVIEW-7-9 범위·민감정보 검토 완료: 사용자 승인으로 7-A/B/C·8-A/B/C·9-B 및 이를 실행/검증하는 미커밋 Mall 정규화·수집 계약 의존 파일100개를 단일 통합 커밋 대상으로 선정했다. 기존 브랜치 codex/security-mall-collection과 최신 origin/main 기준점은 동일하며 원격 동명 브랜치는 없었다. 후보의 실제 비밀값/개인키/운영 DB·로그·스냅샷은 발견되지 않았고 API Key 예시는 환경변수 자리표시자, 시험 표식은 합성임을 확인했다. 별도 6단계 부팅·서비스 전환·ES 구성 도구와 관련 기록/테스트87개는 범위 밖으로 보존·제외한다. state/·실제 비밀/DB는 커밋하지 않는다. 공유 파일의 단계별 부분 분리는 피하고 현재 구현 그대로 보존한다. 전체/기존 검증 재실행·서비스/ES 변경은 없으며 9-B는 로컬 구현/합성 검증만 완료, 실제 SQLi/배포/ES/브라우저 미검증을 유지한다. 실제 commit/push 결과는 Git 이력·원격 참조와 최종 보고로 확인한다.

## 2026-10-17 자체 SQLi 의심 규칙 최소 구현

- [x] MALL-WAF-09B 로컬 구현·합성 검증 완료(2026-10-17): 기존 YAML/threshold 엔진·증거/경보 저장·Portal 구조에 WEB-WAF-01만 추가했다. CRS3.3.5 초기8ID allowlist·같은 요청 중복 제거·300초3요청 반복 판단·DetectionOnly의 실제차단 아님·조직/호스트/IP 분리 및 provenance를 검증했다. 신규 Python31/직접 회귀7·공유 DOM12 통과, 변경 Python 정적0이다. 기존 증분 Worker/임시SQLite에서 최초3경보·checkpoint재실행 추가0건을 확인했다. 기존 AUTH/ACCESS YAML·위험도 산식·VM/ES/서비스는 보존했다. 실제 SQLi/ES/브라우저·상주 탐지 배포는 미검증이며 기존 Portal의 앱 전용 scope를 자동 확대하지 않았다. 관련 파일/설계·실행 결과·한계는 docs/security_mall_waf_detection.md에 기록한다. AI8-D/배포/commit/push 없음.

## 2026-10-17 수동 탐지 룰 관리 MVP

- [x] RULE-MANAGEMENT-08C 실습 Portal 반영·실제 브라우저 인수 완료(2026-10-17): 승인13파일·SQLite Online Backup4개 integrity ok·부가2테이블/1인덱스·Portal892692→933317의1회restart0/login200을 확인했다. 실제Edge 관리자작성/검증/승인/거부/내보내기·CSRF403/미승인409/일반·타조직403·기존ACCESS20low/limited/증거200·hash의5검사군/pageerror0을 통과했다. 기존사건스키마/행·대시보드기존행·설정·다른unit·엔진/7-A/B/C코드는보존했다. AI/운영룰활성화·전체이전테스트는없고rollback불필요다.

2026-10-17 RULE-MANAGEMENT-08C 새 검증 근거:

- 실제백업 portal-lab/backups/8c-87a6d2의SQLite4개를readonly소스→Online Backup/진행상한15초→백업integrity검사로확인했다. 기존4소스/WSGI/unit/config 복구본을보호했다. staging/8c-87a6d2의승인13SHA와기존VM해시/불변의존성확인후반영했고기존설정·WSGI는바꾸지않았다. 초기화의IF NOT EXISTS와실제새스키마3개정확일치를확인했으며기존테이블/기존사건수동priority/대시보드기존행은불변이다.
- 실제실습초안2개만새rule테이블에저장했다. 승인1개는pending_deployment/activefalse,잘못된YAML1개는검증실패후rejected,이력7행이다. 삭제하지않고보존하며runtime탐지기에전달하지않았다. 관리자lab-admin은기존전역관리자권한을유지하고일반mall-analyst/타조직other-viewer의관리·승인·이력·export403을확인했다. 기존원본메타데이터200/타조직404/보호원문403 및CSRF없는정상관리자요청403·미승인apply/export409를확인했다.
- 실제Edge155.0.4283.45의핵심흐름1회·5검사군통과/pageerror0·스크린샷확인이다. Git제외state/rule-management-8c-20261017의acceptance.json/deployment.json/스크린샷에근거를보존했다. 원본/정규화/경보ES수정·재수집·Mall/WAF/ES/수집기재시작·AI연결·Gitcommit/push없다. Portal외unitPID·시각·상태와config해시·기존엔진/7-A/B/CSHA가불변이다. 세션/보호조회감사등정상Portal기록과새초안이력추가는허용범위로구분한다.
- docs/security_mall_correlation.md·security_mall_triage.md의현재미실행표기를저장된c289b4ba summary/lifecycle완료/exit0와기존기록으로정정했다. 실제6인덱스211·3종8/105대조/hash1·SQLite12의기존완료와실제AUTH/반복가산미검증을구분했으며7-A/B를재실행하지않았다. docs/rule_management_8c_validation.md에새실습인수만기록한다. 8-C수동MVP완료지만전체AI단계/운영룰적용은미완료로부모task는unchecked유지다.

2026-10-17 RULE-MANAGEMENT-08C 진행 중: 사용자가 실습 Portal13파일·SQLite Online Backup·부가DDL·1회재시작·Portal단독복구를 승인했다. 기존사전점검본변경여부와복구수단만확인한뒤핵심브라우저/보안인수를수행한다. 기존사건/승인이력삭제·활성룰/AI/다른서비스변경은금지하며이전단계는재검증하지않는다.


- [ ] RULE-MANAGEMENT-08 부분 완료(2026-10-17, 수동 MVP 실습 인수완료/AI 미연동/운영 룰 적용 대기): 최신 요청을 우선해 기존 Portal 관리자 인증·조직 정책·사건 SQLite와 엔진 YAML 검증기를 재사용한다. AI 미연동을 명시하고 수동 초안/검증/승인·거부/배포 대기·승인 YAML 내보내기만 구현한다. 기존 고정 profile에는 동적 적용 경로가 없어 활성 규칙·서비스·7단계는 변경하지 않는다. 로컬 관련 보안 검증과 실제 배포를 구분한다.


2026-10-17 RULE-MANAGEMENT-08 Portal 반영 사전점검 완료(배포 미실행):

- 최신 요청으로 사전점검·배포/백업/rollback 계획만 수행했다. VM Portal892692/active running/login200·기존7-C WSGI snapshot 설정을 확인했다. 관련7-A/B·7-C·detection 의존11파일 SHA가 일치하고 app/auth는8단계추가제외 AST동일, shell/auth-client는새메뉴/페이지식별자만차이다. 새API5경로/메서드정적충돌0·검증된로컬7파일 SHA동일이며25테스트/이전단계검증은반복하지않았다.
- VM Portal code/rules의고정카탈로그6YAML부재를확인했다. 코드/UI7개만반영하면 catalog검증이실패하므로 Portal전용읽기카탈로그6개를포함한총13파일을승인대상으로정리했다. 기존탐지기경로/활성규칙/엔진파일을교체하지않는다. 로컬 state/rule-management-preflight-20261017/deployment-manifest.json에13SHA·기존VM해시/부재·변경없는의존성과unit/WSGI해시를기록했다.
- VM기존SQLite4개는0600/delete/WAL없음·state0700이며cases의새이름충돌0이다. 현재역할은admin1/analyst1/viewer1·정책조직2개이고기존전역관리자는두조직허용이다. 제한관리자타조직404는로컬store시험범위로구분했다. cases부가2테이블/1인덱스외기존스키마수정없음·상태/감사원자트랜잭션·관리자/CSRF/서버조직검사·원본접근유지로계획했다.
- docs/rule_management_deployment_preflight.md에정확한13파일/기존차이/SQLite Online Backup·integrity검사·기존레코드논리기준선/Portal1회재시작·신규기능/7-C인수/코드단독rollback을기록했다. 전체DB자동복원·DROP·정상사건/세션상태덮어쓰기를금지한다. 별도승인대상은13파일·부가DDL·일관성백업·Portal재시작/단독복구이며현상태조건부반영가능이다.
- 실제Portal파일교체/staging전송·DB백업/DDL/업무데이터변경·서비스제어·ES검색·AI연결·기존룰수정·Gitcommit/push없음이다. VM소스4파일은로컬state로읽기복사만했다. 이번변경은사전점검문서와tracker뿐이며부모8단계task는실제배포/AI미완료로unchecked유지다.

2026-10-17 RULE-MANAGEMENT-08 수동 MVP 검증 완료·제한:

- 새 portal/rule_management.py와 settings-rules.html/js를 추가하고 기존 portal/app.py·auth.py 및 공통 shell.js/auth-client.js에 관리자 전용 경로/메뉴만 연결했다. 기존 CaseStore가 사용하는 cases.sqlite에 초안/이력2테이블만 추가하며 새 DB·의존성·운영 적용 경로는 만들지 않았다. tests/test_rule_management.py와 docs/rule_management_mvp.md 및 tracker를 추가/수정했다.
- 기존 validate_rule/catalog를 재사용한 strict threshold/single 부분집합·known 필드/연산자·1rule/4KiB·안전 YAML/중복키·alias/tag/depth 차단·조직 equals+group guard·기존/승인 ID 충돌·version/SHA recheck를 구성했다. draft/validated/approved/rejected와 awaiting_application/pending_deployment를 구분하고 active=false를 유지한다. 감사에 actor/at/id/hash/상태/검증 결과를 같은 트랜잭션으로 보존한다. 일반 사용자 관리 API/화면/이력/내보내기403·제한 관리자 다른 조직404·CSRF를 유지했다.
- Python 고유25pass·변경4Python 정적진단0·신규JS문법0이다. 최종적으로 validated 상태의 미승인 적용/내보내기 차단과 상태 불변을 보강하고 직접 영향1검사만 재확인했다. 최초 임시폴더 부모누락으로7setup오류가 났지만 준비후 해당7만pass했고 성공18을 반복하지 않았다. 기존엔진으로 합성 내보내기 규칙의10실패→1경보/9실패·다른조직→0을 확인하고 기존6YAML hash/16카탈로그를 보존했다. 변조/오래된hash/중복승인/SQLite감사실패 원자rollback도 통과했다.
- 별도 localhost18188/임시SQLite/합성계정의 실제 Edge155.0.4283.45에서 수동 작성→검증→명시승인→배포대기·YAML내보내기/이력 및 일반 타 조직403의3검사군을 통과했고 pageerror0·화면도 확인했다. launcher issuer 대역누락만고쳐 외부ES 없이기동했고 작업후임시서버를종료했다. 근거는Git제외 state/rule-management-08-20261017이다. 기존7단계/전체pytest/UI/ES/VM/Docker 검증은 실행하지 않았다.
- 기존 고정 profile에는 신규 ID의 런타임 적용 경로가 없으므로 승인 YAML은 내려받기·배포대기로 남긴다. AI 연동/외부API·키 추가·서비스 자동배포/재시작·활성규칙/위험도 변경·ES/실제Portal/쇼핑몰변경·Gitcommit/push는 없다. 수동 MVP는 로컬완료지만 전체8단계는 AI미연동 및 실제배포/운영인수미검증을 남겨 unchecked 유지한다. 실제 적용에는 별도 프로필/효과 검토와 배포 승인이 필요하다.

## 2026-10-17 Security Mall 7-C Portal 조사 연결

2026-10-17 최종 인수 완료:

- 사용자가 실습 Portal 파일 반영·1회 재시작을 명시 승인해 staging11코드 및 WSGI snapshot 경로만 적용했다. VM portal-lab/backups/7c-20261017T112828Z에 원본/복구 목록을 보존했다. restart0·신규892692/enabled/active/running·login200·기존config SHA 불변·다른6 user unit 신원/시작시각 불변·snapshot SHA 불변이다. DB/ES/규칙/위험도/다른 서비스 변경·Git commit/push 없음이다.
- 실제 Edge155.0.4283.45/Playwright에서 기존 목록·새 조사 상세·현재 증거 hash/링크·외부 조직/보호 원문 차단의4검사군을 통과했다. 실제 화면 스크린샷도 확인했으며 pageerror0이다. 인수 스크립트의 기존 버튼명 오기만 고쳐 증거/권한 단계부터 재개했고 성공한 목록/점수·기존26/10·전체 테스트는 반복하지 않았다. 제품 수정/추가 restart·롤백 없다.
- 관련 파일은 승인된 portal app/operations/mall_investigation·공유JS·필수 correlation/triage/edge 모듈 및 VM portal_wsgi.py이며 신규 기능은 없다. 문서 docs/security_mall_portal_investigation.md에 최종 반영/인수/백업/시연 주소를 추가했다. Git제외 state/security-mall-7c-20261017의 acceptance.json/스크린샷에 증거를 보존했다. 고정 snapshot·실시간 미지원·기존 전역 수집 상태 일부 미확인/최소3인덱스 읽기·실제 AUTH미검증은 제한으로 유지한다.

2026-10-17 인수 진행 중: 최신 요청으로 실습 Portal의 검증 staging 반영 및 필요한 1회 재시작이 명시 승인됐다. 기존 부분 완료 기록을 보존하고, Portal만 보호 백업/최소 반영한 뒤 실제 브라우저·필수 조직/원문 차단을 검증한다. 다른 서비스·ES·정책·DB 스키마는 변경하지 않는다.

- [x] MALL-PORTAL-07C 실제 인수 완료(2026-10-17): 승인된 실습 Portal 최소 반영·1회 재시작(PID485310→892692/enabled active) 후 실제 Edge에서 ACCESS1/AUTH0·기존severitylow/risk20low·조사20low/limited/고유이벤트1·증거참조2/app관측·web/WAF미확인 및 증거 링크200·타 조직404/보호 원문403·파라미터400을 검증했다. 다른 서비스/ES/기존 비밀설정/스키마는 보존했고 고정 snapshot 시연 범위만 완료다. 실시간 분석·실제 AUTH는 범위 밖이다.



2026-10-17 MALL-PORTAL-07C 구현·검증·제한:

- src/cloud_soc/portal/mall_investigation.py를 추가하고 app.py·operations.py의 기존 /api/alerts/detail에 선택적 investigation 요약을 연결했다. 기존 operations/사건 조사 화면의 공유 prototype/mall-alerts.js만 확장했다. 새 API·DB/table·위험도/탐지 정책·사건 수동 priority·원본 증거는 변경하지 않았다. tests/test_mall_investigation_portal.py·tests/test_mall_alert_ui.cjs·docs/security_mall_portal_investigation.md 및 이 tracker를 추가/수정했다.
- 서버 설정 SOC_MALL_TRIAGE_SNAPSHOT_FILE로 SHA256 고정된 닫힌 기존 7-B SQLite를 메모리 query_only로 읽는다. 경보 index/id·scope/site/host/service·정책/frame/publisher/revision·기존 risk/severity·증거 참조/해시를 대조하고 현재 증거는 기존 Operations.evidence로 조직/원본 identity/해시를 재확인한다. LogPrincipal 재검사·클라이언트 인덱스/조직/스냅샷 파라미터 거부·기존 viewer 원문403/타 조직404를 보존했다. 분석이 없거나 불일치하면 기존 상세는 유지하고 미확인으로 표시한다. 가명/IP/원문/새 원본 locator는 분석 API에 추가하지 않으며 고정 요인 문구와 textContent를 사용한다.
- 관련 Python 고유26 pass/OS 전용2 skip, DOM 고유10 pass, 최종 변경 Python4파일 문법/Pyflakes0이다. 기존 목록과 원문 권한 회귀2만 재사용했고 전체 Python/UI·7-A/B 통합 검증은 반복하지 않았다. POSIX 소유권·mode 부정 분기는 Windows 모의 메타데이터로 확인했다. 실제 Linux mode/Windows symlink 생성 검사는 미검증이다. 추가 보강 이후 직접 영향 파일23사례 및 새 SQLite 호환1만 실행했고 DOM 성공9를 반복하지 않고 새 ID 모호 표시1만 실행했다.
- 기존 실제 검증 c289b4ba의 격리 correlation/triage.sqlite 두 개만 SSH/SCP로 로컬 Git제외 state/security-mall-7c-20261017에 읽기 복사했다. 실제 스냅샷 hash56d461524737f256d74056daad66bb1440fe490f9c2ff3dc4805088d2d79affb 불변 및 새 어댑터의 실제 ACCESS20low/limited/app관측/web·WAF미확인/고유이벤트1·관측증거참조2를 확인했다. 현재 ES를 재검색하지 않고 이미 저장된 경보 투영/증거 메타데이터를 사용했다. 이는 실제 데이터 오프라인 재조회이며 현재 Portal/ES API·브라우저 성공이 아니다. API 회귀의 ES transport는 대역이다.
- 서비스 재시작·VM Portal 배포·키 발급·ES/운영 SQLite/H2/registry/사건 변경·Git commit/push 없으며 쇼핑몰 저장소는 읽기 상태 확인만 수행했다. 두 브랜치와 기존 미커밋 작업을 보존했다. 현재 연결은 명시적 범위의 검증 스냅샷이며 자동 갱신/실시간 7-A/B 발행은 미구현이다. 별도 승인 배포·기존 읽기 키/CA 유지·실제 ACCESS 상세와 타 조직/원문 권한·브라우저 인수가 남아 task unchecked를 유지한다.

2026-10-17 MALL-PORTAL-07C 실제 반영 준비·승인 경계:

- 최신 요청으로 실제 Portal 반영·브라우저 인수를 우선하되 서비스 영향 변경의 명시적 승인 전에는 중단한다. 기존 실행 Portal PID485310/active running/login200 및 explicit WSGI settings·Gunicorn reload 미설정, VM 어댑터/7-A/B 의존 모듈 부재를 확인해 Portal 단독 파일교체/재시작이 필수임을 확인했다. 현재 승인 범위가 불명확하므로 active 코드/설정/서비스는 변경하지 않았다.
- VM portal-lab/staging/portal-7c-92309a에만 코드11·스냅샷·설정의 payload13SHA 일치와 manifest54bdf19fcf3e8012acfac89b4155198db644a511c6de58f696b98802f078650f를 확인했다. Python 문법·실제 venv import·Linux private snapshot 로딩/scope/frame/53항목 성공이다. 소유 파일0600/디렉터리0700이며 기존 snapshot SHA 불변이다. docs/security_mall_portal_investigation.md에 exact Portal restart 명령과 영향/백업/WSGI 설정/복구 범위를 기록했다.
- ES 검색/키/DB/다른 서비스/전체 테스트/Git commit/push는 수행하지 않았다. 실행 Portal API의 새 분석 표시·증거 링크·권한·실제 브라우저는 미검증이며 완료 표시하지 않는다. 다음은 Portal 한 서비스 파일 반영 및 짧은 재시작 승인 후 기존 읽기 키/CA·조직 정책으로 브라우저 인수를 수행하는 것이다.

## 2026-10-17 Security Mall 7-A/B 실제 ES 읽기 검증

2026-10-17 실제통합재개완료: 최신요청으로수정CLI1파일만갱신한42파일패키지와manifest를준비했고사용자콘솔인증으로실제검증을완료했다. 기존10테스트는반복하지않았다. 2h최소읽기키/6정확인덱스/TLS/폐기401/격리SQLite를유지했고7-C·엔진정책·기존서비스는변경하지않았다.

- [x] MALL-7AB-CLI-HTTP-FIX 분석·로컬수정검증완료(2026-10-17): e50dd618저장기록과배포42SHA·9.5.2공식소스로할당role키의GetUserPrivileges미지원/CLI API계약결함을확인했다. 자기키정보역할상한+기존_has_privileges유효권한검사로최소수정·안전한HTTP코드/단계/조회진행진단을추가했다. 신규3/관련회귀7고유10통과·마지막summary영향1만재확인·변경Python3정적0이다. 실제HTTP숫자/본문은과거기록에없어복원불가며신규키/실ES재실행/VM재배포/서비스변경은하지않았다.

2026-10-17 MALL-7AB-CLI-HTTP-FIX 근거·범위·제한:

- 지정결과 approved-20261017T102713Z-e50dd618의lifecycle/summary/서비스전후파일만읽었다. 발급사용자권한/신규키발급/실할당대조·폐기/401/secret제거성공,cleanup_failedfalse·6unit/Mall674554start4406377불변이다. 최초reader_policy전후에검색이없으며SQLite없음·원stdout/stderr파일없음이다. 최초API가할당role키에서미지원인것은9.5.2 RBACEngine의699~724행에서확인했고자기키ID조회는246~255행에서확인했다. 실제숫자HTTP코드는기존도구가버려es_http_error만있으며본문/상태를봤다고주장하지않는다.
- deploy/security-mall/validate_correlation_triage.py·tests/test_security_mall_reader_auth.py·docs/security_mall_validation_reader_cli.md·docs/security_mall_ab_approved_console.md·이tracker수정, tests/fixtures/mall_reader_policy_legacy.py추가다. fixture는실패패키지Reader/policy두정의만동결한시험문자열이다. 실제CLI서브프로세스에서이전API오류를재현하고수정본의자기ID정보조회/유효권한검사/실엔진호출·400/500/401/403/초과권한/정체성/만료불일치/secret미노출을확인했다. stage/index_queries/document_count/HTTP숫자/고정operation/엔진진입표지만기록하고원문오류나URL/키ID/Authorization은기록하지않는다.
- process/provenance/permissions정의는AST대조불변이며7-A/7-B/위험도/해시/scope/revision알고리즘수정없음이다. 관련10메서드33하위사례통과·summary저장실패단계변경후해당1만추가통과다. 실ES원본/정규화/경보6인덱스모두검색단계미진입/건수미확인이며실데이터0건으로표현하지않는다. 앱/웹/WAF/경보입력확보·7-A/7-B/revision검사는이번실행에서전부미실행이다. 새로성공한것은합성/격리테스트이며실통합은unchecked유지다.
- 다음실검증에는수정본staging/manifest와사용자콘솔의새2h키1개발급·검증·폐기가필요하다. 이전키는이미폐기되어재사용불가다. 이번조사에서새키/기존Portal·수집키/보호암호/ES접속/서비스명령/운영DB접속/Gitcommit/push/merge없음이다. Mall저장소와기존미커밋변경을보존하고전체회귀는반복하지않았다.

- [x] MALL-7AB-LISTENER-FIX 구현·실VM사전검증완료(2026-10-17): ss단일LISTEN행의주소·포트를ipaddress로파싱하고IPv4-mapped를127.0.0.1로정규화했다. wildcard/외부/혼합/포트/PID/ss실패거부·procPID/양의시작tick확인·기존전후신원비교를보존했다. 신규4/기존회귀2고유6개통과·Python2파일정적0·VM42SHA일치·Mall674554/start4406377및6unit전후불변사전검사0이다. 실제키발급/ES통합/서비스변경은수행하지않았다.

2026-10-17 MALL-7AB-LISTENER-FIX 변경·검증·제한:

- deploy/security-mall/run_validation_console.py의snapshot만수정·mall_listener추가, tests/test_security_mall_validation_console.py에관련4메서드추가, docs/security_mall_ab_approved_console.md와이tracker를갱신했다. 이전VMc827b1의부분일치/31bca6의두표기허용소스및SHA를확인하고둘다보존했다. 새AST와이전package대조에서Transport/발급/권한/키저장폐기/main등기존10정의가불변이다. 정규화/인덱스/revision/쇼핑몰코드변경없음이다.
- Windows5통과1skip/32하위사례·VM에서skip된Linux실main시작tick변경1통과다. 신규고유4와기존회귀2가모두통과했고전체테스트는실행하지않았다. IPv4/IPv4-mapped/확장16진표기·외부/IPv6wildcard/다른포트·혼합바인딩·PID누락/복수/0·ss실패·proc누락/오식별/잘못된tick·같은PID의시작시각변경을확인했다. 두변경Python파일Pyflakes0이다.
- VM validation-7ab/mall-listener-20261017-9c1e07의42파일SHA일치·manifest9503834cd80d463efff4dc75fbb77bee6f27689ce11c3e1744d6e9a80ab08ec8·zipbe6f97333273a4cb5003162cdf892475040e6640734a3651d1f8c59d0cac379d다. identity-preflight.json에실제Mall674554/start4406377/currentUID·6unit전후동일·actual_es_requestsfalse/new_api_key_issuedfalse를기록했다. 로컬증거는Git제외state/mall-listener-fix-20261017이다. 기존키/비밀번호읽기·서비스변경·ES통합·DB접속·Gitcommit/push없음이다. 사용자의elastic CA200보고는이번에재실행하지않았다. 전체통합은미완료로유지하고실제발급/통합은사용자가별도로진행한다.

2026-10-17 승인범위변경: 사용자가신규2h최소권한키발급·실ES읽기·신규키폐기를승인했다. 인증은사용자가VM콘솔에서만입력하며Codex/저장된암호파일로전달하지않는다. 이를위한콘솔실행절차를준비하고실사용자입력전에는키발급/ES검증을실행하지않는다. 기존Portal/수집키·ES문서·서비스는보존한다.

2026-10-17 콘솔인증준비·입력대기:

- deploy/security-mall/run_validation_console.py·tests/test_security_mall_validation_console.py·docs/security_mall_ab_approved_console.md를추가했다. 실제TTY getpass사용자입력만허용·기존암호/Portal/수집키읽기없음·정확한6개/read/view/2h·발급자권한·실부여역할대조·private저장·기존CLI실행·finally단일신규ID폐기/401/동일inode파일제거를구성했다. 비정상생성결과/폐기실패는추가발급없이중단하며비밀파일을보존한다. 새탐지/7-C/API/UI/엔진변경없음이다.
- 신규고유7메서드가VM Linux표준unittest에서전부통과했다. 성공/CLI실패/부분결과/권한부족/저장실패/역할불일치/폐기실패/401미확인·다른키폐기금지·TTY없는실CLI·0600exclusive파일을합성자격증명으로검증했다. Windows정상폐기모의검사의mode표현차이만테스트대역으로수정해실패경로재검증했고실POSIX보호조건은완화하지않았다. Pyflakes변경2파일진단0이다.
- VM validation-7ab/approved-console-20261017-c827b1에42파일SHA일치·합성7검사성공을기록했다. zipSHA9a013f351cfa2ec07dc74aed91867fe2936befde99150d9a6be66e393f018f2f다. 기존6user서비스active/running조회만했고수동Mall/다른서비스조작은없다. 기존앱unitfailed기록은보존했다. 사용자에게실콘솔명령을제공했으며입력전에는실키발급/실ES읽기/폐기를성공으로기록하지않는다. 실제결과확인전전체통합task는unchecked다.
- 실제사전경로에서Java의IPv4-mapped주소를문자열검사가거부하는것을확인했다. 첫사용자콘솔결과approved-20261017T100222Z-79aa267b/lifecycle.json은mall_identity_unavailable/exit1·key_issuedfalse로인증전중단이다. 실행기만정확한127.0.0.1또는[::ffff:127.0.0.1]허용으로최소보완하고외부/wildcard주소거부회귀1을추가했다. 수정본31bca6의실제preflight0·42해시일치·6unitrunning·Mall674554를확인했다. manifest391171f76a09e24fd9d9317df8d0e048d471d376d84efd96256995f4152f8ad3/ziped1b250badcb42ecd552d88b9919de47739d218d1a5041e57cedd4c5a839840a다. 고유8검사통과이며새콘솔입력을요청했다. 별도시스템Python의의존성import실패는기존venv로바로잡았고설치하지않았다. 이전결과를키발급실패/실제통합실패로과장하지않는다.

- [x] MALL-7AB-READER-CLI 구현·인증사전검증완료(2026-10-17): 필수--api-key-file·전용경로/openat/UID/0700/0600/링크/TTL·정확한6인덱스·자기권한검사·고정TLS·안전오류를구현했다. 신규고유15메서드/기존영향4통과·변경Python3파일정적진단0·VMstaging40SHA일치다. 실제키발급·폐기·ES접속·서비스변경·전체통합검증은미실행이며별도승인이필요하다.

2026-10-17 MALL-7AB-READER-CLI 변경·검증·제한:

- deploy/security-mall/validate_correlation_triage.py·tests/test_security_mall_live_validation.py·docs/security_mall_validation_reader_plan.md를최소보완하고 tests/test_security_mall_reader_auth.py·docs/security_mall_validation_reader_cli.md를추가했다. Portal키기본값을제거했으며VM의validation-7ab/secrets/reader-run.json만읽는다. 권한자동수정/fallback/발급/쓰기/삭제/TLS우회옵션없음이다. GET자기권한에서cluster/remote/외부index/wildcard/추가권한을거부하고6개자기유효권한후검색한다. 401은실서버만료/폐기/잘못된값을추정하지않으며파일TTL만별도로만료판정한다.
- 새15고유메서드및기존영향4통과다. 실제main/Reader/urllib Request/검색본문/normalize/7-A/7-B/임시SQLite를subprocess로실행하고EStransport만대역으로처리했다. Windows의POSIX전용4개는VM실제파일로검증했다. VM에는pytest가없어설치하지않고표준unittest로고유6개를실행했으며확장된소유권검사만추가재확인했다. 최초합성로그인null가명계약및Windowspytest임시경로실패는테스트만고쳐실패경로재검증했다. VM최초디렉터리생성명령의인용문오류는파일생성전실패했고표준입력스크립트로안전하게준비했다.
- Pyflakes기존wheel로변경Python3파일진단0·문법통과다. VM validation-7ab/auth-ready-20261017-62c894의최종40파일manifest가로컬과일치하며zipSHA9a5b8c105d03aeeb35c00a3e3f014690767c02bf120ee8205a7d0ba5e01786a2다. Windows/VM모의CLI성공은실ES인증/TLShandshake/키발급폐기/현행3종연관성공을뜻하지않는다. 테스트보고서는비밀없는state/security-mall-reader-cli-20261017와VM새staging에만보존했다.
- 발급사용자권한·2hTTL·0700/0600exclusive저장·승인후검증명령·정확한새ID폐기및401재확인절차를문서화했다. 폐기실패시파일을0600으로보존하고자동재발급/무조건삭제하지않는다. 기존키/ES문서/서비스/운영SQLite/H2/registry를읽거나변경하지않았다. VM기존venv만실행했고코드staging/합성임시파일만생성했다. 실제발급과ES통합은승인대기로중단한다.

- [x] MALL-CORRELATION-TRIAGE-LIVE 핵심실제통합검증완료(2026-10-17): c289b4ba실행에서정확한6인덱스raw105/norm105/ACCESS1/AUTH0조회·3종요청묶음8·105provenance대조/hash1·triage20low·격리revision/권한12검사·211읽은문서불변을확인했다. 새2h키발급/자기역할/최소유효권한/TLS·폐기401/secret제거·6서비스/Mall신원불변도성공했다. 실제AUTH60/반복가산/다른조직ES부정시험·장애/7-C는미검증또는범위외이며이완료에서추정하지않는다.

2026-10-17 MALL-CORRELATION-TRIAGE-LIVE 최종실제검증·제한:

- 패키지ab-final-20261017-82cf09/manifest1d9c04bbf60a47addf1975ced4a8ff773baa5ca0b96c0ae13050a73a2c03a197/42SHA일치다. 사용자콘솔인증으로approved-20261017T105455Z-c289b4ba를실행했고CLI/lifecycle0·integration_completetrue다. UTC기준10:55:17.439925/범위[10/16T00:00:00Z,10/17T10:54:54Z),0.503초다. 이전실패기록과패키지는보존했다.
- 실제6인덱스검색모두성공: 현행appraw21/edgeraw80/norm101·과거raw4/norm4·livealerts1다. raw/norm105대조·event.id/request_id/범위/provenance보존·기존ACCESS증거hash1/미해결0·읽은총211문서source/seq/term/version불변이다. 전체ES클러스터재검증이라고표현하지않는다. AUTH실경보0이며합성인덱스는읽지않았다.
- 격리SQLite저장·재조회에서관측105→고유101(app21/web40/waf40)·중복관측4병합·묶음53(complete8/incomplete36/unlinked9/ambiguous0),webWAFonly32를확인했다. 조사큐53의scope일치·raw/norm참조105·ACCESS20low/기존severitylow/가산0·confidence limited를확인했다. 이ACCESS는과거앱증거라web/WAF누락이며3종보강이라고표현하지않는다. 52미경보관측을새운영경보/사건으로만들지않았다.
- 실제자료의격리재생에서sequence1→2·동일revisionno-op/구revision/동순번충돌/발행자교체거부·atomicrollback·재개지속·경보항목ID안정·foreignprincipal/조직/site/host/service거부총12검사true다. 실데이터의로컬권한변조시험이며실제다른조직ES권한부정시험이아니다. DetectionOnly관측40항목·WAF차단true0/공격·출처확정0·지연표시13항목도저장결과로확인했다. 없는증거를생성하지않았다.
- 발급권한/자기키역할/실효read·view만/CA호스트검증·신규키폐기/401/동일inode비밀파일제거성공이다. 새secret파일부재확인·cleanup_failedfalse다. 기존6unit/Mall674554start4406377전후동일·운영사건SQLite미접속·기존키/원문/비밀번호미출력·서비스/DB/ES문서변경명령없음이다. 실제AUTH60/독립반복가산/모호ID재사용/상주장애복구는이번실자료로검증하지못했으며기존격리검증과구분한다.
- 이번저장소변경은docs/security_mall_ab_approved_console.md·이tracker뿐이며이전검증된CLI를재패키징했다. 이전10/전체pytest/UI/Docker/쇼핑몰재배포/로그재수집은실행하지않았다. VM새결과와Git제외state/mall-ab-final-20261017에비밀없는JSON과해시근거를보존했다. 기존두Git브랜치/미커밋작업보존·commit/push없음이다. 7-C진행가능판정만했고API/UI/새규칙은구현하지않고종료한다.


- [x] MALL-7AB-READER-PLAN 계획준비완료(2026-10-17): 실제설정의현행3+기존경보증거3인덱스에만read/view_index_metadata·cluster없음·2시간TTL의새검증키계획과요청예시를검증했다. 발급주체/0600보호저장/TLS/권한검사/정확한신규ID폐기를문서화했다. 실제발급·폐기·권한변경·전체통합검증은미실행이며별도승인전중단한다.

2026-10-17 MALL-7AB-READER-PLAN 범위·검증·제한:

- 최신사용자요청으로추가실제연관검증보다키발급계획준비를우선했다. docs/security_mall_validation_reader_plan.md·deploy/security-mall/validation-read-key.request.example.json을추가했다. VM실제collection/scope설정과기존자기권한조회로정확한6인덱스를확인했으며합성/운영/processing범위는제외했다. 발급자사용자인증에manage_own_api_key와요청인덱스읽기권한이필요하고새키에는cluster/키관리권한을주지않는다.
- 요청JSON계약검사통과:6개고유exact이름·wildcard없음·read/view_index_metadata만·cluster/applications/run_as빈목록·restrictedfalse·2h다. 관리자암호/CA보호파일은stat으로만UID1000/0600/일반파일을확인했고암호원문은읽지않았다. 신규키파일은VM전용0700디렉터리/0600exclusive생성·TLS검증·정확한신규ID폐기·401재확인절차이며아직만들지않았다.
- 이번마무리에서CLI/테스트2파일AST문법통과다. 선택venv에는pyflakes가없어최종정적분석명령은미실행상태로기록하며추가설치하지않았다. 기존통과11사례를반복하지않았다. 최초158기존main파일대조에서tracker만변경·mall11파일전부불변·두브랜치유지다. 현재CLI는Portal키경로가고정되어별도승인후새검증키경로선택만최소보완해야하며기존Portal키를덮어쓰지않는다.

2026-10-17 MALL-CORRELATION-TRIAGE-LIVE 실제부분검증·제한:

- deploy/security-mall/validate_correlation_triage.py와 tests/test_security_mall_live_validation.py를추가했다. 고정TLS127.0.0.1:19200/CA·NOredirect·읽기operation/정확한index·scope/time/500문서상한/정규화full_source증거hash·_mget불변대조·privateSQLite만사용한다. 현재Portal키는과거raw/norm/alerts3개read/view허용·쓰기/관리false이고현행3개는read/viewfalse다. 별도validationreader는2026-10-16T17:51:24.397Z만료며사용자도대체키없음을확인했다. normalizer쓰기키/관리자우회/자동키발급은없다.
- UTC2026-10-16T00:00:00~2026-10-17T08:53:00범위,조회기준2026-10-17T09:03:56.202707Z에서과거raw4/norm4/ACCESS1/AUTH0를읽었다. 현재normalize로주요ID/가명/소유권필드/발생·수신시각/원본참조4대조와원경보정규화hash1을확인했다. ID없는과거4건은unlinked,웹/WAF연결0·신뢰도limited/누락web,waf·실점수20/low로위험도/severity를유지했다. 모든읽은9문서source/seq/term/version을_mget으로재확인해불변이었다. 실제AUTH60·반복3권한거부·현재3종연결성공을주장하지않는다.
- 실제자료를격리SQLite에나눠재생해seq1→2·동일재처리/no-op·구revision/동순번충돌/다른발행자거부·재개순번유지·trigger저장실패rollback·조직/site/host/service검사·경보기반항목ID유지를검증했다. 이는과거자료의일회성재생이며실제상주지연/무로그인시험이아니다. 별도합성CLI검사에서3종연결1·AUTH60mediumseverity·반복점수20/20/30을확인했고실ES에는쓰지않았다. CLI신규고유11사례검증이며최초subprocess2실패는PYTHONPATH누락테스트구성만수정해2건재확인했다.
- 최초VM CLI는불필요GET루트의monitor권한403으로데이터전중단됐다. monitor권한을추가하지않고그조회만제거한V2를한번실행했다. V2는부분검증exit_code4/integration_completefalse를기록했으며PowerShell외부래퍼는비0실행을1로반환했다. 기존키권한변경/ESversion재확인없음이다. 실제엔진의필요39파일Windows/VMsha일치·VMsyntax/import통과,manifest08f708c777710d1a9b1be66fdbbcdf3569bcc57f20e7db206b9f5f1eae7075a4다.
- VM validation-7ab/run-20261017-559f7aff/results-v2/summary.json·final-proof.json,로컬Git제외state/security-mall-ab-live-20261017에비밀없는근거를보존했다. Mall수동674554/시작신원·다른6unit PID/InvocationID/재시작수·선택6설정/JAR/CA/키파일해시유지다. 기존운영SQLite/Native원문/DB접속·서비스명령·새키·ES쓰기·Gitcommit/push/merge없다. 재시작/키준비후전체실제연관검증을추정하지않고unchecked유지한다.

## 2026-10-17 Security Mall 조사 우선순위

- [x] MALL-TRIAGE-07B 로컬구현·격리검증완료(2026-10-17): 기존위험도/severity/탐지ID를유지한별도우선순위·설명·조직격리큐·원자적revision소비를구현했다. 신규43/7-A관련회귀10 고유53사례통과·최종null표현영향3만추가통과·변경Python8파일정적진단0이다. 실제ES/VM배포/PortalAPI/UI/서비스활성화·실제수집인수는미실행이며Mall전환/장애시험보류를유지한다.

2026-10-17 MALL-TRIAGE-07B 변경·검증·제한:

- src/cloud_soc/triage/__init__.py·policy.py·engine.py·store.py, tests/test_security_mall_triage.py, docs/security_mall_triage.md를추가했다. 7-A correlation/store.py·security_mall.py와해당회귀테스트,7-A문서/이tracker만수정했다. 기존CaseStore의수동priority·risk.py/규칙·원본경보/사건을바꾸지않고기존파서/normalize·탐지증거hash·LogPrincipal·SQLite트랜잭션을재사용했다.
- risk20/60을base로유지하고3종증거개수에는0점을준다. 같은scope/가명/키버전/관측IP의현재이전300초·검증된WEB-ACCESS/not_owner·고유웹관측3건부터(n-1)*5/max15만가산한다. AUTH여러요청은기존60에이미반영돼중복가산하지않는다. 0..100·critical80/high60/medium30/low정책을한파일에모았다. 누락/해시미확인에도고위험항목을남기며confidence/completeness·지연/출처불확실성을별도로반환한다. 미경보관측base는null/우선순위0으로미측정을위험도0과구분한다.
- 고정설명/규칙ID/숫자·허용증거참조/event.id만전달하며비밀/원문을복사하지않는다. 앱권한거부사유/403원인후보·DetectionOnly/차단관측null또는false·로그인결과를분리하고공격성공/출처인증을확정하지않는다. 정규화hash와경보참조일치만확인하며원본ES바이트재검증/공격성공확률로표현하지않는다.
- 7-A에전용revision_state(publisher/sequence)와경보evidence목록만최소보완했다. actualledger변경과동일트랜잭션에서만순번증가·no-op/실패는불변이며snapshot도동일읽기시점이다. 4→5전용테이블업그레이드는합성DB에서만검증했다. 7-B는범위[시작,끝)/scope별전체큐를원자교체하고동일순번/내용no-op·작은순번stale·동순번다른내용conflict·다른publisher/정책/binding을거부한다. publisher/order는서명이아닌신뢰로컬생산자계약이며브라우저입력금지다. 경보index/id기반항목ID와기존사건경보참조는묶음ID변경과무관하게유지한다.
- 최초전용34사례전부통과후event.id/403원인/설명·상한/순번/저장한도추가영향43사례전부통과했다. 마지막미경보base null영향3만재확인했다. 7-A관련기존10사례만회귀실행해통과했으며전체49/전체Python/UI·실VM/ES검사는반복하지않았다. SQLite실제trigger실패에서이전큐/순번보존·새revision/구revision/재개/범위격리/다른DB무변경거부를확인했다. 정적Python8파일Pyflakes0이다.
- Git제외state/security-mall-triage-7b-20261017의before.json/verification.json에기존파일및코드해시·검사근거를보존했다. main152/mall11파일대조에서승인기존5파일만변경됐고브랜치codex/security-mall-collection·codex/access-security-audit를유지했다. SSH/VM/ES접속·서비스조작·키발급/실로그·실DB접근·Gitcommit/push/merge없다. 실제ES/site binding/증거보존기간·발행자복구·실부하/OS권한·7-C서버API/원문권한/UI는미검증후속이며이번로컬완료에서추정하지않는다.

## 2026-10-17 Security Mall 요청 증거 연관

- [x] MALL-CORRELATION-07A 로컬구현·격리검증완료(2026-10-17): 최신 요청으로 Mall systemd 전환을 보류하고 요청 단위 증거 연관·독립 SQLite ledger·기존 경보 참조/해시 연결을 구현했다. 신규 고유49사례 통과·신규4Python 정적진단0이다. VM/실ES/Portal/UI/상주수집 연결은 미실행이며 실제 배포/수집 인수를 뜻하지 않는다.

2026-10-17 MALL-CORRELATION-07A 변경·검증·제한:

- src/cloud_soc/correlation/__init__.py·security_mall.py·store.py, tests/test_security_mall_correlation.py, docs/security_mall_correlation.md 및 이tracker를 추가/수정했다. 기존 normalize/앱·Native/TSV 파서, detector event_evidence/event_fingerprint, 경보 provenance 및 LogPrincipal 조직 정책과 기존 CaseStore 방식의 SQLite 트랜잭션을 재사용했다. 기존 분석가 사건/경보/정규화/탐지/위험도/Portal/Java소스는 변경하지 않았다.
- 서버 site/조직/host/service·exact원본/정규화/경보allowlist·기존27자RID·기본30초최대span으로 후보를묶는다. 사이트는검증된전용index/host binding이고입력이주장한site는무시한다. 같은host/index의여러사이트를구별할계약이없으면확정불가다. missing/incomplete·legacy unlinked·근접복수web ambiguous를구분하고시간초과RID재사용을분리한다. event.id·각raw/norm참조·수신/발생시각·가명/키버전을보존하며원문/개인정보/비밀은복사하지않는다.
- WEB-ACCESS-01/WEB-AUTH-01은기존경보의exact raw/norm위치+detector hash로연결하고해시없음/누락은unresolved다. AUTH여섯요청을여섯묶음으로보존하며새탐지/경보/사건을생성하지않는다. 기존medium/60/high를분리해전달한다. DetectionOnly는차단false·WAF증거없음null, 일반403원인미확정·앱권한거부동반은consistent까지만표시한다. origin_authenticated/compromise_confirmed=false·위조/프록시/누락/재사용불확실성을유지한다.
- ledger를배치원자병합하고snapshot마다연관/링크를함께계산한다. 재처리결정적ID/revision·중복관측alias·충돌failclosed·용량/증거fanout한도를검증했다. 지연에의한재분할은묶음ID를바꿀수있어7-B는scope새revision전체교체가필수다. 기존다른DB/손상파일은readonly사전검사로무변경거부·binding을직렬화하며원문열람권한은기존Operations별도검사를유지한다.
- 최초공용pytest임시경로권한으로35setup오류→전용state경로로실행했다. 35중25pass/10fixture실패는TSV필수스키마표식누락만수정해실패10만pass로검증했다. 시각소수점/lookup/fanout보강후관련47pass·필드/모호상태영향8pass·다른DB/손상보호신규2와재개영향2의4pass로최종고유49검증이다. 미사용import1은정리후정적검사만재확인해Pyflakes진단0이며전체Python/UI/과거단계검사는반복하지않았다.
- Git제외 state/security-mall-correlation-7a-20261017/verification.json에코드SHA/실행결과/보존근거를기록했다. 두브랜치 codex/security-mall-collection·codex/access-security-audit 및기존main129파일기준(이전문서4변경만존재)/mall11파일을확인했다. 실SSH/VM/ES접속·서비스조작·키발급·실로그읽기/DB연결·Gitcommit/push/merge없다. 실제읽기어댑터/사이트정합/기존경보해시/조직API/실부하/권한·보존기간검증과7-B우선순위/PortalUI는별도단계다.

## 2026-10-17 상주 수집 복원력·재부팅 준비

- [x] MALL-REDIRECT-06E2A-FIX 코드·CLI·읽기전용사전검증완료(2026-10-17, 실제전환제외): 상대root 단정 오류를 고정출처/포트/경로 검증으로 대체했다. 신규43사례 및 VM 필수기존22검사/정적12파일 F821/F8230·실제APP/WAF probe·Gate/SSH/Windows0·13파일SHA일치를 확인했다. 수동674554 및 unitdisabled/failed·다른6서비스/기존288문서/active·GZIP/상태를 보존했다. 실인증VM POST·DB접속·서비스전환은 미실행이다.

2026-10-17 MALL-REDIRECT-06E2A-FIX 범위·근거·제한:

- 최신사용자요청으로 실제전환보다 검증도구수정을 우선했다. mall_http.py/mall_business_check.py·mall_preflight.py/LF run-mall-gate.sh·tests/test_mall_redirects.py/fixtures/mall_owner_legacy.py 및 docs/security_mall_redirect_validation.md·MIGRATION/TOOL-GATE/RUNBOOK/이tracker를 변경했다. 옛private전환/owner도구는 실패증거로유지하며 재실행금지·새CLI사용을 명시했다. Java앱/SQL/H2/unit/다른서비스원본은 변경하지 않았다.
- 원본legacy main subprocess가 정상절대root에 종료1을 내는 것을 합성HTTP에서 재현했다. 신규 실제urllib/CLI는 상대/같은출처/명시peer만허용하고외부·포트·userinfo·경로·query·sessionURL·제어문자·누락·상태·반복을거부한다. 자동따라가기0·검증후명시GET최대1이다. Windows고유43사례검증·VM43/실패오류skip0와필수기존Gate22통과다. Windows합성os.getuid호환4실패는합성UID만수정해실패경로를재검증했다. 첫VM Gate는Servlet sessionURL을거부1로중단했고쿠키사전준비로수정한뒤새Gate0이었다. 실제보안정책완화·오류무시없다.
- VM최종 mall-redirect-preflight-v2-20261017/staging13파일manifest f116a8dfe5337b6f6600bc61a6b3fb1126b18705204a0ad59837e9407d3fd10c가원본/local/VM일치다. mall-gate-redirect-fixed-v2-20261017/gate.json·final-proof.json과로컬Git제외state/mall-redirect-fix-20261017에증거를보존했다. actual APP18080/WAF18082는각각동일출처절대302/login→200이며Gate본문/SSH/Windows0다. 미래승인에는현재receipt를재사용하지않고새Gate/신원/해시검사가필요하다.
- 실제journal은UTC07:10:18.890399요청정지→18.974506exit143→19.001081stopped다. rollback SIGTERM15맥락이며모든143을정상으로일반화하지않았다. unit SuccessExitStatus미설정/failed증거보존·reset/start/enable없음이다. Gate는disabled/MainPID0/정확한143exit-code/NRestarts0인기존기록만허용한다.
- Mall674554/starttoken4406377·다른6서비스PID/InvocationID/NRestarts불변, 보호설정/HMAC/JAR/CA·registry/checkpoint범위유지다. 기존7index288문서source/seq/term불변·audit active1895/GZIP해제5901 SHA/EOF/CRC검증이다. GET부수edge원본8/norm8/processing8·appraw0증가는실제3종시험으로표현하지않는다. 실DB접속/실인증POST/서비스조작0이며가동H2전문동일성이나현재실owner주문200은미검증이다. Dry-run의실제HTTP는합성서버, 서비스/DB/ES/rollback은대역이다. 실제전환태스크는unchecked유지하며별도승인후H2전후기준선/업무/3종수집인수가필요하다. Gitcommit/push/merge·재부팅·새키/알림없고두저장소브랜치/기존변경을보존했다.

- [ ] MALL-APP-06E2A-TWO-STOP-TRANSITION 전환실패·수동복구완료(2026-10-17): 승인된전환1회로349259정상종료→닫힌backup/copy기준선계정2/주문1→unit671877/HTTP200까지진행했다. 임시업무검증이Location상대root만허용해정상절대root redirect를거부하고주문조회전에실패했다. 추가전환없이unit만stop/disable·2차닫힌backup기준선일치후수동674554/HTTP200·로그인성공으로복구했다. unitdisabled/failed/MainPID0·enable없음, 업무/최종systemd인수는미완료다.

2026-10-17 MALL-APP-06E2A-TWO-STOP-TRANSITION 실행근거·복구·제한:

- 최신2회정상종료승인에따라준비/신원token2440837/UID1000/고정명령·Java17.0.20.1/JAR7dddb416b370a939a4c78afcb6ac221bd14ad611625731cf79e5497f4c6de241·SQLnever/Hibernateupdate·H2경로·오프라인번들/증거/공간약11GB·복원계정을확인했다. 새LF Gate22검사/정적8파일·원본/local/VM9SHA644a7fe5ea1cfff0fd7db4c9eab8f8a5626131658af5ea8201032ae1aba0f7d6·body/SSH/Windows0 후pidfdSIGTERM을실행했다. Gate의필수22검사외에과거전체검사는반복하지않았다.
- 첫종료후FD/OS잠금·자식/포트해제를확인하고0700 master/0600파일backup을생성했다. copy만H2readonly로검사해실제PUBLIC.USERS/ORDERS계정2/주문1·PK/FK/열/스키마계약을통과했다. 첫unit671877은같은JAR/DB/설정/HMAC/never·loopback/HTTP200이었다. 기존계정/주문생성·삭제는없다.
- 임시approved_owner_check.py가status302/Location=='/'/cookie조건으로성공을판정해동일origin절대root를누락했다. 최초소유자login은HTTP302/서버login success event99c0692b-744b-45eb-9c9c-4f289b1d6284/request_idatMfRIRNbmfsFtbl83ggogAAAAc였고주문GET은실행되지않았다. 당시ownerLocation원문은미기록이며복구계정에서절대root true/상대root false/cookie1/login success로검증결함을재현했다. 앱인증실패로판정하지않는다. 최초복구로그인검사도같은조건때문에오판했고안전한응답분류/감사근거로복구로그인/홈/로그아웃을확인했다.
- 승인된실패처리로Mallunitstop0/disable0 후2차정상종료를확인했다. Java143종료로unitfailed/MainPID0가남아첫복구준비가inactive단정에서차단됐지만실제잔류/포트/잠금부재를확인한뒤복구를완료했다. recoverycopy inspect0/compare0·계정2/주문1·ID/소유관계/스키마SHA73b35c5e6bee1661629804fb79fd050cfee98c920aa7d9474f4bcd8fe6c5016b 일치다. DB덮어쓰기/자동복원없이동일명령수동674554로복원했고unit은disabled/failed/ExecMainStatus143/NRestarts0를보존한다. 정상전환후최종start/enable은없으며추가시도0이다.
- master는VM mall-app-two-stop-20261017/backups/pre 및recovery, SHA9d7c72c16a319e708f8d6a9cd92fb4a1d4b14cbb7a26ff807ffed73555cb611d /4392f71ea8b928febda93ead88ab77085c18d557ff1d7555b38c403ba35581b2다. 원본DB활성JDBC/실행중복사·비밀출력없음·master/copy검사전후무결성통과다. 물리SHA변화와논리기준선일치를구분하며미선택상세전체동일성을주장하지않는다.
- 추가요청없이최초로그인의기존저장결과에서app1/access1/waf1 원본3/정규화3·request_id/scope/고유eventid/provenance/개인정보보호를확인했다. DetectionOnly/blockedfalse·새901001Native/private각0이다. 소유자주문200/타인403/비로그인401은이번엔미검증이며시도하지않은업무인수를성공으로표시하지않는다.
- 기존7인덱스231문서source/seq/term불변(이전219포함)·최종appraw3/edgeraw16/norm19/processing19 증가는실제login/복구/health부수기록이다. 기존Portal조회3인덱스증가0·active758/GZIP해제5901 SHA/EOF·CRC/Apacheprefix·HMAC/설정/JAR/CA/세션키·SQLite/registry범위보존이다. H2동일inode709758·현재674554소유/40960바이트다. 다른6서비스PID/InvocationID/NRestarts·Portal/ESreadiness유지이며restart/변경없다.
- 산출물 docs/security_mall_app_systemd_transition_validation.md·MIGRATION/RUNBOOK현재상태포인터·이tracker, 로컬Git제외state/mall-app-two-stop-20261017의비밀없는검증JSON과VM동일run의protectedbackup/receipt다. credentials/masterDB/비밀설정은로컬전송/커밋하지않았다. 임시실행도구만사용했고실제앱/규칙/unit원본을고치거나추가전환하지않았다. 두Git브랜치/기존변경보존·Gitcommit/push/merge·새키/Slack·Docker/VM재부팅없다. 이번실패와복구가확정됐으므로중단한다.

- [x] MALL-H2-OFFLINE-BASELINE 도구구현·합성검증완료(2026-10-17, 실제DB/전환제외): 동일H2 2.4.240/Java17용 inspector·Python CLI/빌더·고정검사경로/IFEXISTS/read-only/해시·metadata/수량/ID/소유관계 검사를 구현했다. Ubuntu 기준선32사례/skip0·새Gate3 통과, Windows31사례/권한skip1·Gate3 통과이며 최종스키마변경은영향4건만재검증했다. 실제Mall/H2는종료·연결·복사하지않았다. 전체실행Gate·실백업·실데이터기준선·전환·사후전체수비교는미검증이다.

2026-10-17 MALL-H2-OFFLINE-BASELINE 변경·검증·제한:

- JPA User(users)/Order(orders)/user_id 관계와 Item/OrderItem/Board 기본매핑을확인했다. 저장된VM설정메타데이터의실제URL/드라이버2.4.240을재사용하며 살아있는DB본문을읽지않았다. 실제DB스키마확인주장이아니라첫오프라인copy검사때metadata로대조할계약이다. SQLnever와Hibernateupdate/빈사용자·상품seed의차이를유지한다. 신규API·앱빌드·H2console/TCP·JVMattach는없다.
- 신규 deploy/security-mall/boot-services/h2-baseline의 MallH2Baseline.java/offline_baseline.py/build_bundle.py 및 tests/fixtures/MallH2Fixture.java·tests/test_mall_h2_baseline.py·test_mall_h2_gate_preparation.py를작성했다. 기존 mall_preflight.py에 offline_tool_ready(고정번들/테스트증거/코드SHA/여유공간)를연결하고 LF run-mall-gate.sh의새staging경로를반영했다. MIGRATION/TOOL-GATE/RUNBOOK·이전app사전기록포인터와 docs/security_mall_h2_offline_baseline.md를갱신했다. 다른WAF도구/공유helper/units/Java앱코드는변경하지않았다.
- Java17 release bytecode를기존WindowsJDK21로컴파일했다. bootJar의동일H2 driverSHA29b70e427cc1c40cdc376283adbb0cc62853073797bb5fe5761f81fe73d57ce0를고정해버전불일치를거부한다. 오프라인전용root/사본regularfile·nlink/심볼릭링크·권한·경로옵션을검사하며 고정READONLY/IFEXISTS/traceoff·고정SELECT만실행한다. 원백업SHA와copy전후SHA/metadata를비교한다. 개인정보열의값/비밀/HMAC/계정명/주문상세/예외원문은출력하지않고 credentials는0600JSON→stdin으로만전달한다.
- 기준선은계정수/주문수·정렬ID/주문ID:계정ID/스키마SHA·원backupSHA·버전/시각/readonly관계결과다. null/orphan·빈테이블/파일누락/오류schema/타입/enum/PK/FK·손상copy를실패처리했다. 실제합성JDBC로INSERT/UPDATE/DELETE/DDL4종거부·파일불변을확인했다. compare는동일건수ID/소유자변경까지탐지하되 개인정보/금액/상태등미선택상세변조·미접근손상페이지의완전검사와동일하지않다.
- Windows최초27중25pass/1failure/1setup오류는잠긴합성파일테스트선행해시와Java미존재오류분류문제로해당2건만수정/재검증했다. VM최초27pass·새SQL/URL2·스키마형식보강영향4(정상1+새3)를검증해32개고유사례를확인했다. Windows symlink생성권한분기를명시skip으로고쳐그1건만확인했으므로최종Windows31사례/1skip·VM32/skip0로구분한다. 새Gate준비3검사는양쪽pass·직접관련Python5파일F821/F8230이다. 과거전체테스트/전체Gate/앱HTTP/로그인/실수집을반복하지않았다.
- 최종번들manifest ef5bbf342c7fda194aae6b99d25eccec66092f2fbc23f8458a9be35c54f42cf4, 새Gate9파일manifest644a7fe5ea1cfff0fd7db4c9eab8f8a5626131658af5ea8201032ae1aba0f7d6가Windows/source/staging/VM에서일치한다. VM offline-db-baseline/bundle-20261017-schema·validation-result.json·gate-validation.json, mall-app-offline-preflight-20261017/staging 및로컬Git제외state/mall-offline-baseline을근거로보존했다. 실제실행Gate가아닌오프라인준비함수/합성CLI검증이며 실제Gate는승인직전새로실행한다.
- VM전후Mall349259/starttoken·Portal485310/WAF593305/수집421214·421217·421218·421219 PID/InvocationID/NRestarts/상태불변이다. 실제H2/로그/ES문서읽기·복사/수정·서비스stop/start/enable·Docker/reboot·새키·Slack·Gitcommit/push/merge없다. 두저장소브랜치/기존미커밋변경보존이다. 이전승인시도는미완료로유지하며 이번도구완료를실제DB기준선/전환으로승격하지않는다.
- 다음별도승인은 Gate/신원/공간준비→정상종료/잠금해제→닫힌DBmasterbackup/해시→별도copy inspect성공전새unit기동금지→실패시Mall단독복원 순서여야한다. systemd기동후전체수량을기존API로비교할수없으므로미검증으로기록하고, 반드시필요하면추가승인된사후정상종료/새backup/compare 구간또는별도안전조회방법을정해야한다. 이번에는그추가종료/서비스전환을하지않았다.

- [ ] MALL-APP-06E2A-APPROVED-TRANSITION 기준선단계중단(2026-10-17, 실제전환미시작): Mall 한 서비스 전환1회는 승인됐지만 종료전 계정/전체주문 기준선 확보가 필수다. 기존 `/admin`은회원/상품만, `/order/complete/{id}`는소유권검사단건만 제공하고 전체주문 count/식별조회 경로가 없다. 안전한 전체기준선을 확보할 수 없어 사용자지시대로 Java종료 전에 중단했다. 계정수/주문수는미측정(null), 신규Gate·unit등록/start/enable·실DBbackup·rollback은 미실행이다.

2026-10-17 MALL-APP-06E2A-APPROVED-TRANSITION 실제확인·남은조건:

- 현재349259/token2440837/UID1000·기존명령/cwd/loopback18080·Java17.0.20.1·기존JAR7dddb416b370a939a4c78afcb6ac221bd14ad611625731cf79e5497f4c6de241·직접/WAF HTTP200을읽기전용으로확인했다. H2 inode709758/28672바이트/기존0600/JavaFD·OS잠금·CLInever/Hibernateupdate·보호HMAC/설정/JAR해시·active/GZIP보존검사정상이다. 잠긴DB본문/계정·주문행을읽거나복사/직접열지않았다.
- Portal485310/WAF593305/수집421214·421217·421218·421219 active/running을유지하며 Mallunit미등록/inactive/MainPID0다. ES기존219문서source/seq/term보존·checkpoint/registry메타데이터를기록했고 기존문서쓰기/삭제없다. 읽기전용SSH종료0/SCP0이며새Gate0으로오인하지않는다. health GET 부수웹/WAF기록은3종수집검증이아니다.
- 유일HomeController·OrderRepository·admin템플릿·빌드의관련범위만확인했다. JAR에도HomeController하나/Actuator없음·H2consolefalse를확인했다. 일부fixture/연속ID추측을전체주문기준선으로대체하지않고 console/TCP/attach/새API배포로우회하지않았다. 안전한인증관리조회방법을별도설계하거나사용자가사전조건을변경해야재개가능하다. 과거Gate/22성공검사를재실행·재사용하지않았다.
- 산출물 docs/security_mall_app_systemd_transition_blocked.md·이tracker 및 Git제외state/security-mall-app-approved-transition-20261017의읽기전용결과다. 두저장소브랜치/미커밋변경을보존하며서비스종료/재시작·unit등록/start/enable·강제kill·DB/log/ES기존자료변경·Docker/reboot·새키·알림·Gitcommit/push/merge없다. 실제전환미시작이므로rollback불필요/미실행이며이번작업은중단한다.

- [x] MALL-APP-06E2A-FINAL-PREFLIGHT 사전검증완료(2026-10-17, 실제전환제외): 수동349259/Java17·동일JAR/비밀설정/H2 inode·FD·잠금·CLI never·app unit 계약을 확인했다. 신규22검사(실패/오류/skip0), 직접참조8파일 F821/F8230, 실제LF Gate/SSH/Windows0, 실행중 stopped-check 의도된1·백업금지를 확인했다. app unit 미등록/미기동·다른6서비스PID유지·기존219 ES문서/active758·GZIP5901/registry·checkpoint 보존이다. 실제정상종료·H2닫힌백업·신규systemdJava·업무인수·신규3raw/3norm·rollback/부팅은 별도승인 후 미검증이다.

2026-10-17 MALL-APP-06E2A-FINAL-PREFLIGHT 근거·변경·제한:

- 최신요청은 Mall 사전검증만이며 WAF성공 이후 다른서비스전환/재부팅/장애주입을 시작하지 않았다. 새 mall_preflight.py 및 LF run-mall-gate.sh, tests/test_mall_app_preflight.py와 docs/security_mall_app_systemd_preflight.md·MIGRATION/RUNBOOK만 범위로 작성했다. 기존 WAF도구/helper/unit/Java코드는 바꾸지 않았다. 본문정책+합성backup+실제subprocessCLI22검사·정상/11실패 Dry-run은 서비스/DB/수집 관측대역이며 live전환 CLI 또는 실제H2복구 검증이 아니다.
- VM mall-app-preflight-20261017/staging9파일 manifest a59ec5a808eaa0fe8e9d145516e6ef0b4ab8498deb1ff623af9ae30f6111c313 원본/localstage/VM일치다. 최종 mall-gate-final-checked-20261017/gate.json의 actual unit구문/readiness/HTTP/중복guard/기존로그보존·정적분석·22검사 통과 및 Gate/SSH/Windows0을 기록했다. stopped-check는 실행중 PROCESS_CHILD_OR_PORT_STILL_PRESENT/SSH1로 정확히 차단했다. 성공검사를 별도 재실행하지 않았다. 첫Gate는 secrets에 기존DB비밀번호 property가 있어 안전하게1로 중단했고 값없이 키이름을 확인한뒤 HMAC+DB비밀번호 두 필드만 허용·초기화override거부 회귀를 추가했다.
- Mall349259/시작token2440837/자식0·JAR7dddb416b370a939a4c78afcb6ac221bd14ad611625731cf79e5497f4c6de241·기존HMAC/DB비밀번호/설정과 Portal485310/WAF593305/수집421214·421217·421218·421219 PID·InvocationID·NRestarts가 유지됐다. H2 inode709758/0600·현재Java잠금은 메타데이터로 확인했으며 내용/행수/실DBhash/backup은 읽거나 만들지 않았다. 감사18이벤트/request_id9·과거누락호환/개인정보allowlist를 확인했고 로그 원문/비밀값을 출력하지 않았다.
- 기존7인덱스219문서source/seq/term불변·원래Portal3인덱스증가0·checkpoint/registry inode/구성/대상보존이다. GateGET의 정상부수기록 edge原2/norm2/processing2는 새3종시험이 아니다. appraw증가0, 강제회전없음·기존active758/GZIP해제5901 SHA/EOF·CRC 통과다. 가동DB전체바이트불변 또는 계정/주문 보존을 추정하지 않는다.
- SQLinit 파일always를 CLInever가 덮어쓰며 unit/복원에 동일never필수다. ddl-auto=update와 빈사용자/상품 테이블seed InitData는 별도라 실제전환 전에 계정/주문 기준선·정상종료·잠금해제·닫힌DB백업/해시·사후업무검사가 필요하다. app/stop.sh에는token검사가 없어 승인후종료직전 신원재검증 절차로대체했고 app/start.sh를 재사용하지 않는다. 자동DB덮어쓰기/강제kill금지·app만복원·모든인수후enable을 문서화했다.
- 로컬 state/security-mall-app-preflight-20261017의 baseline/initial/gate/final-proof와 VM같은private경로를 근거로 보존했다. 기존main129/mall11변경 및 codex/security-mall-collection / codex/access-security-audit 브랜치를 보존한다. 패키지설치·새키·service stop/start/enable·DB/log/ES기존문서쓰기·Docker/reboot·Slack·Gitcommit/remote변경없다. 현재준비완료는 전환승인이 아니며 별도승인+새Gate+업무기준선 후에만 진행한다.


- [x] MALL-WAF-06E2A-APPROVED-TRANSITION WAF실제전환·인수완료(2026-10-17): 최신명시승인으로LF새Gate14항목/45검사·Gate/SSH/Windows0·PID/해시재확인후단1회전환했다. 수동549681/자식549682 정상종료→systemd593305/자식593307, HTTP200·DetectionOnly·CRS32/900990335·신규9010010·새로그인request_id3종일치·원본3/정규화3 자동저장/provenance·기존범위/192문서·상태보존을통과한뒤enable했다. enabled/active/running/NRestarts0, rollback불필요·추가시도없음이다. Mall/Portal/ES/수집4개는그대로이며전체6-E-2A무로그인/재부팅인수는미완료다.

2026-10-17 MALL-WAF-06E2A-APPROVED-TRANSITION 실제근거·범위·제한:

- 기존549681/549682의token3748420/3748424·UID1000·고정명령hash·소켓1을재확인했다. Windows원본/VMmanifest14SHA31e2ce6fb8d2c63c222258dce42a2e28b9e7fcf9a56fff66ce2ec62b241764c0·LFwrapper28cb5d9b104a4bce898eb6d7bd14613fbab8ef1fd9845e30cd1580975db1fec9 일치다. run-gate.sh로새waf-gate-approved-transition-20261017 Gate14/내부31+CLI14·정적분석·실제구문/readiness/보존/복원준비를통과했고body/SSH/Windows모두0이었다. 최신요청의freshGate필수검사만실행했으며별도과거전체테스트는반복하지않았다.
- 동일해시/300초내receipt로실제waf_transition.py migrate --execute를1회호출했다. 15:07:55.718KST graceful-stop→15:07:57.813KST 부모/자식/포트해제후기존등록된동일unit을재사용해start했다. 새foreground/cgroup·PID593305/자식593307·loopback18082·단일소켓·정상HTTP200을검증하고모든사후조건뒤enable했다. 15:08:35.114KST완료/외부종료0/NRestarts0다. 강제종료·이중기동·unit덮어쓰기/다른서비스재등록은없다.
- 안전한가상계정실패로그인HTTP302 request_id atMQvoRNbmfsFtbl83ggnQAAAAI로앱1/웹1/WAF1·원본3/정규화3을상주수집기가자동반영했다(약36.459초). app event_id ce667b69-5326-4bc5-9069-9345450fa59c·세event.id고유·정확raw index/id provenance·조직/호스트/서비스·요청/수신시각구분·원문/비밀허용목록검사를통과했다. 홈200 ID는별개 atMQvoRNbmfsFtbl83ggnAAAAAE다. request_id는상관ID이며출처인증/공격성공증거로표현하지않는다. Native/private신규901001각0·CRS32/중복0/900990335/setup선행/DetectionOnly/blockedfalse를유지했다.
- active기존379바이트·과거GZIP5901 원범위SHA/전체EOF·CRC, Apache기존3prefix/inode/0600·설정/HMAC/JAR/CA/Portal세션키·H2동일경로/inode/프로세스·SQLite scope/target/inode·registry2개를보존했다. 기존ES7인덱스192문서source/seq/term불변·Portal기존3인덱스증가0·green이다. 전체증가appraw1/edgeraw8/norm9/records9에서대상3raw3norm외6raw6norm은Gate/기동/홈readiness부수기록이다. 정상checkpoint진행/로그append를허용하고실행DB전체바이트불변을주장하지않는다. 강제회전/새회전발생주장은없다.
- Mall349259/Portal485310/수집421214·421217·421218·421219의PID/상태/재시작수와보호설정을유지했다. WAF만enabled/active이며실제rollback은불필요/미실행이다. Mall전환·다른서비스재시작/변경·Docker/ES재시작·키발급·기존문서쓰기/삭제·로그삭제·Slack·새룰·Gitcommit/원격작업·VM재부팅없다. 부팅/무로그인/실제장애복구는추후승인범위이며이번완료로확대하지않는다.
- 산출물 docs/security_mall_waf_systemd_success_validation.md 및현재상태포인터(TOOL-GATE/MIGRATION/RUNBOOK/WAF-PRECHECK·resilience/final-preflight)와이tracker다. VM새run의receipt/preflight/es-before/progress/result/final-state·WAFconf보호백업,로컬state/security-mall-waf-approved-transition-20261017의Git기준선/비밀없는결과3파일을근거로보존했다. 기존main128/mall11파일·두브랜치를문서대상외보존한다. 과거실패기록을지우지않고WAF한서비스인수완료후중단한다.


- [x] MALL-WAF-06E2A-FINAL-PREFLIGHT 최종사전검증완료(2026-10-17, 실제전환제외): PS7.6.5 here-string→SSH bash-s의끝CRLF가exit인자0\r를만드는원인을무해footer로재현했다. Bash-n0/실행2/LF대조0을확인하고새run-gate.sh만LF로작성했다. 회귀8건·외부종료0/1/2/3전파·14파일SHA/줄바꿈일치·새Gate14항목(31+14검사)·실제SSH/Windows종료0을확인했다. 수동549681/자식549682·unitdisabled/inactive 및기존186문서/서비스·active/GZIP·상태보존, 실제전환/enable은없다.

2026-10-17 MALL-WAF-06E2A-FINAL-PREFLIGHT 원인·검증·제한:

- 원래오류는저장소셸파일이아닌PowerShell메모리전달스크립트에서발생했다. 과거명령/오류를기반으로동일종료문만현재PS7.6.5/UTF8 pipeline에보내2LF+끝CRLF1을캡처했다. 입력말미hex220a65786974202224636f6465220d0a, Bash-n0이지만실행2/numericargumentrequired이며LF대조0이다. 과거stdin원본바이트는없으므로이번합성캡처를원본으로주장하지않는다. PythonGate0과외부오류를구분하고예외를무시하지않았다.
- Windows실원본↔VMmanifest14파일SHA/줄바꿈수가일치한다. waf_transition.py CRLF568·기존CLI180·동결재현350은Python명시인터프리터에서정상이며변환하지않았다. units/다른실행도구LF도유지했다. 비밀설정·DB·실제로그/registry/checkpoint는줄바꿈변환하지않았다. 신규run-gate.sh v1만UTF8/BOM없음/LF36줄로준비했고SHA28cb5d9b104a4bce898eb6d7bd14613fbab8ef1fd9845e30cd1580975db1fec9, VM waf-final-preflight-20261017(0700)의셸0700/테스트0600·해시일치다.
- 새셸은기존Python Gate/manifest31e2ce6fb8d2c63c222258dce42a2e28b9e7fcf9a56fff66ce2ec62b241764c0를exec해0/1/2/3을그대로전파하고잘못된인자/범위·run재사용을거부한다. migrate/stop/start/enable모드·오류무시·사후exit문은없다. Bash실제문법과실행/대역8검사통과·실패/오류/skip0이다. sudo/system패키지설치는없다.
- 최신사용자요청이최종Gate모든조건재확인을요구하여새waf-gate-final-readiness-20261017에서기존31+14검사만필수Gate로실행했다. body0/receipt성공/실제직접SSH $LASTEXITCODE0/Windows명령0이며14항목모두통과했다. 정적F821/F8230·실제요청/전환/rollback대역·unit3구문·Apache실제Syntax/CRS32/900990335/DetectionOnly·HTTP/TLS/readiness·PID/자식/guard·active/GZIP·복원준비를확인했다. 변경없는receipt3/기존32/전체Python·UI는반복하지않았다.
- 최종WAF549681/549682·token3748420/기존명령·수동unitdisabled/inactive/MainPID0/NRestarts0, Mall/Portal/수집4개PID/상태/설정·HMAC/JAR·H2동일경로/inode·SQLite scope/target/inode·registry2개보존이다. active379/GZIP5901 SHA/EOF·CRC통과·기존7인덱스186문서source/seq/term불변이다. Gate무해GET1은HTTP200/request_id atMPHu8BPEW31BYawfVX3AAAAAM이며추가edge原2/norm2/record2는정상부수기록이다. 앱raw0·새로그인/주문/공격요청은없고3종통합시험으로표현하지않는다. 신규private9010010·DetectionOnly유지다.
- 산출물 deploy/security-mall/boot-services/run-gate.sh·tests/test_waf_shell_transport.py·docs/security_mall_waf_final_preflight.md·TOOL-GATE/MIGRATION·이tracker다. 근거는로컬state/security-mall-waf-final-preflight-20261017의Git기준선/transport-proof/final-proof/줄바꿈대조/파일해시와VM동일경로·새Gate receipt/preflight/es-before다. 기존main125/mall11변경·두브랜치를범위외보존했다. WAF/다른서비스stop/start/enable·ES수정/삭제·키발급·로그변환/강제회전·Docker/reboot·Slack·Gitcommit/원격작업없다. 실제정상종료/새systemd효과/실제rollback/새로그인3raw3norm은미검증이며별도승인후새Gate/외부명령모두0으로만가능하다. 이번엔사전검증까지만중단한다.


- [x] MALL-WAF-06E2A-FULL-PATH 구현·사전검증완료(2026-10-17, 실제전환제외): urllib import 누락을 명시적별칭으로 수정하고 실제request·모든핵심검증함수본문/CLI·WAF한정 rollback Dry-run을 필수Gate에 반영했다. Pyflakes직접참조10파일 F821/F823·이름충돌/entrypoint 오류0, 신규31+기존CLI14+receipt3=관련48검사 통과·Gate14항목 본체종료0·Windows/VM manifest14SHA일치·실제무해GET200·active379/GZIP5901 무결성과 기존174문서/서비스 보존을 확인했다. WAF수동549681/자식549682·unitdisabled/inactive 유지하며 실제전환/enable·새로그인3종·무로그인/부팅인수는 미완료다.

2026-10-17 MALL-WAF-06E2A-FULL-PATH 범위·검증·제한:

- request()/check_request()의 urllib 전역누락이 세번째오류원인이다. url_request/url_error/url_parse로 명시해함수명충돌을피하고 HTTP상태를그대로반환하며 redirect비추적·고정경로·연결거부/timeout/연결/프로토콜오류를고정실패코드로구분했다. 예외를성공으로바꾸거나원문URL/본문/키를출력하지않는다. ES TLS/최소권한/기존보존조건은유지한다.
- 신규HTTP9검사는실제urllib와임시loopback서버, 전체CLI22검사는수정하지않은staging소스의__main__/main·preflight/configuration/single/request/check_request/privacy/local_matches/preservation/verify_receipt/migrate/rollback본문을실행했다. 대역은호스트프로세스/명령·ES·readiness및임시proc/cgroup경로에한정했다. CRS/상위준비/PID·사전설정·손상gzip/시작·unit·신원/HTTP·ID·수집timeout·provenance·민감필드/최종설정·checkpoint·restart·ES·enable/도구NameError/rollback실패를주입해종료코드·WAF한정1회복원·enable차단을확인했다. 실제systemd명령은실행하지않았다.
- 초기합성fixture의Python3.12 Path생성/비JSON과거입력·trace오류주입과성공마지막명령단정문제를수정해실패범위만재검증하고최종버전Gate를완주했다. 최종31+14+3=48검사 실패/오류/skip0이며기존32/전체프로젝트테스트는반복하지않았다. 정적분석은Pyflakes3.4.0 wheel약64KB를사용자staging에download만해설치없이실행했다. Windowsvenv pip부재는시스템설치없이우회했고,직접참조10파일F821/F823·import충돌/진입점오류0이다. 기존미사용import2진단은별도유지한다.
- 실제Gate14항목은정적검사·실제본문31검사누락/실패/skip시차단하며기존guard/구문/CRS/실제readiness/unit/legacyCLI/active·gzip/복원준비를유지했다. manifest14파일 SHA31e2ce6fb8d2c63c222258dce42a2e28b9e7fcf9a56fff66ce2ec62b241764c0·Windows실원본/localstage/VM일치,별도receipt테스트도동일하다. runtime client/parser 해시·기존300초TTL/시작토큰을receipt와전환직전에확인한다. Gatebody0/성공receipt를확인했으며이후전송bashstdin CRLF exit문오류는별도운송오류로기록했고Gate를반복하지않았다. 향후직접SSH/LF실행의외부종료코드도확인해야한다.
- VM새staging waf-full-path-20261017/staging만반영했다. 실제request('/')1건HTTP200/request_id확인·로그인/주문/공격요청없음. 수동WAF549681/549682·시작토큰3748420/단일loopback·unitdisabled/inactive/NRestarts0, SyntaxOK/CRS32/900990335/setup선행/DetectionOnly/신규private9010010 유지다. active379/GZIP5901원범위·EOF/CRC,기존7인덱스174문서source/seq/term·다른서비스PID/설정/HMAC/JAR·H2경로/inode·SQLite scope/target/inode·두registry를보존했다. health웹/WAF추가기록은앱3종통합성공으로계산하지않는다.
- 산출물: waf_transition.py·waf_dry_run.py·waf_static_check.py, tests/test_waf_transition_paths.py·기존CLI/receipt관련테스트수정, docs/security_mall_waf_tool_full_path_validation.md·TOOL-GATE/MIGRATION/WAF-PRECHECK/RUNBOOK·이tracker다. 이전code/docs와두Git상태는state/security-mall-waf-full-path-20261017에보존,VM waf-gate-full-path-20261017의receipt/preflight/es-before/readonly-proof가근거다. 기존main121/mall11파일·두브랜치를이번대상외보존했다. WAF/다른서비스stop/start/enable·ES직접쓰기/문서삭제·강제회전·키발급·Docker/reboot·Slack·Gitcommit/원격작업은없다. 실제전환은별도승인·새Gate·사후3종검증이필요하며이번엔중단한다.


- [ ] MALL-WAF-06E2A-FINAL-TRANSITION 실패·수동복원완료(2026-10-17, 실제전환미완료): 명시 승인된1회만 수행했다. 새Gate12항목/CLI14건·Windows/VM9SHA·522227/522228시작토큰 모두 통과하고 정상종료→systemd549637을 확인했다. request()315행 urllib 미import NameError로 로그인 요청 전 실패해 WAF unit만stop/disable·수동549681/자식549682·HTTP200 복원 후 중단했다. unitdisabled/inactive·enable미실행이며 실제3종검증/재전환/Mall전환은 미완료다.

2026-10-17 MALL-WAF-06E2A-FINAL-TRANSITION 근거·제한:

- 실제 waf_transition.py Gate는 종료0, 12항목·합성CLI14건 모두 통과했다. manifest d24dbc827bbb3205a852b7fb69be651f2dc3ae86a0af6e0c15fac274519166bc·도구9SHA일치·현재PID/start/고정명령·실제구문/CRS32/900990335/DetectionOnly·active/GZIP·상위readiness를 확인하고 300초내 receipt로 1회만 전환했다. Gate 성공을 전환 완료로 처리하지 않는다.
- 실제 실패는 migrate294→check_request181→request315의 NameError다. urllib 전역import 누락이며 Gate모의테스트가 request/check_request 본문을 대체하고 readiness는 다른모듈이라 누락을 발견하지 못했다. tool_error 내부반환3(코드상), Windows 실행 외부관측1을 구분한다. 이번엔 코드수정/재시도 없이 중단했고 현재도구의 Gate만으로 후속전환준비완료라고 주장하지 않는다.
- 정상수동복원 후 SyntaxOK/CRS32/중복0/setup선행/900990335/DetectionOnly와 새비공개오류9010010·단일loopback소켓을 확인했다. active379바이트·기존GZIP5901바이트 원범위검사통과, ES기존7인덱스156문서source/seq/term불변·green이다. appraw0/edgeraw6/norm6/records6 증가는 Gate/기동/복원health 부수기록이며 로그인/3종성공으로 계산하지 않는다.
- Mall/Portal/수집4개PID·상태/보호설정/HMAC/JAR·H2동일inode/실행프로세스·SQLite scope/target/inode·registry2개·Apache기존prefix를 보존했다. 기존DB 전체바이트불변으로 확대해석하지 않는다. 서비스추가기동/enable·다른서비스재시작/변경·로그삭제/강제회전·ES기존문서쓰기·새키·Docker/reboot·Slack·Gitcommit/원격작업은 없다.
- 산출물 docs/security_mall_waf_systemd_final_validation.md·기존TOOL-GATE/MIGRATION/WAF-PRECHECK/RUNBOOK의현재상태주의·이tracker다. VM waf-gate-final-transition-20261017의receipt/preflight/es-before/result/final-safety와 로컬 state/security-mall-waf-final-transition-20261017의원Git해시/결과를 보존한다. 기존main120/mall11파일과두브랜치는 이번문서변경외보존한다. 다음엔실제request본문경로검사와도구보완·새Gate·별도승인이필요하다. WAF전환/전체6-E-2A무로그인/부팅인수는 unchecked 유지한다.


- [x] MALL-WAF-06E2A-TOOL-GATE 도구수정·사전실행검증완료(2026-10-17, 실제전환제외): 원stdin CLI와같은argv/본문/진입순서를합성subprocess로재현해migrate281행 single NameError를확인했다. 공식waf_transition.py에모든함수정의뒤단일main·import지연·종료코드분리·MainPID우선기록·필수failclosed Gate를반영하고신규17검사/실제VM Gate12항목을통과했다. WAF522227수동/disabled유지·실제stop/start/enable·다른서비스재시작은없으며실제전환task는unchecked유지한다.

2026-10-17 MALL-WAF-06E2A-TOOL-GATE 재현·수정·검증·제한:

- 원본retry.py와Git상태를state/security-mall-waf-tool-gate-20261017에보존했다. 당시traceback원문은저장되지않았으므로새subprocess에서원본AST의정의/호출순서·실제__main__과migrate argv를유지하고I/O/서비스경계만대역으로교체했다. 예외이벤트NameError/name single/function migrate/원본281행을확인했다. 진입점301행이single314/request306/privacy338앞이었다. compile은이름해석을실행하지않고기존preflight/32보존테스트도이CLI분기를다루지않았다. 재현은실서비스명령을전혀실행하지않았다.
- deploy/security-mall/boot-services/waf_transition.py는기존검증함수/원래안전조건을재사용하고함수정의후main을배치했다. VMimport는CLI시점으로지연하고MainPID를single호출전에기록한다. code0성공/1검증실패/2인자오류/3도구자체오류와파일/함수/행메타데이터를구분하며원문예외/locals/비밀을출력하지않는다. log_preservation.py SHA a3206661a462c35d68d7d0087789bf7d09c0aa466e5ca70f8cb3b99db308f4a7·기존SHA/GZIP전체EOF·CRC/O_NOFOLLOW/btime검사는변경하지않았다.
- 신규총17검사통과·미해결실패/skip0: 함수/정적3,CLI/import subprocess14다. 원본오류재현/수정본migrate전체모의완주·NameError code3/WAF한정모의복원·검증실패code1·인자code2·import무부작용·실제보존CLI(active/gzip/변조/손상)·manifest/file변경/만료/다른PID거부를포함했다. 최초합성테스트문자열구분오류는Gate가서비스검사전에차단했고테스트구분자만수정한뒤14통과·추가3만실행했다. 기존32/전체Python/UI/실제전환·수집시험은반복하지않았다.
- VM waf-tool-gate-20261017의실제gate CLI는12항목모두통과했다. Windows원본/staging/VM9파일SHA일치,manifest d24dbc827bbb3205a852b7fb69be651f2dc3ae86a0af6e0c15fac274519166bc다. 실제4도구import/CLIselfcheck·unit3개systemd-analyze verify exit0·ApacheSyntaxOK/CRS32/900990335/DetectionOnly·현재PID/자식/단일loopback소켓·수집/Portal/Mall/ES CA검증readiness·guard예상거부·실제legacycapture/verify·합성PID/포트0 wait-stopped·active379/GZIP5901 실제보존CLI·복원실행조건을확인했다. 실제Apache종료/새MainPID/3raw+3norm/rollback/enable은사후항목으로명시했다.
- Gate실패시종료전차단하며migrate는별도승인/--execute와같은manifest·현재PID/start_ticks·300초이내receipt를필수로확인한다. 만료/변경은1로실패한다. current receipt는읽기검사시점의증거이며다음승인전환에서새Gate가필요하다. 실제기동/enable·VM재부팅·현재서비스정지·키발급·ES직접쓰기·로그강제회전/삭제·Slack·Gitcommit/원격작업은없다.
- WAF522227/자식522228 및unitdisabled/inactive/MainPID0/NRestarts0,Portal485310/Mall349259/수집421214·421217·421218·421219/보호설정·상태동일이다. 기존7인덱스150문서source/seq/term해시불변,Portal기존3인덱스증가0이다. GatehealthGET1건의웹/WAF raw2·norm2·records2 정상추가는앱3종통합검증과구분한다. 비밀값/로그원문·환경을출력/반출하지않았다.
- MIGRATION의WAF수동shell블록만공식Gate/CLI로대체하고다른서비스이력은유지했다. WAF-PRECHECK/RUNBOOK·과거retryvalidation에후속링크를추가하고TOOL-GATE.md에정확명령/코드버전/사전·사후분리를기록했다. 기존문서전문은state의docs-before-gate에보존했다. 소스waf_transition.py·tests/test_waf_transition_cli.py·tests/test_waf_preflight_gate.py·문서/이tracker가산출물이다. 근거는state의final-proof와VM cli-test-output/gate-unit-summary·waf-gate-preflight-20261017/gate-receipt/preflight다. 기존main116/mall11파일/두브랜치를보존했다. 실제WAF재전환은별도승인후새Gate로만진행하며이번에는중단한다.


- [ ] MALL-WAF-06E2A-WAF-RETRY 실패·수동복원완료(2026-10-17, 재전환미완료): 명시승인에따라수동504576/자식504577·start_ticks3462437/고정명령을확인하고최신보존checker로기준선을확보했다. 정상종료후기존unit start는반환됐지만임시검증도구의정의순서오류로중단했다. WAF unit만stop/disable하고수동522227/자식522228·HTTP200으로복원했다. 실제전환인수·enable·신규실습3종검증은미완료로유지하며추가시도/Mall전환은없다.

2026-10-17 MALL-WAF-06E2A-WAF-RETRY 근거·실패원인·보존:

- preflight에서504576의시작13:34:43KST·UID1000·고정명령/cwd·자식/loopback18082,최신checkerSHA a3206661a462c35d68d7d0087789bf7d09c0aa466e5ca70f8cb3b99db308f4a7의local/VM일치·SyntaxOK/CRS32/중복0/900990·335/DetectionOnly·TLS/ESgreen·다른5unit상태를확인했다. WAF설정만0700/0600백업·ES7인덱스138문서해시·새app379바이트range·이전gzip5901바이트·로그prefix·checkpoint/registry기준선을보존했다. 이전32개성공테스트는반복하지않았다.
- 13:53:07KST graceful-stop→13:53:09부모/자식/포트해제후기존disabled unit을start했다. journal started1/priorityerror0이지만single호출전결과기록이없어중간systemdMainPID는미확보다. AST상진입점301행이request306/single314/privacy338정의보다앞서있어single호출때미정의인임시도구오류를확인했다. 구문compile은통과했으나정의순서인수를대신하지못했다. 고정RETRY_OPERATION_FAILED로기록했으며서비스/회전검사실패로간주하지않는다.
- 실패조건대로WAF만정상stop/disable·잔류cgroup/원부모/자식/포트종료확인후TZUTC기존독립Apache명령으로복원했다. 현재수동522227/자식522228·HTTP200,unitdisabled/inactive/MainPID0/Resultsuccess/NRestarts0다. 이번에는코드수정후추가기동·enable·강제종료·다른서비스전환을하지않았다.
- 새실습로그인요청은실행되지않아원본3/정규화3·앱/웹/WAF연결은이번미검증이다. 기동/복원health만2건으로웹2/WAF2·HTTP200·ID집합일치·DetectionOnly·새901001 Native/비공개오류각0이며총증가appraw0/edgeraw4/norm4/records4다. 이를3종성공으로표현하지않는다.
- 복원후개선checker의현재active379/기존gzip5901범위검사가모두통과했고기존138ES문서source/seq/term SHA동일·Portal기존3인덱스증가0·ESgreen이다. 보호설정/HMAC/JAR/CA/세션키해시,H2·SQLite·두registryinode를유지했다. Mall349259/Portal485310/수집421214·421217·421218·421219 상태/PID유지,기존4수집/Portal enabled/running/NRestarts0다. 새키/ES문서수정·로그삭제/강제회전·서비스모드/탐지/알림·Docker/reboot/Gitcommit·원격변경은없다.
- docs/security_mall_waf_systemd_retry_validation.md와기존validation/MIGRATION/WAF-PRECHECK/RUNBOOK의최신상태링크·이기록을추가했다. 근거는로컬state/security-mall-waf-systemd-retry-20261017의baseline/retry.py/diagnosis/final-safety/startup-metadata/preservation과VM동일경로보호백업/preflight/es-before/result다. 기존main115/mall11파일/두브랜치를보존한다. 실제재전환은실패로중단했으며다음엔부작용없는검증도구정의순서검사·현재PID522227/disabled unit사전점검·별도승인이필요하다. SecurityMall전환·전체6-E-2A무로그인/부팅인수는여전히미완료다.


- [x] MALL-WAF-06E2A-LOG-PRESERVATION 검사개선완료(2026-10-17, WAF재전환제외): 기존 활성inode/크기고정검사가 정상Logback 일별GZIP회전에서 실패한 원인을 확정하고 공통 log_preservation.py·관련32개합성사례·VM기존GZIP5901바이트/현재379바이트읽기검증을완료했다. MIGRATION/WAF-PRECHECK의종료전capture/enable전verify를새검사로연결했다. 실제WAF전환/enable·서비스재시작은없으며상위실제전환task는unchecked유지한다.

2026-10-17 MALL-WAF-06E2A-LOG-PRESERVATION 범위·검증·제한:

- 이전state/migrate.py의preserve_prefix가inode709749/5901바이트를새active655363/379바이트와직접대조해해시검사전실패했고 suffix도과거offset을새active에적용함을분석했다. 기존GZIP security-audit.jsonl.2026-10-16.0.gz가원래범위를보존했다. 압축시작/완료정확시각은미측정이다. 이전도구/실패기록은이력보존하고재사용금지로명시했다.
- 새공통검사는원N바이트SHA256·device/inode/birth(statx)로식별하고append/승인rename/GZIP(전체EOF·CRC확인)/새active를구분한다. 원파일축소·변조,잘못된보관내용·이름,누락,손상GZIP,symlink/권한/식별불가를실패시킨다. directoryfd/O_NOFOLLOW·0600/0700,최대3회0.2초재시도·파일32MiB/128후보/시도총256MiB상한·고정오류만출력을적용했다. btime없는신규환경은failclosed이고과거birth미기록범위는명시null/같은inode세대불명시실패한다. checkpoint/registry/DB접근·변경기능은없다.
- VM비공개합성테스트는최초27중26통과/새active의inode재사용1오류였다. inode번호만으로세대를판정하지않도록btime추가후실패1+신규5+직접관련변조회귀1만7개재실행해모두통과했다. 고유32개최종통과·미해결실패0이며이전성공26/전체Python/UI/실서비스수집을반복하지않았다. 정상/append/rename/gzip/새active/검사중rename/부분압축·변조·유실·CRC·잘못된파일·symlink·copytruncate·상한·비밀미출력·checkpoint/registry무변경을포함한다.
- 실제VM의이전GZIP5901바이트가새verify로통과하고현재active379바이트capture/verify·btime지원도통과했다. 원문·키/환경·Native/error로그는출력/반출하지않았다. VM staging만log-preservation-20261017에0700/0600으로복사했고bootcheck/units/서비스설정은바꾸지않았다. 로컬·VMchecker SHA일치다.
- WAF수동504576/자식504577, unitdisabled/inactive/MainPID0, Mall349259, Portal485310 및수집421214/421217/421218/421219 enabled/active/running/NRestarts0·검사전후동일이다. 기존SQLite/registry inode/권한을유지했다. HTTP신규요청/ES접속·변경/강제회전/삭제/재시작/enable·Gitcommit/원격작업은없다.
- 산출물 deploy/security-mall/boot-services/log_preservation.py·LOG-PRESERVATION.md·MIGRATION.md·WAF-PRECHECK.md·RUNBOOK.md, tests/test_mall_log_preservation.py 및이tracker다. 근거는로컬state/security-mall-log-preservation-20261017의baseline/test-summary/targeted-summary/vm-validation/preservation,VM동일staging이다. 기존main112/mall11파일/두브랜치를보존했다. 보존검사준비만완료이며실제WAF재전환은현재PID/disabled unit기준사전점검과별도승인후수행한다. app이외Apache실제회전지원/새수집·무로그인·부팅인수를추가로주장하지않는다.


- [x] MALL-WAF-06E2A-WAF-SYSTEMD 후속실제인수완료(2026-10-17, APPROVED-TRANSITION 참조). 아래는 최초 실패 당시 이력이며 보존한다: 부분검증·수동복원완료(2026-10-17, 실제전환미완료): 사용자의 명시 승인으로 WAF만1회 전환했다. 수동250530/자식319382 정상종료→systemd504226 기동/프록시200/새로그인3raw+3norm 성공 후 보존 검사에서 정상 앱 로그 일별회전을 실패로 판정했다. WAF unit만정상stop/disable하고 수동504576/자식504577·HTTP200으로복원했다. 재전환/enable은없고실제상주전환인수는미완료로둔다.

2026-10-17 MALL-WAF-06E2A-WAF-SYSTEMD 실행·실패·복원 근거:

- 전환전PID/start_ticks/UID/고정명령/cwd·부모/자식·loopback18082·SyntaxOK·CRS32개/중복0/900990단일335/DetectionOnly와Mall/ES TLSgreen을재확인했다. WAF설정만0700/0600보호백업하고ES7인덱스111문서source/seq/term해시·registry/SQLite scope/inode·로그prefix·기존서비스상태기준선을보존했다. 13:34:00KST graceful-stop→13:34:02 원부모/자식/포트종료→13:34:05 systemd504226/자식1/foreground·unitcgroup·socket1로기동했다. 강제종료·다른서비스재시작은없다.
- 새홈HTTP200 request_id atL6vY9E_EApxpmLFjMwUQAAAAE, 실패로그인HTTP302 request_id atL6vY9E_EApxpmLFjMwUgAAAAI다. 후자는앱1/웹1/WAF1의ID일치·원본3/정규화3·고유event.id·정확provenance·조직/호스트/서비스·개인정보허용목록을확인했다. 신규Native와비공개오류901001각0, DetectionOnly/blocked=false 유지다. startup/홈/rollback health분은별도이며복원후총증가는앱raw1/edge raw8/norm9/records9다. 기존상주수집기로자동처리됐고수동normalize/경보생성은없다.
- 검증도구의활성앱로그 inode/prefix고정요구가 Logback SizeAndTimeBasedRollingPolicy의정상일별회전을 LOG_REPLACED_OR_TRUNCATED로판정했다. 즉시WAF unit stop/disable·cgroup/부모/자식/포트해제·기존수동명령으로복원했으며현재504576/자식504577·HTTP200, unitdisabled/inactive/MainPID0/Resultsuccess/NRestarts0다. 오류원인진단만했고도구수정/재전환/enable/다른서비스전환은하지않았다.
- 후속읽기진단에서 security-audit.jsonl.2026-10-16.0.gz가이전5901바이트와길이/SHA완전동일·UID1000/0600임을확인했다. 삭제·손실로판정하지않는다. Apache3로그는inode/기존prefix/0600동일,설정/HMAC/JAR/Portal보호설정SHA동일이다. 기존111ES문서불변,Portal기존3인덱스증가0,ESgreen이며Mall349259/Portal485310/수집421214/421217/421218/421219의토큰·상태동일이다. H2경로/inode·normalizer/projector inode/scope/target·두registryinode를유지했고실행중H2복사·DB전체물리불변주장은없다.
- 문서 docs/security_mall_waf_systemd_validation.md 및boot-services/WAF-PRECHECK·MIGRATION·RUNBOOK에현재복원상태/오래된최초등록명령재실행금지를기록했다. VM waf-systemd-20261017의보호백업/비밀없는해시근거와로컬state/security-mall-waf-systemd-20261017의baseline/failure-diagnosis/rotation-diagnosis/preservation을보존했다. 기존main111/mall11파일·두브랜치보존,Git커밋/원격·Docker·기존ES문서쓰기·새키·서비스모드변경·알림은없다. 과거전체테스트반복없음·검증helper구문만확인했다. 다음시도전정상회전을인식하는보존검사/현재PID와disabled unit사전점검/별도승인이필요하며Mall전환은보류한다.


- [x] MALL-WAF-06E2A-WAF-PRECHECK 사전점검완료(2026-10-17, 실제전환제외): Portal 전환 이후 WAF만 읽기 전용 최종 확인하고 WAF-PRECHECK.md에 단독 등록·전환·복구 명령을 준비했다. 실제 stop/reload/unit등록/start/enable은 미승인·미실행이며 전체6-E-2A 완료로 간주하지 않는다.

2026-10-17 MALL-WAF-06E2A-WAF-PRECHECK 결과·범위·제한:

- 13:23KST Apache250530/start_ticks1795016/자식319382·UID1000·고정공개명령/cwd 일치와 loopback18082를 확인했다. 실제 -t exit0/Syntax OK, include/module dump exit0·security2/unique_id/proxy 로딩·CRS32파일/중복0·setup선행·900990단일/335·901001유지·DetectionOnly·진단10002없음이다. dump모드는Syntax OK문구를생략하므로일반-t를분리확인했다. 비공개오류/Native/argv/environ원문은출력하지않았다.
- 준비WAFunit은Type simple/foreground·MainPID정본·ExecStop없음/SIGWINCH/mixed/60초/SendSIGKILL no·guard/실제Mallreadiness·on-failure/5초/300초5회로호환한다. local/staging WAFunit과stable/staging helperSHA동일하여코드/설정수정·기존15/8성공시험·unit구문검사반복은없다. WAF PID파일0644/parent0700과설정/로그0600은그대로다. Mall349259직접홈GET200 1회만확인했고WAF신규요청은생성하지않았다.
- Portal485310 및수집421214/421217/421218/421219는enabled/active/running/NRestarts0동일, 수동Mall/WAF토큰·WAF설정6개SHA·PortalunitSHA불변이다. WAF/Appunit은not-found이며stable에WAFunit도미설치다. 기존normalizer/projector SQLite와두registry경로를읽기전용확인했다. 실제ES쓰기/새키/DB·registry조작/서비스종료·기동·reload·원문로그복사는없다.
- Portal전환으로이미존재하는boot-services를보존하도록WAF단독등록·정상종료·원PID/자식/포트해제·기동검증후enable,실패unit cgroup잔류확인후수동복원절차를추가했다. MIGRATION/RUNBOOK 첫머리에일괄등록블록재실행금지와새문서링크를추가했다. 예상중단시간은미측정이며신규901001=0/요청ID/3raw+3norm/기존ES문서SHA불변은승인후실제검증대상이다.
- 기존main110파일/mall11파일의해시기준선과두브랜치를보존한다. 근거는 state/security-mall-waf-systemd-precheck-20261017/{baseline,preflight,syntax-state,final-safety,preservation}.json, 산출물은 deploy/security-mall/boot-services/WAF-PRECHECK.md·MIGRATION.md·RUNBOOK.md 및이기록이다. WAF한정전환승인가능판정이지만이번에는미전환으로중단한다. 재부팅·무로그인·실제전환인수는별도다.

- [x] MALL-WAF-06E2A-PORTAL-SYSTEMD Portal 실제전환완료(2026-10-17, 무로그인/부팅제외): 최신Portal실제전환요청을Portal한정승인으로적용했다. PID214366/start_ticks/고정명령/UID/cwd일치후SIGTERM정상종료·worker214367종료/포트해제확인→SQLite5개/설정8개보호백업→Portal unit만등록/기동→HTTP/기존세션/새로그인/경보·증거·조직/대시보드/불변검증후enable했다. 새master485310/worker1·socket1·enabled/active/running/Result success/NRestarts0이다. Apache/WAF·Mall·ES·수집4개는유지했다.

2026-10-17 MALL-WAF-06E2A-PORTAL-SYSTEMD 결과·근거·범위:

- 13:13:40KST경정상종료후원래부모/자식종료를확인했고13:13:41새unit을기동했다. 기존venv/wsgi/session-secret/CA/읽기키/조직정책/DB경로를그대로사용한다. 백업은VM portal-systemd-20261017/backup의0700/0600/UID1000이며SQLite backup/quick_check정상·H2복사없음이다. unit은 ~/.config/systemd/user/soc-mall-portal.service,ControlGroup user@1000/app.slice다. MainPID정본으로관리하며예전수동PID도구를혼용하지않는다.
- /login200·비인증홈302/login·인증홈200·전환전2계정세션연속성·전환후2계정새로그인·저장Mall위젯/digest·실제ACCESS1/AUTH0·low/20/low·normalized_hash_verified·정확raw/norm참조를확인했다. 타조직목록0/상세·원본GET404/원본POST403과미존재동일응답·조직파라미터400을검증했다. 실습관리자health200/일반health403정책을유지했다. 세션은보호메모리로만쓰고시험후로그아웃했다. 브라우저전체재검증은이번범위아니다.
- 초기preflight검증도구의viewer원본POST404/analysthealth200기대값때문에두번중단했지만Portal종료전이었다. 실제403정책과미존재동일응답을좁혀확인하고도구만수정했다. 서비스권한/소스수정·실제기동실패·반복서비스restart/rollback은없다. 기존15/8/전체테스트도반복하지않았다. 실제전환start는1회다.
- 기존7인덱스111문서수량/source/seq/term SHA동일·Portal설정8개해시동일·packages/cases/dashboards테이블논리해시동일이다. sessions/log-access는검증에따른정상기록변화이므로물리DB불변은주장하지않는다. journal/비공개로그의검사대상비밀값일치0·백업모드정상이다. WAF250530/Mall349259 토큰과collector421214/421217/421218/421219 상태/NRestarts0동일·ESgreen/DetectionOnly유지다. 새WAF/Mallunit은미등록이며관찰/재부팅/신규3종요청시험은실행하지않았다.
- 기존120개미커밋baseline과두브랜치를보존하고Git원격·sudo·ES재시작/문서변경·키발급/폐기·운영알림은없다. 문서는 docs/security_mall_portal_systemd_validation.md 및부팅/기존Portal문서후속기록이고근거는 state/security-mall-portal-systemd-20261017/{preflight,result,final-safety}.json이다. rollback불필요·Portal이전완료후중단하며WAF/Mall실제전환은별도승인이필요하다. 전체6-E-2A무로그인/부팅인수는여전히미완료다.


- [x] MALL-WAF-06E2A-MIGRATION-PRECHECK 전환직전준비완료(2026-10-17, 실제전환제외): 최신사용자지시에따라Portal→WAF→Mall을한서비스씩종료/백업/기동/검증후enable하고실패한서비스만복원하도록MIGRATION.md를작성했다. 실제전환승인이없으므로stop/kill/unit등록/start/enable·H2복사·rollback·새요청직전에중단했다. 이전일괄중지/복원RUNBOOK구간은새문서참조로대체했다.

2026-10-17 MALL-WAF-06E2A-MIGRATION-PRECHECK 근거·제한:

- 현재Portal214366/WAF250530/Mall349259의UID1000·고정명령허용목록/cwd일치·loopback18081/18082/18080,ES19200TLS검색/green·Docker enabled·Linger=yes를읽기전용확인했다. 기존수집4개421214/421217/421218/421219 active/enabled·NRestarts0을유지했다. 새3unit은not-found/inactive이고안정boot-services경로도없다. unit기존ExecStart/WorkingDirectory/종료SIGTERM·WAFSIGWINCH/SendSIGKILL=no/제한된readiness를검토했으며설정변경이필요하지않아기존15/구문성공검사를반복하지않았다.
- 실제원문argv/environ출력조회가자동승인검토에서비밀노출위험으로거부되어실행하지않았다. environ을읽지않고argv를메모리의고정공개명령과대조해boolean/SHA/PID만출력하는대안으로안전하게완료했다. 관리자승인이나인증완화는없다.
- 새읽기전용legacy-check.py는PID/start_ticks/UID/명령/cwd·원래자식PID를capture/verify하고모든기존프로세스와포트가끝날때만wait-stopped를완료한다. 신호/서비스조작/DB복원기능은없다. 신규8사례통과(최초7통과/Windows공용tmp권한setup오류1은새state임시경로에서그1건만재검증통과). VM에서3서비스capture/verify만실제성공했고wait-stopped는실행하지않았다. PSS합계현재Portal61736/WAF30199/Mall364045KiB로제안cap보다낮지만최대부하메모리검증은아니다.
- 기존SQLinit always에대한CLI never유지·Mall가동중H2복사금지·PortalSQLite backup·서비스별stop/rollback·전환중WAF일시502/메모리세션영향·WAF기동health로그추가분을정확히구분했다. 승인후최종실습요청1개의request_id범위에서원본3/정규화3·provenance·기존문서해시를검증하도록준비했으며실제데이터는생성하지않았다.
- 기존117파일과두브랜치baseline은 state/security-mall-migration-precheck-20261017이다. 변경은boot-services/MIGRATION.md·legacy-check.py·새test·RUNBOOK·이tracker/사전점검후속링크뿐이다. VM migration-precheck-20261017/staging만비공개준비했으며원본DB/로그/registry/키·ES컨테이너/문서·기존서비스재시작·Git원격작업은없다. 사용자전환승인대기이며전체6-E-2A무로그인/재부팅인수는여전히미완료다.


- [x] MALL-WAF-06E2A-BOOT-PREP 구성·절차준비완료(2026-10-17, 적용/무로그인/실부팅제외): 사용자실제ESinspect unless-stopped/running·Docker enabled확인과VM Compose읽기결과를반영해로컬Compose restart1줄만동기화했다. 상위3앱미활성userunit/중복기동guard/제한된HTTPS준비검사·전환/복원·실무로그인ES관찰·키·장애별절차를준비했다. 기존110파일baseline은 state/security-mall-bootprep-6e2a-20261017이며두브랜치를유지했다. 기존MALL-WAF-06E2A전체무로그인/부팅인수는unchecked상태를유지한다.

2026-10-17 MALL-WAF-06E2A-BOOT-PREP 변경·검증·남은 인수:

- 실제Mall349259/Apache250530/Portal214366와수집421214/421217/421218/421219를그대로두고실행명령/cwd/허용환경·보호설정/DB경로를읽었다. application-lab.properties의SQLinit always를현재CLI never가덮어쓰는것을확인해새unit/복원CLI에never를유지했다. 기존start.sh는초기화/로그truncate위험때문에그대로쓰지않는다. WAF foreground/SIGWINCH·DetectionOnly/CRS900990·Portal기존venv/wsgi/상태/세션비밀/readonly키/CA를그대로재사용한다.
- 새 deploy/security-mall/boot-services의3unit/bootcheck/RUNBOOK/FAULT-TEST-PLAN 및확장 collection-services/logout-probe.py·새tests/test_mall_boot_preparation.py를작성했다. systemd등록/enable/start·기존프로세스종료/교체·Docker설정명령/compose up/down·재부팅·새키발급/폐기를실행하지않았다. VM bootprep-6e2a-20261017/staging만0700/0600으로준비했고새3unit은미등록이다.
- 신규관련15사례통과: 최초13통과/1실패의WindowsCA경로기대값만수정해1건재실행, Apache0644PID/0700parent추가1건통과다. 기존21/전체회귀는반복하지않았다. VM systemd-analyze user verify3unit exit0/진단0,3guard는기존PID/포트로거부했다. 최초WAF PID파일을비밀0600과같이검사한오류는PID만비밀과구분했고실제권한을바꾸지않고WAF항목만재검증했다. 확장observer --baseline --pipeline의기존22raw/22norm읽기를검증했고새요청/타이머는실행하지않았다.
- 실제서버GET API키메타데이터와encoded/인증ID를대조해4키활성/만료/정확한최소역할일치를확인했다. 관리자는그읽기조회에만썼고발급/폐기는없다. Portal읽기키HTTPS인증200·size0 ES readiness성공·만료2026-10-23 21:35:41KST, 수집app/edge/normalizer만료24일00:51:28/29/30KST를보호metadata에서확인했다. Portal기존3인덱스readonly와collector최소역할·기존키백업/새키검증/개별정상restart후기존키폐기순서를준비했으며권한확대/키교체는없다. 무로그인관찰은모든세션0·7unit연속·새실습요청3raw/3norm·provenance가맞아야성공이며closing/다른사용자세션이남으면성공하지않는다.
- 기존설정/HMAC/DB/로그/registry·소스변경은없고3unit/관찰타이머기동도없다. 전체부팅/무로그인·ES중단·단일kill·실회전/부분입력/copytruncate·용량·키만료/교체는실제인수미완료다. 상세준비명령은 deploy/security-mall/boot-services/RUNBOOK.md/FAULT-TEST-PLAN.md,안전한근거는 state/security-mall-bootprep-6e2a-20261017이다. 사용자승인후전환/로그아웃시험이먼저이며이번에는중단한다.


- [ ] MALL-WAF-06E2A 부분검증(2026-10-17): Linger=yes·4unit enabled/active/running·Restart on-failure/5초/300초5회와 UID1000을 실제 확인했다. 네 수집unit만1회 정상 restart해 checkpoint/scope/registry를 유지하고 기존17인덱스211문서 source/seq/term 불변·같은ID create409·재시작직후 문서증가0을 확인했다. 신규 실패요청1개가 앱1/웹1/WAF1·정규화3/기록3으로38.051초에 자동 반영됐다. 무로그인 전수/실부팅·Docker 런타임정책은 미검증이므로 전체 완료로 표시하지 않는다.

2026-10-17 MALL-WAF-06E2A 검증·계획·남은 인수:

- 실제 PID는projector394900→421214/appFB394901→421217/edgeFB394902→421218/normalizer406030→421219다. 각journal stop/start1회·error0, 자동NRestarts0→0으로수동restart와구분했다. projector offset/scope/counter동일, normalizer checkpoint16:25:34→16:25:44UTC후신규처리16:26:25로진행, registry경로/inode유지다. raw19→22/norm19→22/records19→22, 신규3종event.id고유·동일request_id·org/host/service·실제provenance·발생/수신시각분리·비밀/원문미저장을확인했다. mutable자기status만불변비교제외하며기존211문서최종불변이다.
- Mall349259/Apache250530/Portal214366 PID·앱/Portal200·ESgreen/TLSfull·DetectionOnly·구시스템에이전트disabled/inactive를유지했다. Linger=yes지만active로그인5(검증SSH포함)/closing3scope가남아있다. 상위3앱은closing세션scope의수동프로세스/관련부팅unit미발견이고Docker/containerd만enabled다. ES Compose는restart:no이며kopo소켓권한없어실제컨테이너policy는사용자sudo읽기전용조회가필요하다. 어떤부팅설정도변경하지않았다.
- 키3개0600/7일TTL·만료2026-10-23 15:51UTC경·TLS인증서2027-10-16과가용RAM약4.86GiB/디스크10.78GiB를점검했다. 신규journal검사대상비밀값0·최근FB오류0·pending실측0, 미지원ACK지표null이다. 검증용읽기키1개만발급후폐기했다. outage/디스크고갈/실회전/copytruncate/키만료/비정상crash는실행하지않았고기존backoff/상한/부분Native대기/보존한계만검토했다. 기존21성공테스트는반복하지않았다.
- 수동logout-probe를준비해baseline읽기와구문만검증했으나timer시작·세션종료는하지않았다. active로그인0과closing포함전체세션0을분리하고journal cursor/PID/InvocationID와대조한다. closing scope강제종료는상위앱종료위험이므로금지하며무로그인실검증전사용자수동계획이필요하다. user재부팅자동시작과상위앱시작은별개다.
- 신규 docs/security_mall_resilience_preflight.md·수동관찰도구 deploy/security-mall/collection-services/logout-probe.py·RUNBOOK/상주문서후속링크·이tracker만변경했다. 기존108파일baseline/두브랜치를보존했고안전한근거는 state/security-mall-resilience-6e2a-20261017이다. 서비스설정·앱빌드/재시작·Apache/Portal/ES재시작·운영ES·sudo실행·탐지/Slack/Git원격작업없다. Docker실제policy조회·상위앱부팅보완승인·무로그인관찰·별도승인후6-E-2B장애/재부팅인수가남아있다.

## 2026-10-17 3종 로그 상주 수집

- [x] MALL-WAF-06E1 실제 자동 상주 흐름 인수 완료(2026-10-17, 무로그인/재부팅 제외): 기존 파서·Filebeat9.5.2·processing.worker/continuation/normalize를 재사용했다. 일반 사용자 제한 실행과 사용자 systemd4unit의 두 단계에서 새 실패 요청2개가 수동 명령 없이 각각앱1/웹1/WAF1·정규화3으로 반영됐다. 신규원본6/정규화6, 초기앱backfill13을 구분하며 최종새원본19/정규화19/처리기록19다. 지연은제한실행36.54초·unit실제발생→정규화40.53초다. unit4개active/enabled·NRestarts0이며현재도유지한다. Linger=no는변경하지않았고사용자콘솔 sudo loginctl enable-linger kopo만안내한다.

2026-10-17 MALL-WAF-06E1 검증·변경·남은 인수:

- 공통worker에선택적exact-source/저장target과checkpoint scope고정만추가했고기존기본값/15분overlap/30초안정화/PIT/create409를유지했다. 새mall_runtime/mall_service/web.mall_edge_service는보호설정·부분레코드대기·기존파서·불변JSONL/fsync후offset·지표를연결한다. 작은세그먼트첫64바이트에ID를배치했고rawpartial/Native/error원문은저장하지않는다. 신규관련18+Worker회귀3=21사례통과·최종실패0이다. 초기Windows inode정수범위9실패는문자열metadata로고쳐실패사례만재실행했다. 실제장애주입없이만료/backoff/unknown=null을격리검증했다.
- 네unit은일반사용자kopo이며원본3파일UID1000/0600그대로·새디렉터리0700·파일0600이다. 새원본2·정규화·처리기록·상태5인덱스만생성했고writer는각exact원본create_doc/monitor,normalizer는exact소스read·정규화/기록create_doc와자기상태index만갖는다. TLSfull/CA·7일키/만료진단·keystore/교체명령을준비했고검증읽기키만폐기했다. 대기건수실측0·coverage지연약30초, 미측정Filebeat값은null이다. 원본재create409/최초source·seq·term과기존13인덱스154문서를보존했다.
- 최초최소VM묶음의Worker의존모듈누락을기존index_scope/continuation/package파일만추가해해결했다. 성공한Filebeat설정검사/앱13건전송은반복하지않고동일registry에서정규화를이어갔다. Portal정상302를점검도구가오인한부분만수정해기존자동수집은반복하지않았다. 실행루프예상ES/키오류는5~60초상한backoff이며변경한새normalizer unit만정상재시작해checkpoint/scope/19건불변을확인했다. 실제비정상종료/ES중단은미실행이다.
- 최종새unit PID는projector394900/Filebeat-app394901/Filebeat-edge394902/normalizer406030이다. Mall349259/Apache250530/Portal214366·DetectionOnly·기존에이전트inactive를유지했다. sudo/기존서비스·Docker/ES재시작·Mall빌드/코드·Portal/UI/탐지/Slack·기존문서수정·Git원격작업은없다. 기존94파일baseline/두브랜치를보존했고기록은 docs/security_mall_continuous_collection.md 및 deploy/security-mall/collection-services/RUNBOOK.md, 안전한근거는 state/security-mall-services-6e1-20261017/vm-results-final이다.
- 정상상주·제어된재시작은실제인수했지만무로그인linger/실재부팅·ES중단·키만료·비정상crash·실원본회전/부분Native·보존/용량복구는6-E-2다. spool128MiB/10000파일상한에서안전정지·미완성회전대기·copytruncate/과거inode부재중단·앱7일보존한계를문서화했다. exactly-once/자동spool삭제는보장하지않고이번서비스를유지한채추가단계는시작하지않는다.

## 2026-10-17 앱·웹·WAF 실제 요청 ID 인수

- [x] MALL-WAF-06D3 실제 앱·웹·WAF 요청 ID 인수 완료(2026-10-17): Windows bootJar만 빌드하고 앱15클래스 Java17 major≤61과 최신 로거를 검사했다. 기존 JAR249e8dd9…와 정상 종료 후H2를 전용backup에0600 보존하고 VM Java17.0.20.1에서 쇼핑몰만55637→349259로 정상 교체했다. 기존 설정/HMAC/DB경로/감사prefix는 유지하고 실행 인자 SQL init never로 재MERGE를 방지했다. 실제 실패302·성공302·타인주문403의3요청에서 Apache응답/웹/WAF/앱ID가 일치했으며901001은0이다.

2026-10-17 MALL-WAF-06D3 결과·근거·제한:

- 기존독립Filebeat9.5.2/6-C정제경로/최신앱JS를 재사용해 신규앱3·웹3·WAF3, 합계9건을 새 raw2인덱스에 실제 저장하고 기존normalize()로 새 정규화인덱스9건을 저장·재조회했다. 3ID마다app/access/waf1개씩·event.id고유·org/host/service·http.request.id·원본index/id9건·발생/중앙수신시각·관측loopbackIP를 대조했다. 실제Painless2종/simulate/선택IDkeyword·과거입력·민감정보차단·최소create_doc·TLS를 확인했다. 원본3+변조동일ID1+edge6 재전송40910건 및 정규화4099건으로최초source/seq/term불변이다.
- 직접헤더4검사401 중 누락/잘못된/중복ID는 생략하고 유효위조ID는참고값으로 남아 프록시인증이 아님을 실제 확인했다. 이4앱이벤트는수집제외이며 기존앱6건+신규7건=13건을보존했다. 성공세션은logout폐기했다. HMAC연속성/기존설정SHA·과거로그prefix·기존ES10인덱스136문서SHA불변, Apache250530/Portal214366 PID·HTTP200·ESgreen·DetectionOnly·기존에이전트inactive를확인했다. 임시Filebeat2개exit0·이번키4개폐기했다. DB는정상종료후백업과경로/계정/주문보존을확인했으나가동중파일의물리해시/전체테이블동등성까지주장하지않는다.
- VM최소정규화묶음에탐지모듈이없어성공수집/정규화는반복하지않고검증된정규화9건으로로컬기존탐지함수만호환검증했다. 실제ACCESS1/AUTH0·low/20, 별도메모리합성AUTH1·medium/60, event_id중복차단/가명키매칭을확인했다. 기존38단위/전체테스트·운영Worker/Detector·경보저장/Slack은실행하지않았다. 초기권한음성도구의ID불일치는final fail processor HTTP500/edge_intake_invalid였고역할조회기본필드비교도보완했다. 유효ID의index403과create409로별도확인했으며권한확대·제품코드변경은없다.
- 기존93파일baseline을보존했고 이번변경은tracker·새 docs/security_mall_request_id_integration_validation.md 및기존request_id문서의후속링크뿐이다. 두브랜치/미커밋·다른서비스·기존ES·Git원격은보존했다. 증거는Git제외 state/security-mall-request-id-6d3-20261017/vm-results 및 VM request-id-6d3-20261017/results다. 수동recover_app.py를준비했으나롤백실행은하지않았다. 직접loopback위조한계·신규실회전/장기상주/exactly-once미검증은문서화했고 상주수집/사건연관/추가규칙개발은시작하지않고중단한다. 기존6-D선행중단이력은보존하며후속6-D-1~3의완료를구분한다.

## 2026-10-16 앱 감사 request_id 하위 호환 확장

- [x] MALL-WAF-06D2 로컬 구현·관련 테스트 완료(2026-10-16, 배포/실제 수집 제외): 최신 사용자 요청에 따라 앱 LoginAuditLogger/기존 로그인·공통 권한 호출에 선택 request_id를 추가하고 앱 수집 JS/allowlist·strict ES 예시 매핑/final pipeline·파서/정규화 필드 선택을 확장했다. Apache의 기존27자 UNIQUE_ID를 그대로 http.request.id에 보존하며 event_id/HMAC/기존 provenance·ID 산정은 그대로다. 직접 loopback 접근과 Apache를 인증할 수 없으므로 항상 참고용 상관 ID로 문서화하고 정규화 limitation에 표시한다. 누락/잘못된/중복/비loopback 헤더는 앱 필드 생략, 수집 단계의 잘못된 값은 거부한다.

2026-10-16 MALL-WAF-06D2 검증·보존·남은 인수:

- 새 RequestIdAuditTests16건 및 test_security_mall_request_id.py22건, 합계38건 통과·최종 실패0이다. 메모리 H2, 정상/잘못된/직접 접근·위조 신뢰 한계, 로그인/주문403/관리자 허용·삭제거부DB불변, 실제 JS의 Node 실행, 과거/null 이벤트, 개인정보 미기록, event_id/가명/키 버전/provenance·재처리 ID 유지, 웹/WAF/앱 공통 필드의 조직·호스트 범위와 WEB-ACCESS-01/WEB-AUTH-01 호환을 확인했다. Python의 ES는 모의 경계이며 Painless 네이티브 검증이 아니다. 기존 성공 테스트 전체는 반복하지 않았다.
- 로컬 JDK17 미설치로 최초 Java toolchain 탐색이 중단됐다. 임시 init-script의 적용 순서만 바로잡아 기존 JDK21.0.7 + release17로 컴파일/16건 실행했다. 프로젝트 Gradle/toolchain17은 변경하지 않았다. 실제 Java17 런타임은 미검증이다. 기존 testdb.mv.db/testdb.trace.db 전후 SHA불변이며 두 저장소 브랜치를 유지했다. 기존90파일은 Git 제외 state/security-mall-request-id-6d2-20261016/baseline 및 baseline.json에 보존했고 이번 수정13파일 이외77파일이 동일하다.
- 관련 파일/설계/향후 조치는 docs/security_mall_request_id.md와 mall/docs/security-audit.md에 기록했다. 변경은 앱2소스·새Java테스트/앱문서, Cloud SOC 파서/security_detail/contract·앱수집2파일·ES예시2파일·관련테스트2파일·수집문서/신규설계문서/이 tracker뿐이다. 실제 VM/Apache/앱/Portal/ES/Filebeat 변경, 신규 경보/규칙/Slack, Git 원격 작업은0이다. 실제3종 로그 연결·네이티브 Filebeat/Painless·신규 인덱스 인수는 다음 승인 단계이며 이번에는 시작하지 않는다. 과거6-D/6-C 실제 검증 이력은 유지한다.

## 2026-10-16 CRS 설정 수정 및 사용자 재적용 후 실제 인수

2026-10-16 MALL-WAF-06D1 사용자 재적용 후 실제 인수 완료: 사용자가 PID250530/kopo/실제 설정/Syntax OK 확인 후 graceful을 실행했다고 보고했다. 이후23:40:35 KST(14:40:35 UTC)에 무해한 홈 GET 정확히2건을 생성해 모두200·웹/WAF ID1:1·각901001 0·각비공개오류901001 0·신규오류구간901001 0을 확인했다. 각 Native K에서900990/335 초기화1회와 실제CRS920350 매치1회를 확인해 단순 PID/정적 구문만으로 판단하지 않았다. 요청ID는 atI3YyuokZgOiD33Gh3LxwAAAAI / atI3YyuokZgOiD33Gh3LyAAAAAM이다.

- [x] MALL-WAF-06D1 CRS 수정·사용자 graceful 재적용 후 실제 신규 요청 인수 완료(2026-10-16): 승인된 proposed.patch를 git apply --check 후 로컬/VM 실제 conf/crs-setup.conf에 초기화1줄(900990/phase1/pass/t:none/nolog/noauditlog/335)과 주석2줄만 추가했다. 기존 원본 바이트/줄바꿈을 보존하며 중복900990 사전0→준비 후1이다. VM 원본은 waf-lab/backups/crs-setup.conf.pre-900990-20261016T143207Z-31a3ff3f에0600/UID·GID1000:1000으로 보존했다. 신규 local/VM SHA는466c60402718032f63bdcf227aca2b9601351cb5674501394c641fc4ee916202다. 사용자 재적용 후 실제 신규2건으로901001 소멸·CRS 실행을 확인했다.6-D 앱 요청 ID 전체 작업은 완료로 올리지 않는다.

2026-10-16 MALL-WAF-06D1 최종 보존·제한:

- 검증 전 Native12건 중 기존90100111건을 확인했고 기타기존1건도 보존했다. 이번 신규2건만 ID/시각/파일 추가 offset으로 구분했으며 과거 prefix SHA와 로그 바이트 보존을 확인했다. 최종 Native14건의 전체 과거901001 수는11로 남는다. 비공개 오류는 메모리에서 해당ID/추가구간의 규칙ID 건수만 확인하고 원문/URI/헤더/본문을 출력·결과 복사하지 않았다. 앱 감사SHA도 같다.
- 현재 설정의 CRS32파일·setup 선행1회·900990 단일 정의·진단10002 미등록·DetectionOnly 및 security2/unique_id/proxy 모듈을 확인했다. 쇼핑몰55637/Portal214366/Apache250530 PID·HTTP200/200·ES CA 검증401/기존 최소monitor 키의cluster health green(1node)을 확인했다. 검증기는 추가reload/restart·patch재적용·VM설정/ES/Filebeat변경·Git원격·전체회귀를 실행하지 않았다.
- 이번 로컬 변경은 tracker·RUNBOOK·CRS진단문서뿐이다. 기존80파일은 Git 제외 state/security-mall-waf-6d1-verify-20261016/baseline, 비밀/원문 없는 근거는 같은 경로 result.json/verify_after_graceful.py다.6-D-2 앱 request_id 개발을 재개할 수 있으나 이번에는 시작하지 않고 중단한다.

2026-10-16 MALL-WAF-06D1 이전 준비 검증·사용자 재적용 대기 이력:

- 독립 실행 conf/httpd.conf·부모PID250530을 확인하고 실제 -t Syntax OK/-M security2·unique_id·proxy·proxy_http/CRS32파일·include 중복0·setup 선행·901001 유지·DetectionOnly·기존 proxy를 검증했다. 다른 conf5파일/접근·Native·앱 감사 SHA는 불변이다. git apply의 CRLF 정규화는 원본 prefix 보존 검사로 VM 쓰기 전에 차단했고, 로컬 기존 바이트를 보존한 뒤 다시 준비했다. 최종 reverse check는 적용 상태를 확인할 뿐 추가 적용하지 않았다.
- 쇼핑몰55637/Portal214366/Apache250530 PID 유지, 직접HTTP200/200·ES CA 검증 비인증401이다. reload/restart/WAF 신규요청/ES 문서 변경/기존 Filebeat·앱·정규화·탐지 코드/Slack/Git 원격 변경0이다. 전체·기존 성공 회귀는 실행하지 않았다. 사용자에게 전용 -d/-f/-k graceful 명령을 제공하고 이 지점에서 중단한다. 신규 요청의901001 0건·요청 ID 대조는 사용자 재적용 후 별도 인수이므로 이 항목은 미완료로 둔다.6-D 앱 요청 ID 개발도 미착수다.
- 기존80파일은 Git 제외 state/security-mall-waf-6d1-20261016/baseline에 보존했다. 변경은 setup/RUNBOOK·CRS 진단 문서·이 기록뿐이다. 실제 준비·보존 근거는 같은state의vm-before/vm-prepared/services.json, VM staging/6d1-20261016의 준비기는 재시작 기능이 없다. 사용자 콘솔 절차와 남은 인수는 RUNBOOK8절 및 진단 문서의 후속6-D-1 절에 기록했다.

## 2026-10-16 CRS 선행 진단 및 앱 요청 ID

- [ ] MALL-WAF-06D 선행 조건에서 중단(2026-10-16, CRS 설정 불량 확인): 실제 기존 Native11개/고유 요청11개 모두901001 매치다. 활성 setup은 CRS32파일보다 앞서1회 로드되고 전체38 include 중복0·구문 Syntax OK·DetectionOnly지만 tx.crs_setup_version 초기화가0건이다.6-A의 최소 setup에서 marker를 빠뜨린 것이 직접 원인이다. 패키지 및 공식3.3.5 setup의900990/335와 대조해 초기화1줄 추가안을 신규 crs-setup-version.proposed.patch와 docs/security_mall_crs_diagnosis.md에만 작성했다.901001 삭제/비활성화·기존 설정 적용은 없다.

2026-10-16 MALL-WAF-06D 중단·보존·남은 인수:

- 최신 사용자의 “설정 불량 확인 시 요청 ID 개발 전 보고·중단” 조건을 적용했다. 앱 request_id·Cloud SOC 하위 호환 확장·신뢰 경계 개발·관련 단위/3종 연계 시험은 시작하지 않았다. 제안 patch는 로컬/VM 설정에 미적용이며 반영에는 별도 실습 Apache graceful 재적용/재시작과 새 무해한 요청의901001 소멸 확인이 필요하다. 기존 과거11건을 지우거나 DetectionOnly를 바꾸지 않는다.6-D 전체는 미완료로 유지한다.
- Apache DUMP_INCLUDES는 Syntax OK 문자열을 출력하지 않아 첫 진단 도구 조건이 중단됐다. 실제 -t exit0/Syntax OK를 별도로 확인하고 include 분석만 이어갔다. 기존 설정6개는6-B SHA와 같고 로그 바이트·쇼핑몰55637/Portal214366/Apache250530 PID를 보존했다. 새 HTTP0·VM 파일 쓰기0·sudo/서비스/ES/Filebeat/Slack/Git 원격 변경0이다.
- 기존78파일은 Git 제외 state/security-mall-waf-6d-20261016/baseline에 보존했다. 로컬 변경은 이 기록과 신규 진단 문서/미적용 patch뿐이다. 비밀/원문 없는 진단은 같은 state의diagnosis.json이다. 사용자에게 문제와 최소 변경·미실행 재적용 필요를 보고하고 중단한다.

## 2026-10-16 Security Mall 웹/WAF 수집·정규화

- [x] MALL-WAF-06C 일회성 실제 수집·정규화 인수 완료(2026-10-16, 지속 수집기 배포 제외): kopo의 기존0600 읽기 권한과 신규0700/0600 보호 spool만으로 실제 TSV11/Native AKZ11을 최종 거부0/정제22건으로 변환했다. 독립 Filebeat9.5.2와 TLS/최소 create_doc 키로 새 soc-host-raw-mall-edge-isolated-20261016-faa605ec에22건, 기존 normalize() 분기로 soc-normalized-mall-edge-isolated-20261016-faa605ec에22건을 실제 저장·조회했다.11개 request_id의 웹/WAF2건씩·원본 index/id/event.id·조직/호스트/관측 IP·발생/서버 수신 시각을 대조했다. 앱 request_id 연계는 미구현이다.

2026-10-16 MALL-WAF-06C 근거·검증·제한:

- 변경은 신규 parsers/security_mall_edge.py·web/mall_edge_projection.py·filebeat/security-mall-edge/·waf-lab/edge-*3파일·tests/test_security_mall_edge.py·docs/security_mall_edge_collection.md, 기존 security_detail/contract의 제한 분기 및 WAF README/계획·이 기록이다. Native 완전AKZ/경계/체인·설치 CRS 소스 대조·고정 오류 코드·허용 필드만 출력하며 요청/메시지/logdata/원문 K/헤더/본문/error-private는 전송하지 않는다. 원본 파일 권한 확대·sudo·앱/Apache/Portal/ES/기존 Filebeat 서비스 변경은 없다.
- 신규 관련 단위32사례+기존 웹/앱/Linux 정규화 회귀3사례 통과, 남은 실패0이다. 초기 Windows fixture CRLF1실패는 LF fixture로 해당 사례만 재검증했다. 실제 Native의 마이크로초/action 없는 체인/선택적 인용부호/인자 없는 연산자 공백은 보수적 거부 후 필요한 부분만 지원했다. 최초 접근11건은 반복하지 않았고 실패한 WAF만 재처리했다. 제어/초기화·부분 체인은 매치에서 제외하며 진단10002는 manifest-only 별도 옵션이다. 실제 WAF는 진단 포함2/미포함9이고920350 숫자Host 및901001 설정 경고를 관측했다. 공격 성공/차단/경보로 집계하지 않는다.
- 실제 Painless 등록/simulate2음성·위조 event.ingested 덮어쓰기·strict/date_nanos/IP/nested 매핑·final pipeline 고정을 확인했다. writer는 신규 원본1인덱스 create_doc/연결 monitor만이며 index/write/delete/manage/read/auto_configure·기존 인덱스·cluster 관리가 거부됐다. 명시적 index Bulk403 후 실제 Filebeat22건 성공, 동일22+변조 동일ID1 재전송 duplicates23·최초source/seq/term 보존, 정규화 create 재처리22건409·불변을 확인했다. 키는 VM 보호 파일/keystore의2시간 TTL이며 감사용 이전6인덱스 읽기 키는 검사 후 폐기했다.
- 비정상 JSON/extra message/중복 키3건은 added/done25 대비 output/acked22로 전송 전 취소를 확인했다.9.5.2에 없는 pipeline filtered 메트릭 경로를 실제 제공 수치로 바로잡았다. 최종 타입 guard의 별도 가상 배열ID2건도 입력2/출력0으로 확인했다. 가상 민감 표식·실제 API 비밀값은 ES 원본/정규화·config/results/진단에 없고 실제 Apache error-private는 수집하지 않았다. 원시 로그/비밀은 로컬 결과로 복사하지 않았다.
- 같은 registry 재시작 added0, 별도 synthetic rotation 인덱스4건으로 append/rename/부분 JSON 보류-완성/immutable GZIP을 실제 확인했다. 모든 이번 Filebeat는 정상 종료했다. Apache 원본 실회전/copytruncate/원본 GZIP·registry 손실/갑작스러운 장애·장기 지속 수집/exactly-once는 미검증이다. Native 파일별 부분 조각을 다른 회전 파일과 합치지 않는 것은 격리 시험했다.
- 기존6인덱스84문서의source/version/seq/term은5-B 보호 baseline과 같았다. 쇼핑몰55637/Portal214366/Apache250530 PID·기본 설정·앱 감사6건, 기존 Filebeat/Packetbeat inactive를 유지했다. ES/Docker/서비스 재시작·운영 VM·새 탐지/임계값·Slack·UI·Git 원격 작업은 없다. 새 VM 작업은 waf-collection-6c-20261016, 안전한 결과는 results/{prepare,integration,replay-rotation,final,mapping}.json 및 Git 제외 로컬 state/security-mall-waf-6c-20261016다. CRS901001의 setup marker 부재는 후속 설정 검토로 남기고 이번 Apache 무변경 제한을 지켰다.6-C에서 중단한다.

## 2026-10-16 Security Mall WAF 실제 연동

- [x] MALL-WAF-06B 실제 독립 Apache 연동 완료(2026-10-16, DetectionOnly 범위): 사용자 설치 Apache2.4.58-1ubuntu8.17/ModSecurity2.9.7-1build3/CRS3.3.5-2와6-A 기본 conf6개를 수정 없이 재사용했다. 실제 -t Syntax OK·-M security2/unique_id/proxy·-S 단일loopback·DUMP_INCLUDES CRS32파일을 확인했다. apache2 서비스/기본 설정이 없어도 apache2-bin과 독립 설정으로 실행 가능해 추가 설치/sudo 없이127.0.0.1:18082→18080을 기동했다. 최종 부모PID250530/자식250531, 80/443 미점유·외부 listener 추가0이다.

2026-10-16 MALL-WAF-06B 검증·보존·제한:

- 실제 홈/로그인 폼/장바구니200·로그인302·빈 카트 checkout302/cart·타인 주문 앱403/소유자정보 미노출을 확인했다. 로그아웃으로 시험 세션을 폐기했으며 주문 생성/결제는 호출하지 않았다. 기존 앱 감사4건은 byte prefix/고유 ID를 보존하고 실제 login success1/order_view failure not_owner1을 추가해 총6건이다. 이 신규2건은 ES로 보내지 않았다. 소유자 상세200/주문 입력 화면 렌더링은 이번 미검증이며 빈 카트의 정상 리다이렉트와 권한 거부를 인수했다.
- 진단 중 웹10/WAF10, 기본 설정 최종 요청까지 접근11줄/Native11레코드·AKZ 경계만·8열·고유27자ID·peer127.0.0.1을 확인했다. 무해한 query/body/가짜 password/cookie/auth/매칭값/경로/client ID 표식은 접근 및 Native A/K에 없었지만 private error에 query/path/matched 표식이 있었다. 실제 계정 이름/비밀번호·가상 소유자 정보 미기록, 로그0600/상위0700이다. AKZ의 보편적 무민감성을 보장하지 않으며 오류 로그 및 K 원문은 수집 금지,6-C 허용 필드 투영이 필요하다.
- 응답↔웹↔Native A 생성ID 일치·클라이언트ID 덮어쓰기를 확인했다. 임시loopback18083 관측 backend GET/POST2회로 생성X-Request-ID1개와 Forwarded/XFF/Real-IP/Correlation 제거를 검증했다. 앱에는 request_id가 없어 정확한 앱 감사 연계는 미구현이며 proxy 관측을 앱의 헤더 기록 성공으로 대신하지 않는다. 진단10002(pass)2매치와 자연 발생 CRS920350(숫자Host)11매치를 관측했으며 공격/차단 성공으로 집계하지 않는다. 진단 규칙·관측 서버·경로를 제거하고 기본 설정으로 실행했다.
- 최초 검증기 PID 파일 생성 경합은 HTTP 요청 전 대기 조건만 보완해 기존 진단 인스턴스에서 이어갔다. 성공 요청/기존 테스트·빌드를 반복하지 않았다. 변경은 신규 waf-lab/VALIDATION-6B.md와 README/LOGGING·이 기록뿐이고 이전68파일 중 해당3파일을 제외한65파일 SHA가 같다. 기본 conf는 staging/local과 일치하며 Git 제외 state/security-mall-waf-6b-20261016/vm-summary.json과 VM waf-lab/results/summary.json에 원문 없는 근거를 보관했다.
- 쇼핑몰55637/Portal214366 PID·HTTP200 유지, ES CA 검증 비인증401·Filebeat/Packetbeat inactive를 확인했다. 앱/Portal/ES/Docker/기존 서비스·Filebeat 설정·기존 ES 문서·운영 VM·Slack·Git 원격 작업은 변경하지 않았다. 새 WAF만 구동했고 중지 절차는 검증 문서에 기록했다. 다음6-C 수집/정규화·create-only·회전, 앱 request_id, Blocking/JSON/XML/응답 본문 검사·장기 운영·패키지 보안지원 인수는 이번 완료에 포함하지 않고 중단한다.

## 2026-10-16 Security Mall WAF 준비

- [x] MALL-WAF-06A 설정·절차 준비 완료(2026-10-16, 설치/기동/실제 WAF 인수 제외): 복제 Ubuntu24.04.5의 Apache/Nginx/ModSecurity/CRS 미설치와80/443/18082 미점유·기존 mall/Portal200 및 CA 검증 ES401을 확인했다. deploy/security-mall/waf-lab에 독립 Apache2.4→18080 프록시/127.0.0.1:18082·DetectionOnly·CRS3.3.5 PL1·Native AKZ/TSV·요청 ID/헤더 정책 등6개 설정과5개 절차 문서를 작성했다. 메타 패키지 apache2 대신 apache2-bin 기반 사용자 소유 실행으로 기본 사이트/시스템 서비스와 분리한다.

2026-10-16 MALL-WAF-06A 근거·검증·제한:

- 현재 APT 후보는 Apache2.4.58-1ubuntu8.17/ModSecurity2.9.7-1build3/CRS3.3.5-2다. 설치하지 않고 apt-get -s/--print-uris --assume-no로 최소 조합 신규10패키지/다운로드2267kB/설치증가8864kB·업그레이드/삭제0을 조사했다. ModSecurity2 공식 매뉴얼 및v2.9.7/CRS3.3.5 소스로 Native K와phase5 ctl 감사 parts 제한·Apache 헤더/로그 구문을 대조했다. Ubuntu 보안지원/ESM 패치 상태는 실제6-B 설치 전 재확인 항목이다.
- 안전 불변조건 정적8검사·공백 검사 통과. 새 사용자 소유 /home/kopo/soc-mall-lab/waf-lab-staging에11파일만 복사해SHA256 전부 일치했다. 실제waf-lab 실행 경로는 만들지 않았으며 Apache -t/모듈 로딩/로그 실물/CRS 작동/오탐/차단·파일 회전은 미검증이다. 로그는 path template/쿼리 비기록, Native Serial AKZ와최종phase5 guard, private error 로그 수집 제외다. 후속 투영 없이 Native K 전체를 Cloud SOC로 전송하지 않는다.
- client ID/Forwarded/XFF 주장 대신 Apache 생성 UNIQUE_ID와관측 connection peer를 사용한다. 앱에는 생성X-Request-ID를 전달하되 현재 앱 감사로그에 해당필드가 없으므로 정확한 앱 연계는 별도 기능이 필요하다. 기존 account_id/HMAC/key ID는 수정하거나 읽지 않았다.
- 기존 변경57파일을 Git 제외 baseline과 해시로 보존했다. 수정 추적 대상은 이 기록과 신규 waf-lab11파일뿐이다. 기존 쇼핑몰PID55637/Portal214366·ES/포트는 유지되며 sudo 설치·다운로드·서비스 기동/중지/재시작·실제 공격·Filebeat/앱/Portal·ES/Slack/Git 원격 변경은 없다. 다음6-B는 사용자 콘솔 설치와 실제 구문·모듈·정상요청·무해한표식 개인정보/ID 검증이며 이번 범위에서 중단한다.

## 2026-10-16 Security Mall 대시보드 연동

- [x] MALL-PORTAL-05B 복제 VM 실제 Portal·브라우저 인수 완료(2026-10-16): 사용자 준비 Python3.12.3/pip24.0의 기존 venv에 기존 명세 패키지만 설치하고 최신 로컬62모듈/정적 자산 등155파일 SHA를 대조했다. portal-lab의 독립 사용자/조직/SQLite/로그/랜덤 비밀과3개 정확한 실제 인덱스의7일 read/view_index_metadata 키·TLS로 Gunicorn을127.0.0.1:18081에서 실행했다. 최종PID214366, Windows SSH 터널PID8720이다. 관리자 ES 자격 증명은 Portal에 전달하지 않았다. 실제 Edge/Playwright에서 로그인·홈·ACCESS1/AUTH0·20low/severity 구분·증거·위젯 저장/새 로그인 복원·타 조직404·파라미터/주입 방어10묶음을 확인했다.

2026-10-16 MALL-PORTAL-05B 최종 인수·보존·제한:

- 실제 브라우저는 기존 Edge155.0.4283.45 headless 렌더러다. CUA 초기화 오류는 기존 Playwright 경로로 대체했다. 초기 타 조직 오류 선택자만 수정해 실패 화면을 재검증했다. 초기 통지의 범위 밖 조회503은 notices.py에서 실습 모드에만 not_configured를 반환하도록 수정했다. 신규 관련 Python2 passed, 최종 page/console JavaScript 오류0이다. 이전 전체/성공 시험을 반복하지 않았다.
- 실제 raw4/normalized4/alert1·합성raw37/normalized37/alert1의 본문/ID/버전/seq_no/primary_term 불변을 확인했다. Portal만 이번 신규 실습 프로세스를1회 정상 재시작했으며 ES/Docker/쇼핑몰/Filebeat/Packetbeat·운영 VM/Portal/Slack은 변경하지 않았다. 비밀 파일0600 및 로그 비밀 미포함, loopback 바인딩·읽기 키의 쓰기/삭제/관리·합성/운영 인덱스 거부를 확인했다.
- 추적 변경은 notices.py, 신규 tests/test_security_mall_portal_lab.py, docs/security_mall_portal_lab.md 및 이 기록이다. 배포·기동/종료·보호된 시험 자료는 Git 제외 state/security-mall-portal-5b-20261016와 VM portal-lab에 보관한다. 기존 미커밋 변경은 baseline/resume 사본으로 보존했다. 실제 운영 배포·공개 HTTPS·부팅 자동 실행·장기 운영은 이번 완료 범위가 아니며7일 키 만료 시 별도 갱신이 필요하다. Git commit/push/PR/merge·추가 단계 개발은 하지 않았다.

2026-10-16 이전 시작 시 환경 중단: SSH·Python3.12.3·가용 RAM5.2GiB/디스크11GiB·18081 미점유·쇼핑몰PID55637을 확인했으나 ensurepip 부재로 venv bootstrap이 실패했다. 기존 pip/virtualenv/uv/Flask/Gunicorn도 없어 관리자 작업 필요 시 중단 지시를 적용했다. sudo/apt/대체 bootstrap을 실행하지 않았고 사용자가 이후 콘솔에서 준비했다.

2026-10-16 MALL-PORTAL-05B 중단 시 보존·남은 작업:

- 기존 변경54파일은 state/security-mall-portal-5b-20261016/baseline에 보존했다. 이번 생성 자원은 VM /home/kopo/soc-mall-lab/portal-lab의 미완성 venv 디렉터리뿐이다. 기존 서비스/DB/원본·정규화·경보/쇼핑몰/Filebeat/ES 설정을 바꾸지 않았다. 로컬 추적 변경은 이 기록과 신규 실행 준비 문서뿐이며 Git 원격 작업이 없다.
- VM 콘솔에서 공식 Ubuntu python3.12-venv를 준비한 뒤 같은 경로에 venv 생성과 pip 확인이 필요하다. 이후 최신 로컬 코드/UI 전송·기존 의존 설치·별도 실습 계정/조직/상태·새 읽기 전용 키·CA·127.0.0.1:18081 실행·SSH 터널·실제 브라우저 14항목을 재개한다. 현재 Portal PID/HTTP/API/브라우저/이번 TLS 및 권한 검증은 미실행이며 완료로 표시하지 않는다. 기존 5-A 및 4-C 성공을 5-B 성공으로 대체하지 않는다.

- [x] MALL-PORTAL-05A API·UI 구현/관련 검증 완료(2026-10-16, Portal 배포·서버 기동 제외): 최신 요청을 우선해 기존 Operations 목록·상세/증거 API와 홈·개인 대시보드·사건 조사 화면에 Security Mall 경보를 연결했다. 정확한 실습 인덱스3개 서버 allowlist·조직별 집계/상세/증거·원본 권한·합성 제외·해시 검증을 적용하고 rule severity와 계산 위험도를 구분했다. 신규 선택형 security-mall-count는 표본이 아닌 규칙별 전체 건수를 집계한다. 기존 레이아웃·규칙 임계값·경보 문서는 변경하지 않았다.

2026-10-16 MALL-PORTAL-05A 인수·범위·제한:

- 변경: portal/{app,operations,log_query,dashboard_widgets,mall_scope}.py, prototype/{dashboard,dashboard-widgets,operations,investigation,mall-alerts}.js 및 operations/workbench HTML, 서버 scope 설정 예시, 신규 관련 Python/DOM 테스트3파일, docs/security_mall_portal.md와 이 기록이다. 기존 미커밋 변경은 Git 제외 baseline에 보존했다. 원문 message 대신 규칙 스냅샷 사유를 표시하고 HTTP 상태는 스키마 미기록이므로 추정하지 않는다. 가명/키 버전/원본 ID는 검증한 증거에서 연결한다.
- 관련 Python45 passed/하위3, DOM8 passed·JS 구문 검사 통과. 첫 실행의 Windows pytest 임시 디렉터리 권한 오류8건과 message 노출 회귀1건을 수정하고 실패9건만 재검증했다. 전체 Python/UI·기존49건·쇼핑몰/Filebeat/3-C/탐지 실행은 반복하지 않았다. 검증 의존성은 Git 제외 로컬 venv에만 준비했다.
- 실제 실습 ES에 기존 Operations 조회 계층을 독립 읽기 프로세스로 실행해 ACCESS1/AUTH0·서비스/20low·정규화 해시/원본 참조·타 조직0/상세404·합성 범위 제외를 확인했다. 원본4/정규화4/실제 경보1의 본문/버전/seq_no/primary_term 불변이다. 증적은 state/security-mall-portal-5a-20261016/es-readonly-result.json과 VM portal-5a-readonly/result.json이다. 기존4-C 인증으로 조회만 했으며 신규 키 발급/권한 확대는 없다.
- 실제 Flask API는 모의 ES와 임시 DB로 검증했고 실습 ES는 같은 조회 계층으로 확인했다. Portal 서버/브라우저 종단 간 화면·운영 배포는 미실행이다. 다음 단계는 별도 읽기 전용 키·CA·조직/사용자 정책·독립 상태 디렉터리·기존 Portal 필수 관리 설정을 준비하고 서버 기동/표시를 인수하는 것이다. 기존 서비스·ES 문서·쇼핑몰·수집/규칙·Slack/Git 원격 작업은 변경하지 않았다.

## 2026-10-15 공통 런타임 v2 업그레이드 안정화

- [ ] RUNTIME-V2-HARDEN-20261015 진행 중: 최신 사용자 요청을 최우선으로 별도 codex/runtime-v2-upgrade-hardening 브랜치에서 main9d97ee2와 학교 검증 수정본을 대조·재사용하고 구형/기존관리형/신규Ubuntu 설치의 반복가능한 업그레이드를 구현·격리 검증한다. 등록OFF 무작업대기/ON유지·bootstrap없는 정확복귀·활성Compose와잔존컨테이너구분·부분migration/키/state 재사용·중단journal·포털동시저장 기준·실제파일시스템별최대디스크/WAL/backup/image/build/로그유입/ES실제watermark/메모리예산·안전한자원부족보고와읽기전용plan을 개선한다. 이전실패백업은자동삭제하지않고 외부백업은별도장치 검증·무결성/복원을 보장한다. 전체Python/Ruff/Bandit/UI/설치·Compose/실제Linux기동/UID권한·실패복구와3유형격리를 검증한다. 기존본작업폴더의사용자Word/JSON/작업이력 보존, 양운영서버배포/데이터·키·Webhook변경/기록삭제 금지. 최신 사용자 요청으로 완료 수정본의 commit/일반 push가 승인됐다. PR 생성·운영 배포는 승인 범위 밖이다. 코드·격리·원격CI·실환경인수를 구분하고 새 skip/xfail/보안완화 없이 진행한다.

2026-10-15 시작 상태: 원격main9d97ee2, 원래작업폴더 HEADdb68f6c/codex/dashboard-platform-20261013·미커밋작업기록/개인Word/JSON을 유지했다. 별도작업디렉터리는 D:/cloud-soc/state/worktrees/runtime-v2-upgrade-hardening이다. 학교 후보의 원래 기준main9d97ee2·검증image d0c4c3a4…/240공개파일 source20985361… 및 기존1314Python/69관련검증 결과를 출발점으로 재검토하며 이를 이번수정본검증으로 대신하지 않는다. 앞선학교운영배포/사용자승인청소는 과거작업이며 이번범위는 소스안정화/격리시험이다. ES쓰기차단사고는 백업중간복제량과실제watermark가공식plan에누락된 것이므로 단순고정여유값을늘리는방식으로 우회하지 않는다.

2026-10-15 RUNTIME-V2-HARDEN-20261015 로컬 구현·격리 인수 완료, 원격 CI 승인 대기:

- 학교의 공개 호환성6파일과 로컬 보관본의 hash 일치를 읽기 확인해 OFF 대기/ON sweep, 최소 no-deps 복귀, retry 계약, 선택적 DB 인수, 쓰기 중지 기준을 재사용했다. 새 구현은 장치별 최대량/실제 ES watermark·신규 ES bootstrap 전 재조회, native filesystem/외부 백업 판정, WAL/온라인·중지 후 무결성·복원 manifest와 검증 중복 제거, 발급 경계·ownership 재시도/fsync journal, 고정 이미지 이전 Compose, 남은 자원 재확인, 행/근거 손실 시 재시도 차단을 포함한다. 운영 DB·WAL·키·인증서·ES·Webhook과 원래 사용자 파일을 변경하지 않았다.
- 실제 격리 스택에서 발견한 별도 릴리스 경로 제한, Compose null CMD/ENTRYPOINT 상속, Docker Mounts 반환 순서로 인한 잘못된 stale 판정도 수정했다. 경로·이미지·RW 등 실제 변경 차단과 조직/RBAC/Basic·Session/7룰/900초 정책을 유지했다. 이전 백업·실패 증거·이미지를 자동 삭제하거나 디스크 보호/메모리 한도를 완화하지 않았다.
- 최종 Ubuntu 전체 pytest **1390 passed/기존 조건부12/하위255**, Windows 전체 **1386 passed/기존 조건부16/하위257**. 실제 Caddy 격리 **4/하위18**, UI153·설치57/기존조건부1 양 OS, Ruff/Bandit/pip check/pip audit/Compose3구성 통과. Windows 에이전트는 일괄108통과/1기존120초timeout/기존조건부1 후 동일 실패1을 제한시간·제품 수정 없이 다시 실행해 통과(약115초); 고유109사례이며 원격 CI 시간초과는 재확인한다. 새 skip/xfail·기존 실패 시험 삭제는 없다.
- 실제 Linux root 컨테이너의 UID/GID1000·파일0600/디렉터리0700·UID1001 접근 거부·chown 실패 시 원본 보존19검사 통과. 실제 Docker/Compose2.40.3에서 관리형/구형/신규 세 유형의 12서비스·7워커 생명주기, OFF 재시작0, bootstrap 없는 최소 복귀, 건강한 ES·워커 유지, 동일 구성 무재생성·DB/WAL/키 보존을 순차 검증했다. 생명주기 대역을 실제 ES 탐지로 표시하지 않는다.
- 별도의 새 실제 ES9.5.2/Kibana/포털/6처리+Slack1 스택을 공식 plan/apply로 기동해 HTTP200/healthy·TLS/Basic/API10, 정상 합성 raw1→정규화1/정확 원본 참조, 같은 관리형 구성의 unchanged 재적용·컨테이너 ID 보존, OOM/재시작 증가0·OFF 정리0/Slack 미설정OFF를 통과했다. 공격·Slack 메시지는 발송하지 않았다. 기존 데이터가 쌓인 실제 학교/집의 신규 배포·장기운영·새 실제 경보 인수와 전체 ES snapshot/DR은 수행하지 않았다.
- 최종 이미지 **sha256:baeaaaccf739128cf8cebada9a7444d89a3d1076797e797b822068c45c3e2444**, 공개243파일 hash 및 검증7룰 revision 대조 통과. 소스 manifest **574f336e4fd3f88fb6e26965e07836e33d265d556e1109290079dc197e7e3e22**. 새 commit SHA가 아니며 commit/push/PR 없음. Git 제외 `state/runtime-hardening-validation-20261015/`에 비밀 없는 증명/격리 결과를 보관한다. 코드/파일·정확 재배포 절차·잔여 위험은 `docs/runtime_upgrade_hardening.md`, 공식 절차는 `docs/runtime_deployment.md`다.
- CI YAML에 양 플랫폼 새 회귀와 Linux 실제 생명주기 단계를 추가했으나 push/PR 승인 전이므로 새 GitHub Actions는 미실행이다. 위 항목의 전체 완료 체크는 원격 CI를 포함한 남은 인수 전까지 보류한다. 원래 D:/cloud-soc의 db68f6c 브랜치·사용자 Word/JSON/작업 기록 및 원격 main9d97ee2는 보존됐다.

2026-10-15 후속 승인: 사용자가 완료 후 커밋·push를 요청했다. 검증한 19개 소스/시험/문서 파일만 별도 기능 브랜치에 커밋하고 일반 push하며, 새 원격 CI 결과를 확인한다. 기존 로컬 검증 기록은 유지하고 PR·양 서버 배포는 진행하지 않는다.


## 2026-10-15 검증 소스 GitHub 통합

- [x] GIT-CI-OWNERSHIP-20261015 완료(2026-10-15 권한 시험 구현·격리/양 플랫폼 CI 인수 범위): 일반 사용자 단위 시험과 실제 root 배포 소유권 시험을 분리했고, 기존 실패18건을 모두 대조해 통과했다. `111b57f34ef4ede1cf22561ea79039f38e59643f`의 [Actions38594058246](https://github.com/Gandalem/cloud-soc/actions/runs/38594058246)에서 Ubuntu·Windows 두 job이 success다. 실제 Linux 소유권19검사·실패 시 원본/WAL/키/설정/발송 이력 보존과 보안 검사도 통과했다. 운영 src/Compose/Dockerfile·권한은 불변이며 새 skip/xfail/CI 비활성화가 없다. 코드/시험 인수와 GitHub 병합을 분리 기록한다. 이 결과 기록 커밋을 포함한 최종 HEAD의 양 CI를 다시 확인한 뒤 PR13을 병합하며, 실제 병합 SHA/상태는 PR의 병합 기록과 최종 보고를 따른다. 운영/학교 서버·Slack에는 접근하지 않았다.

2026-10-15 `111b57f` 최종 시험 인수 결과:

- Ubuntu: 전체 Python1,298 passed/기존 조건부 제외18/하위255, 신규 공통 권한 회귀, UI153, 설치 JS57/기존 조건부 제외1, Ruff·Bandit·pip audit·Compose/image build·게이트웨이 실제 격리4/하위18 통과다. 비밀정보/경로 검사는 PR 전체56파일의 diff와 blob을 대조했다. 기존 실패18개 ID와 새 JUnit 사례를 일대일 비교했으며 모두 통과·새 skip/xfail0이다.
- 별도 Linux root 컨테이너의 실제 소유권19검사는 진짜 os.chown으로 UID/GID1000:1000·파일0600/디렉터리0700·앱 UID1000 읽기 허용·UID1001 접근 거부를 확인했다. 일반 UID1001의 실제 chown PermissionError에서 기존 계약 원본/UID를 보존하고 임시 파일을 정리했다. 온라인 WAL 백업·6워커 디렉터리·7읽기/처리 키·암호화 키·설정·outbox 보존/반복 migration을 통과했다. os 모의0·운영 mount0·네트워크 none·rootfs read-only·tmpfs/CPU1/512MiB/PID64 조건이다.
- Windows: Python655/조건부 제외8/하위136, 독립 처리59, 공통 배포/Slack/권한198이 통과했다. PowerShell/오프라인 에이전트109/기존 조건부 제외1, UI153, 설치 JS57/기존 조건부 제외1도 통과했다. 이 수치는 Windows 전체1,298 실행을 의미하지 않으며 CI가 명시한 시험 범위를 따른다.
- 소유권 거부 경로는 원자적 계약 저장, DB/워커 디렉터리 인수, 기존 워커 및 알림 읽기 키, 알림 디렉터리/DB/암호화 키, coordinator 중단 복귀를 함께 검사했다. 실패를 무조건 무시하는 예외 처리나 운영 권한 변경은 추가하지 않았다. 실행 소스240개의 원본 hash는 기존 배포본과 같으며, 운영 DB/키/CA/체크포인트/발송 이력·집/학교 서버·Slack 전송에는 접근하지 않았다. 빈 Ubuntu 실서버·학교 중앙·장기 부하/독립 DR은 기존 미검증 범위 그대로다.

2026-10-15 권한 시험 보완 기록(커밋 전 로컬 기준):

- 후속 `c257b78`의 Ubuntu 전체 Python은1,298 passed/18 skipped/하위255로 기존18건을 포함해 통과했다. 다음 설치 JS 단계에서 기존 시험 대역의 `apt-get()` 함수 이름을 Ubuntu dash가 거부해22건이 실패했다. 운영 sh를 bash로 바꾸거나 시험을 빼지 않고, 시험의 임시 PATH에 실행 파일 대역을 두고 비계획 패키지 실행 거부도 추가 검증한다. 실제 root 소유권 단계는 선행 JS 실패로 아직 실행되지 않았으므로 미검증이다. 새 HEAD의 모든 CI를 다시 통과해야 병합한다.
- PATH 대역 보완 후 로컬 설치 JS57 passed/기존 조건부 제외1·diff 검사를 통과했다. 실제 운영 설치 스크립트/배포 소스는 불변이며 Ubuntu dash 실행은 새 CI에서 다시 확인한다. 테스트를 통과시키려고 실제 패키지 관리자나 Docker 명령을 실행하지 않도록 기본 대역의 거부도 시험한다.

- 실패15건은 기존 상태 인수2·신규/업그레이드 키2·중단 재개1·coordinator5·계약 복구1·신규 설치4다. 나머지3건은 Slack 부분 migration 재개·암호화 키/설정 보존·기존 canonical 읽기 키 재사용이다. 공통 실제 호출 지점은 host의 DB/워커 디렉터리 chown, atomic_json의 임시 계약 파일 chown, migrations의 기존 워커/Slack 읽기 키와 알림 디렉터리/DB/암호화 키 chown이다.
- `tests/deployment_ownership.py`와 opt-in `ownership_calls` fixture는 이9개 시험 함수의 POSIX 분기만 모듈별 OS 대역으로 실행한다. 전역 os.name/os.chown과 운영 코드는 변경하지 않으며 실제 경로 존재·시험 tmp 경계·UID/GID1000:1000·POSIX0700/0600을 검사한다. 각 시험은 필요한 대상/원자적 임시 계약 파일 호출과 키 재사용 시 추가 chown 부재도 단언한다. 독립 시험으로 fixture가 없는 코드가 실제 os를 사용하는지도 확인한다.
- 소유권 거부 시 임시 계약 파일 정리/원본 보존·WAL 원본 보존·후속 워커 중단·실패 ledger·기존 알림 키/설정 보존을 검사했다. coordinator에도 ownership 실패/기존 실행 복귀 사례를 추가했다. 로컬 관련 Python120 passed/기존 Windows symlink 조건부 제외1, Ruff·Bandit 중간 이상0·diff 통과다. 새 skip/xfail/검사 비활성화는 없다. 실행 소스240개 hash `b6bafc954a026b6b175b8ff116e39b4254cf3e5840f8fddbd317c7e0ae787522`는 그대로다.
- 실제 Linux 소유권은 CI 전용 Dockerfile/독립 실행 스크립트로 별도 검증한다. root 컨테이너는 네트워크/호스트 mount 없이 read-only rootfs·임시 tmpfs·512MiB/CPU1/PID64 제한에서 실제 os.chown으로 UID/GID·0600/0700·앱 UID1000 읽기 허용/다른 UID1001 거부·일반 UID의 chown 실패와 원자적 원본/임시 파일 정리·WAL/키/설정/발송 이력 보존을 검사한다. 이 PC에는 실행 가능한 Linux 컨테이너 엔진이 없어 해당 실제 실행은 Ubuntu CI에서 확인하며, 아직 통과로 기록하지 않는다. 기존 실패 실행의 Windows job은 최종 success였고 Ubuntu는 failure로 보존한다. 새 HEAD는 두 job을 모두 다시 확인한다.

- [ ] GIT-INTEGRATE-20261015-CI 중단(실제 원격 CI 실패): 준비 커밋 `288be89237911d1ec092f387964d002a2f135e42`를 일반 push하고 [PR13](https://github.com/Gandalem/cloud-soc/pull/13)을 생성했다. [Actions38589987647](https://github.com/Gandalem/cloud-soc/actions/runs/38589987647)의 Ubuntu 전체 회귀는18 failed/1,269 passed/18 skipped/하위255로 실패했다. 배포/Slack migration 관련 시험에서 일반 runner가 `os.chown(..., 1000, 1000)`을 실행해 PermissionError가 발생했다. root 컨테이너의 기존 Linux202 통과와 일반 CI 계정의 권한 조건이 다름을 확인했으며 이전 결과로 이 실패를 대체하지 않는다. 사용자 지시에 따라 코드 수정·추가 commit/push·병합은 중단했다. Windows job은 이 기록 시점에 실행 중이다. 원격 main은 `7bb5fa0328c9611681d64d88e8faca3d1fc364d5` 그대로이며 병합 SHA는 없다. 제품 권한/시험 gate를 완화하거나 skip하지 않았다. 실패 로그는 Git 제외 보호 경로에 저장하고, 이 중단 기록은 추가 커밋하지 않은 로컬 작업 기록으로 남긴다. 다음 단계는 운영 권한 보존을 유지하는 일반 CI 시험 방식의 보완과 양 플랫폼 최종 HEAD 재검증이다.

- [x] GIT-INTEGRATE-20261015-PREP 완료(로컬 통합 준비 범위): 사용자의 최신 명시 승인으로 기존 Git 금지 범위만 변경했다. 진행 중으로 먼저 등록한 통합 작업의 구현 체크리스트는 이 준비 범위로 구분하고, 원격 push/PR/최종 HEAD CI/병합 결과는 GitHub PR의 실행·병합 기록과 최종 보고에서 별도로 확인한다. 검증된 공통 런타임·6워커·Slack·상세 링크 및 관련 시험/문서51파일을 검토·명시적 stage하고 전체 staged 보안/경로·소스 대조·로컬 품질 검사를 통과했다. 실제 비밀 발견0, 실행 소스240개는 검증본의 CRLF→LF 정규화만 존재하며 Git 정규화 manifest는 `80be5525b5a7d13bb90191b2dd50fdc5b79716a2c2240ed8679310bd69b0488f`다. CI에 Windows/Ubuntu 공통 신규4회귀와 설치 JS를 포함했다. 이 완료가 원격 CI/병합 선행 성공을 뜻하지 않는다. 충돌/검사 실패 시 해당 단계에서 중단하며 운영/학교 서버·Slack 발송은 범위 밖이다.

2026-10-15 GitHub 통합 전 검토:

- 원격 main과 작업 HEAD는 모두 `7bb5fa0328c9611681d64d88e8faca3d1fc364d5`로 재확인했다. 기존 `codex/runtime-parity-20261014` 브랜치와 사용자 변경을 유지했고, Git 제외 보호 경로에 51개 후보 파일/해시·변경 patch를 보존했다. 공개 실행 파일240개와 시험108개가 마지막 배포/시험 archive와 각각 바이트 단위로 일치한다(source `b6bafc954a026b6b175b8ff116e39b4254cf3e5840f8fddbd317c7e0ae787522`). 기존 전체 Python1,287/조건부 제외16/하위257·Linux202·실제 PC/모바일 및 사용자 동일 Slack 링크 인수 근거와 연결했다. Git의 CRLF→LF 정규화는 의미 변경과 구분해 staged blob을 다시 대조한다.
- 이번 추가 검증은 배포/Slack/링크/기존 인증·상태 관련 Python235 passed/1 conditional skipped, UI·설치 JS209 passed/1 conditional skipped, Ruff·Bandit 중간 이상0·JS syntax·diff 검사 통과다. CI 구성 확인용 보조 스크립트의 이름 없는 uses 단계 처리 오류는 수정 후 검사를 다시 통과했으며 제품 코드 변경이나 제품 시험 실패는 없다. CI의 공통 단계에 신규 메시지/탐색 회귀를 추가해 Windows/Ubuntu 모두 4개 신규 회귀 파일 및 설치 JS를 실행하도록 보완했다. 제품 소스는 최종 검증 이후 변경하지 않았다.
- 커밋 후보의 URL/인증 값 검토에서 문서의 URL 형식 예시와 명시적인 합성 Slack URL·안전하지 않은 주소 거부용 가짜 user/password fixture만 확인했다. 실제 Webhook·비밀번호·토큰·개인키/운영 DB/state/백업/로그는 포함하지 않는다. 전체 staged diff 검사를 별도 gate로 실행한다. 이 시점은 아직 원격 push/PR CI/병합 전이며 성공으로 미리 기록하지 않는다. 빈 Ubuntu 실서버 설치·접속 불가 중앙·다른 7룰의 새 실공격·장기 부하/독립 DR은 기존 미검증 범위를 유지한다.

## 2026-10-14 Slack 메시지 디자인 개선

- [x] SLACK-MSG-01 로컬 구현·관련 회귀 완료(2026-10-14): 간결한 연결 테스트, 공통 Block Kit 경보(위험도/제목/룰/관측 건수), AUTH-001 쉬운 제목, 본문 ID/불필요한 문구 제거와 정확한 최종 경보 링크를 구현·검증했다. 내부 ID/감사/발송 이력/체크포인트/암호화 키 처리 및 기존 payload는 유지한다. 아래 시험 기록은 로컬·합성 환경 범위이며 운영 적용/새 디자인의 실제 Slack 수신 완료를 뜻하지 않는다.
- [x] SLACK-MSG-02 완료(2026-10-15 집 서버 디자인/동일 상세 링크 인수 범위): 명시 승인과 전체 회귀·Linux/브라우저·실제 자원/백업 안전 검사 후 공통 런타임으로 적용했다. 운영 ES에 가짜 경보를 넣지 않고 명확히 표시한 예시 경보 1건을 Slack 워커가 attempts=1로 전송했다. 실제 사용자 수신 후 발견된 403은 아래 SLACK-LINK-01에서 수정했고, 사용자가 같은 기존 메시지의 표시·로그인 복귀·AUTH-001/10건 경보 상세를 모두 정상으로 확인했다. 기존 AUTH 재전송 0, DB/커서/키/Webhook/발송 이력/6워커 보존을 검증했다. Git commit/push/main 병합·학교 중앙 변경 없음. 이 완료는 빈 Ubuntu 실서버나 다른 중앙의 인수를 뜻하지 않는다.
- [x] SLACK-LINK-01 완료(2026-10-15 실제 동일 링크 재클릭 인수): 실행 중 포털 app SHA와 339행의 전역 cross-site 차단을 확인하고 실제 HTTPS에서 주소창 요청 302와 Slack 헤더 요청의 동일 Werkzeug 403을 재현했다. 유효한 단일 경보 ID와 navigate/document/User=?1 조건의 상세/로그인 HTML GET/HEAD만 제한적으로 예외 처리하고 기존 인증·권한·Host/Origin·CSRF·Strict 쿠키·Caddy IP 제한을 유지했다. 로그인 복귀는 같은 출처의 고정 내부 workbench 경로만 허용한다. Python 전체 1,287/하위257, Linux202, 관련 JS30, PC/모바일 로그인 복귀 시험과 실제 HTTPS9조합을 통과해 집 서버에 적용했다. API·외부 fetch/iframe/잘못된 Origin은 여전히403이다. 추가 Slack 전송/기존 메시지 수정 없이 사용자가 같은 링크의 정상 표시·로그인 복귀·원래 경보 상세를 확인했다. 운영 데이터/키/발송 이력·6워커 보존, OOM/자동restart0을 확인했다.

2026-10-14~15 집 서버 적용 및 실제 링크 오류 후속 기록(최종 인수 대기):

- 사용자 집 서버 적용 명시 승인 후 공개 소스 차이를 메시지/링크 관련 5파일로 제한했다. 전체 Python 본 실행 1,268 passed/16 skipped/257 subtests 후 Windows 시험 스크립트 실행 정책으로 막힌 2건을 해당 시험 프로세스의 RemoteSigned로만 재검증해 모두 통과했다(시스템 정책 불변). Linux 격리 170, PC/390px 모바일·두 테마의 관리자 Slack 흐름을 통과했다. 초기 브라우저 fixture의 비동기 목록 갱신 대기를 보완했으며 제품 코드는 이 때문에 변경하지 않았다.
- 2026-10-14 23:40:47 KST 집 서버 공통 런타임에 source `7dba20a769b9716a264f2bb04c3efeebb7c0aad2111455c21e01c1ab64c535da`, image `sha256:111ba89a59949615414d275a24d58470bf67d1cdac742a23f5fe035f48ed2bb5`를 적용했다. 기존 정책/검증 7룰·6워커 옵션·runtime contract·키/CA·Webhook 설정을 유지했다. 공통 보존 검사에서 기존 경보/통지 10문서·포털 저장 7행을 확인했다. 별도 검사에서 보호 파일 41해시·운영 DB 16파일 inode·기존 발송 2행 전체 hash·커서 2scope와 체크포인트 비후퇴를 확인했다. 6워커와 Slack 워커 Running, OOM/자동 restart 0, ES/Kibana healthy다(계획된 이미지 교체 재기동과 자동 restart를 구분).
- 적용 전 공통 자원 기준 통과: 디스크 3,343,167,488B ≥ 필요 2,936,872,960B, 메모리 가용+관리 working set 7,562,809,207B ≥ 전체 제한+512MiB 여유 7,516,192,768B. 이번 온라인/정지 백업 32개는 SQLite online backup API로 생성·복원 검증 후 hash/압축 해제/SQLite integrity를 다시 확인해 압축 보존했다(789,389,312B → 3,747,717B). 운영 원본은 유지했다. 압축 후 별도 프로세스에서 디스크 3,327,741,952B·메모리 7,608,938,982B로 공통 기준을 다시 통과했다. 크레딧 부족으로 승인 검토가 한 번 실행되지 않은 자원 조회는 사용자 재개 후 같은 승인 절차로 재실행했다. 초기 범용 SSH 도구/불명확 자격 증명 전달 거부는 고정된 읽기 전용 명령과 직접 사용자 제공 자격 증명의 출처 확인으로 해결했고 비밀번호를 파일/기록에 저장하지 않았다.
- 운영 ES에는 문서를 넣지 않고 기존 읽기 전용 키로 참고 경보의 존재만 확인했다. 명시 승인된 `[테스트 예시] SSH 로그인 실패 집중 탐지`/HIGH/AUTH-001/10건(예시)·실제 탐지 아님 메시지 1건을 고정 내부 test ID로 영속 enqueue했다. Slack 워커의 sent/slack_accepted/attempts=1을 대조했고 기존 AUTH-001 발송 행은 불변/재전송 0이다. 본문/대체 텍스트에 긴 ID 없음, Block Kit 필드와 참고 상세 링크를 저장 payload에서 확인했다. 별도의 일반 연결 테스트 1행이 동시 관측돼 그대로 보존·분리했으며 이를 예시 경보의 중복으로 계산하지 않았다. 실제 사용자 수신은 확인됐으나 상세 링크에서 Forbidden이 보고돼 SLACK-MSG-02를 완료하지 않았다. 기존 Slack 메시지 수정/추가 전송 없이 같은 링크로 후속 인수한다. 근거는 Git 제외 `state/slack-message-20261014/`의 gate/plan/apply/preservation/backup/budget/example 보고서다.
- 403 원인 확인: 현재 실행 포털 app SHA `d51ca6f0d84d479deb64065edf689fe99ccda80513da1b204f75188d7bd27158`는 보존 소스와 일치하며 339행의 무조건 cross-site 거부가 존재한다. 실제 HTTPS 같은 URL에서 주소창 요청에 해당하는 요청은 302 `/login`, Slack 링크와 같은 Sec-Fetch-Site=cross-site/Mode=navigate/Dest=document/User=?1은 동일 Werkzeug 403을 반환한다. Caddy의 단순 Forbidden 응답과 구분했다. [Fetch Metadata 명세](https://www.w3.org/TR/fetch-metadata/)의 탐색/리디렉션 의미를 확인했다.
- 최신 명시 지시에 따른 링크 수정은 `portal/app.py`, `prototype/login.js`와 관련 시험으로 한정한다. 유효한 단일 64hex alert 인자가 있는 workbench/login HTML의 GET/HEAD, navigate/document/User=?1만 예외로 분류하고 기존 인증/Host/Origin/RBAC/CSRF 검사를 유지한다. API/쓰기/iframe/image/외부 fetch는 계속 거부한다. 쿠키 SameSite=Strict, 조직 정책, Caddy IP 제한, 메시지/발송/탐지 코드와 DB/키는 바꾸지 않는다. 로그인 후 목적지는 고정 내부 workbench 경로+검증 ID만 허용하고 외부 URL/중복 인자는 사용하지 않는다. 관련 Python 32와 JS 19, 실제 Chromium PC/390px 외부 출처 링크→로그인→원래 경보 URL 복귀(Strict 쿠키/외부 API403/JS0)를 통과했다. Linux 격리 202 passed. 후보 source `b6bafc954a026b6b175b8ff116e39b4254cf3e5840f8fddbd317c7e0ae787522`/image `sha256:56a86f6dc84ef7b99df128ae30c079551a7cc67ce73a883ab7f0053e594542fe`는 빌드됐으나 현재 전체 Python 회귀가 진행 중이므로 이 링크 보강은 운영 미적용이다. 근거는 Git 제외 `state/slack-link-20261014/`다.

2026-10-15 00:10:35 KST 링크 보강 최종 적용·인수:

- 마지막 제품 코드 변경 후 Python 전체 **1,287 passed / 16 conditional skipped / 257 subtests passed**(단일 본 실행 실패0), Linux 격리202, 관련 인증/로그인/조사/공통 shell JS30, PC/390px 실제 Chromium 외부 링크→로그인→동일 경보 URL 복귀를 통과했다. Ruff/Bandit 중간 이상0·diff 검사도 통과했다. 조건부 제외는 별도 플랫폼/환경 시험이며 빈 Ubuntu 실서버·학교 중앙·장기 안정성 시험으로 확대 해석하지 않는다.
- 공통 preflight에서 디스크 3,283,972,096B ≥ 필요2,936,872,960B, 메모리 가용+managed working set 7,565,209,725B ≥ 제한+512MiB 여유7,516,192,768B, 신규 워커/권한/키/누락 인덱스0을 확인했다. apply가 같은 기준과 fingerprint를 적용 직전 재검사한 후 source `b6bafc954a026b6b175b8ff116e39b4254cf3e5840f8fddbd317c7e0ae787522`/image `sha256:56a86f6dc84ef7b99df128ae30c079551a7cc67ce73a883ab7f0053e594542fe`를 적용했다. 직전 운영본과 달라진 공개 소스는 `prototype/login.js`, `src/cloud_soc/portal/app.py` 두 파일뿐이다. 메시지 생성/발송/탐지/룰/키/정책/Compose/Caddy 코드는 이 보강에서 불변이다.
- 실제 HTTPS 엄격 CA 검증에서 주소창/Slack 최상위 GET/HEAD 모두302로 **같은 alert ID를 보존한 `/login?alert=…`**로 이동하고 로그인 HTML200을 확인했다. 외부 fetch/iframe/API·잘못된 Origin/ID는 각각403이다. 로그인 후 원래 상세 복귀는 격리 Chromium과 사용자의 **기존 Slack 메시지 같은 링크 재클릭**으로 대조했다. 사용자 응답: `표시·로그인 복귀·경보 상세 모두 정상`. 추가 메시지를 보내거나 예전 메시지를 수정하지 않았다.
- 최종 보존 검사에서 보호 파일41·운영 DB16 inode·runtime contract/worker identity·체크포인트 비후퇴·Webhook 설정/암호화 키·기존 발송4행의 전체 hash를 대조했다. 기존 AUTH 발송 attempts=1 그대로, 예시 test attempts=1 그대로, 링크 보강의 추가 송신0이다. 기존 경보/통지10문서와 포털 저장7행도 공통 보호 검사로 보존했다. 기존6워커+Slack 워커 모두 Running/같은 검증 이미지, OOM/자동restart0, ES/Kibana healthy를 관찰 시점에 확인했다. 계획된 이미지 교체 재기동과 자동 재시작을 구분한다.
- 이번 online/stopped 백업32개도 online backup API 생성본의 복원 hash/SQLite integrity를 검증하고 압축 보존했다(789,389,312B → 3,857,232B). 운영 DB/볼륨 원본은 유지했다. 압축 후 프로세스를 교체해 재측정한 디스크3,276,791,808B ≥ 기준2,936,872,960B·메모리7,558,117,323B ≥ 기준7,516,192,768B로 통과했다. 백업과 이전 이미지/소스는 보호 경로에 남겼다. 증거: Git 제외 `state/slack-link-20261014/{full-regression.xml,final-test-gate.json,browser-report.json,running-code.json,home-plan.json,home-apply.json,home-final.json,live-navigation-report.json,human-acceptance.json}`. Git HEAD/main 유지, commit/push/병합·다른 중앙 변경 없음.

2026-10-14 SLACK-MSG-01 작업 기록:

- 변경 파일: `src/cloud_soc/notifications/messages.py`(신규 공통 포맷), `worker.py`(저장된 탐지 제목/룰 이름 전달), `store.py`(새 테스트 payload만 교체), `tests/test_slack_messages.py`(신규 관련 회귀). 탐지기/룰/API/UI/DB 마이그레이션은 변경하지 않았다. 정확한 링크 생성에 필요한 비밀 아닌 `SOC_PUBLIC_URL` 전달만 `deploy/server/runtime.compose.yaml`과 `deployment/host.py`에 추가했다. 신규 설치는 기존 공개 호스트 설정을 사용하고 업그레이드는 기존 포털 origin/사용자 지정 포트를 보존한다. 자원 제한/명령/볼륨/인증 설정 변경 없음.
- 테스트: `✅ Cloud SOC 연결 테스트 성공` + `Slack 알림이 정상적으로 연결되었습니다.` 두 줄이다. 테스트 ID는 API/내부 outbox에 유지하며 Slack payload에는 넣지 않는다. 경보는 제목 header·위험도/룰 ID/관측 건수/최종·초기 구분 fields·상세 링크로 구성한다. AUTH-001 제목은 `SSH 로그인 실패 집중 탐지`, 다른/향후 룰은 저장된 `alert_title`/룰 이름을 사용하고 없으면 중립적인 `보안 이벤트 탐지`로 표시한다. 긴 경보 ID는 링크의 조회 인자로만 사용하며 화면에 보이는 본문/알림 대체 텍스트에서는 숨긴다. 요청한 공격 성공 관련 문장을 제거하고 별도의 성공 추정을 추가하지 않았다.
- 링크/안전성: 최종 경보는 기존 `workbench.html?alert=<동일 ID>`로 연결하며 기존 로그인·권한 검사를 그대로 따른다. 초기 통지는 아직 최종 경보가 없고 현 UI에 개별 통지 딥링크가 없어 `초기 통지 목록 보기`로 기존 홈 목록에 연결한다(개별 초기 통지 딥링크/UI 변경은 이번 범위 밖). 링크 대상은 배포 설정의 포털 origin만 사용하고 이벤트의 URL은 사용하지 않는다. 값은 plain_text와 길이 제한, 알림 대체 텍스트의 Slack 특수문자 escape를 적용하며 원본 로그/근거/키를 payload에 포함하지 않는다. HTTPS origin 검증(로컬 시험의 HTTP loopback만 예외), URL의 사용자 정보/경로/쿼리/fragment/제어문자 차단, ID URL 인코딩을 시험했다. Slack 공식 문서상 URL 버튼에도 interaction 응답이 필요하므로 추가 콜백 없이 동작하는 일반 mrkdwn 링크를 사용했다. 참고: [Block Kit](https://docs.slack.dev/block-kit/), [버튼의 URL/acknowledgement 조건](https://docs.slack.dev/reference/block-kit/block-elements/button-element/), [메시지 링크 문법](https://docs.slack.dev/messaging/formatting-message-text/).
- 마지막 코드 변경 후 관련 Python 190 passed/1 skipped(Windows 심볼릭 링크 생성 권한 미지원), 조사 화면/초기 통지/설치 JS 61 passed, Ruff 통과, Bandit 중간 이상 0, `git diff --check` 통과. SQLi/XSS/Windows/네트워크/미래 룰×위험도, AUTH 제목, 최종/초기 상태와 연결 최종 중복 억제, 정확한 상세 인자, 최대 길이/기존 12,000-byte 예산, 기존 전송기에 대한 합성 HTTP, 신규/업그레이드 주소 전달, 저장 이력/ID/키/설정 보존 및 재시작 후 신규 경보 1회 송신을 검증했다. 실제 Slack 네트워크 요청은 하지 않았다. 최초 회귀에서 새 시험의 합성 Webhook 문자열이 기존 URL 검증 길이를 충족하지 못한 1건은 기존 합성 fixture를 재사용하도록 수정했으며 검증기를 완화하지 않았다.
- 보존/근거: Git 제외 `state/slack-message-20261014/baseline/`에 변경 전 관련 소스를 보존했다. `regression.xml`과 `scope-audit.json`에 로컬 결과/소스 SHA를 기록했다. AST 비교에서 store의 테스트 payload 함수/추가 import 외 저장 스키마·키·설정·ledger·재시도·감사 로직이 동일하고 worker의 실제 deliver/singleton/main이 동일함을 확인했다. 운영 서버/DB/키/체크포인트/기존 Slack 메시지에는 접근·변경·재전송하지 않았다. 전체 Python/Linux/실제 브라우저 및 운영 안전 검사·새 디자인 실제 채널 수신은 이 변경에 대해 아직 미검증이며 운영 인수 전 별도 gate로 남긴다. Git commit/push/main 병합 없음, 다른 중앙 변경 없음.

## 2026-10-14 Slack 연동 개발 요청 필수 요구사항 추가

최신 사용자 요청으로 기존 Slack 연동 개발 범위에 아래 조건을 필수로 추가한다. 설정 화면은 **Cloud SOC 자체 웹 관리자 페이지의 `설정 → 알림 연동 → Slack`**에 구현한다. Elasticsearch/Kibana의 설정 화면이나 서버 파일 수동 편집을 사용자 설정 절차로 사용하지 않는다. 첨부 화면은 예정 UI의 디자인 참고이며 구현/배포 완료 근거가 아니다. 저장소 검색에서는 기존 Slack 작업 ID/구현을 찾지 못해 아래 ID로 개발·인수 조건을 명시한다. 기존 완료 이력과 다른 미완료 항목은 유지한다.

2026-10-14 구현 착수: 사용자가 문서 추가를 넘어 실제 코드·로컬/격리 시험·집 서버 보호 적용을 요청했다. 기존 공통 런타임 소스/변경을 Git 제외 state/slack-20261014에 먼저 보호한다. 독립 알림 워커는 룰 ID를 고정하지 않고 모든 최종 경보와 초기 통지의 상태/revision을 처리하며 기본 HIGH·설정 시점 이후 발송·429/재시도/영구 실패/중복 제어를 구현한다. Webhook은 사용자가 관리자 웹에서 직접 입력하며 채팅/로그에 요청·출력하지 않는다. 실제 Slack 수신 전 SLACK-LIVE-01은 미완료다. 다른 중앙 수정·Git push/main 병합은 하지 않는다.

### 필수 기능·보호 조건

1. Cloud SOC 관리자 메뉴에 `설정 → 알림 연동 → Slack`과 전용 설정 화면을 추가한다. 메뉴 접근과 직접 URL/API 접근 모두 같은 관리자 권한 정책을 적용한다.
2. 최초 설치 후 관리자가 웹에서 Incoming Webhook URL을 입력·저장할 수 있어야 한다. SSH 접속이나 서버 파일 편집을 요구하지 않는다. 미설정 상태를 명확히 표시한다.
3. URL은 백엔드에서 검증한 후 Git에 포함되지 않는 보호된 서버 저장소에 보관한다. 저장소·백업의 접근 권한을 제한하고 URL을 소스/이미지/공개 설정에 넣지 않는다. 저장된 URL은 조회 API/HTML/JS/브라우저 저장소·로그·오류 응답에 다시 노출하지 않으며 화면에는 저장 여부만 표시한다. 저장 성공 후 입력값을 비우고 변경할 때는 새 URL을 입력받는다.
4. Slack 알림 ON/OFF, 위험도 선택, 테스트 메시지 전송, Webhook 변경·삭제를 제공한다. 선택한 위험도와 실제 백엔드 발송 필터가 일치해야 한다. 변경·삭제 후 이전 Webhook을 재사용하거나 브라우저에 반환하지 않는다. 테스트 결과는 비밀을 제외한 성공/실패로 표시한다.
5. 관리자만 설정 상태를 조회·수정하고 테스트 전송할 수 있다. 기존 인증/역할 체계를 재사용하며 비로그인·일반 사용자·직접 API 호출을 차단한다. 상태 변경에는 기존 세션의 CSRF 방어를 적용한다. URL 원문은 관리자 조회에도 반환하지 않는다.
6. 서버는 구현 시 Slack 공식 문서에서 확인한 Incoming Webhook 호스트/경로의 정확한 허용 목록과 HTTPS만 허용한다. 유사 도메인·임의 포트·URL 사용자정보·IP 직접 입력·내부망/loopback/link-local 주소 및 IPv6 우회를 차단한다. DNS 검증과 실제 연결 대상 검사가 분리되지 않게 하고, redirect·프록시 등으로 허용 범위 밖에 요청하지 못하게 한다. 저장·테스트·알림 워커의 모든 발송 경로에 같은 검증을 적용한다.
7. 신규 설치와 기존 서버 업그레이드에 같은 설정 화면/API와 Slack 알림 워커를 자동 구성한다. 기존 공통 Compose·런타임 정책·버전 마이그레이션·자원 사전 점검·자동 인수 목록에 함께 반영한다. 서버별 수동 override/워커 실행이나 Webhook 파일 수동 생성에 의존하지 않는다. 미설정 워커는 외부 요청 없이 대기한다.
8. Slack 미설정·OFF·Webhook 검증 실패·Slack 장애가 로그 수집·정규화·탐지·경보 저장·대시보드의 정상 동작을 막지 않아야 한다. 알림 실패는 별도 상태로 표시한다. 발송 타임아웃·재시도·중복 제어는 기존 경보/체크포인트를 되감거나 수정하지 않는 별도 알림 상태로 관리한다.
9. 기존 비밀번호·사용자/역할·인증서/CA·API 키·운영 DB·체크포인트·초기 통지·경보·사건·저장 대시보드를 초기화하거나 재발급하지 않는다. 온라인 백업과 보호 마이그레이션으로 인수하고 전후 보존을 검증한다. Git push/main 병합 금지와 다른 중앙 서버 수정·초기화 금지 지시는 유지한다.
10. 실제 Cloud SOC 웹 화면에서 **Webhook 등록 → 테스트 전송 → 실제 경보의 Slack 수신**까지 검증한다. UI의 성공 표시나 HTTP 요청 시도만으로 Slack 수신 완료를 주장하지 않는다. 실제 채널의 테스트/경보 메시지와 Cloud SOC 경보 ID를 대조하고 ON/OFF·위험도 필터·변경·삭제·비관리자 차단·URL 비노출·미설정 정상 동작도 인수한다.

### 개발·인수 작업

2026-10-14 추가 요청 반영 진행: 수신 미확인 개별 경보 ID/상태를 관리자 화면에 표시하고, 이미 채널에 수신됐을 가능성과 중복 위험을 명시적으로 확인한 경우에만 관리자 수동 재전송을 허용한다. 기존 화면의 집계만으로는 이 조건을 충족하지 않아 UI/API·지속 감사 기록/호출 제한을 보완한다. 이 코드 변경 전 실행 중이던 전체 Python은 중간 실행으로 보존하고 최종 전체 검사를 다시 수행한다. 전체 통과 전 운영 미적용을 유지한다. 적용 직전 메모리/디스크 재검사와 적용 후 OOMKilled·RestartCount·기존6개 상태/체크포인트·키 보존을 확인하며 테스트 채널 수신과 신규 AUTH 채널 수신을 별도로 인수한다.

2026-10-14 추가 운영 게이트(사용자 최신 지시): 기존 6개 워커와 Slack의 전체 컨테이너 한도·ES/Kibana·다른 서비스 사용량 및 별도 512MiB 여유를 실제 호스트에서 재계산하고 부족하면 적용을 중단한다. 보호 백업은 온라인 SQLite API로 WAL까지 포함한 일관된 사본을 만들고 복원을 검증하며, 압축 사본의 해제 해시·무결성 검증 후 실제 디스크 여유를 다시 확인한다. 운영 원본은 유지한다. 별도 Webhook 암호화 키는 신규 설정에 한 번 생성하고 업그레이드/재시작/URL 변경 시 유지한다. 기존 인증 키·인증서는 변경하지 않는다. 최초 활성화·OFF→ON·URL 변경 시 현재 위치를 기준으로 과거 발송을 건너뛰고 재시작 후 커서/중복 기록을 보존한다. POST 후 응답 유실·중단은 수신 미확인으로 보류하며 자동 재전송하지 않는다. 429/일시 실패의 제한 재시도와 영구 실패를 구분하고 종단 간 exactly-once는 보장하지 않는다. 마지막 코드 기준 전체 Python·Linux 격리·PC/모바일 시험 이후에만 보호 적용하며 실제 AUTH/대시보드, 웹 설정, 테스트의 채널 수신, 신규 실경보의 채널 수신을 각각 검증한다. 실제 수신 인수 전 네 Slack 작업의 최종 완료 체크는 보류한다.

- [x] SLACK-UI-01 완료(2026-10-14 코드·격리/PC/모바일·집 서버): Cloud SOC 자체 관리자 메뉴/설정/API에 등록·ON/OFF·최소 위험도·테스트·변경·삭제 및 수신 미확인 목록/위험 확인 후 수동 재전송을 구현했다. 관리자/RBAC/CSRF·URL 비반환·입력 비움·전체 브라우저 회귀를 통과했다. 실제 웹 등록·ON 저장/조회·테스트 수신은 집 서버에서 확인했고 변경/삭제·비관리자/오류 경로는 격리 시험으로 검증했다.
- [x] SLACK-SEC-01 완료(2026-10-14 코드·보안/격리·집 서버 보호 저장): 별도 Fernet키/보호 SQLite, 정확한 Slack 공식 호스트/경로·공인 DNS 연결 고정·TLS·redirect/프록시 차단, CSRF/RBAC·호출 제한·비밀 비반환을 검증했다. URL 변경/삭제 후 이전 대상 미사용·재시작/업그레이드 키 보존·응답 유실 보류·관리자 수동 재전송/감사를 검증했다. URL을 채팅/Git/공개 문서/로그에 기록하지 않았다. 강제429/응답 유실·수동 재전송은 운영 장애를 유발하지 않고 격리 시험으로 검증했다.
- [x] SLACK-RUNTIME-01 완료(2026-10-14 공통 코드·Linux 격리·집 서버 업그레이드/재시작/재업그레이드): 공통 Compose/런타임v2/003 마이그레이션·독립 워커·정확한 읽기 권한·자원 gate를 구현하고 신규 설치/재실행/실패 복구 격리 시험과 실제 집 서버 보존/재업그레이드를 통과했다. 기존6워커/검증7룰·DB/체크포인트/키/CA를 유지했다. 사용자 승인에 따라 신규 설치의 인수 근거는 Linux 격리이며 빈 Ubuntu 실서버 신규 설치와 다른 중앙의 실제 적용은 미검증이다.
- [x] SLACK-LIVE-01 완료(2026-10-14 집 서버 실제 웹→테스트/신규 AUTH 채널 수신 범위): 사용자가 웹에서 Webhook을 등록하고 `#soc-alerts`의 테스트 및 신규AUTH-001/HIGH/고유10건/동일 경보ID 수신을 각각 확인했다. 실제 송신1회·과거경보/중복발송0·정확근거10·대시보드/최종 재업그레이드 보존을 대조했다. 필터/차단/변경/삭제/미확인 수동 재전송의 안전성은 단위·보안·격리 브라우저 인수와 구분한다. 운영 Webhook 삭제·장애 주입은 수행하지 않았다.192.168.32.60은 접속/수정/초기화하지 않았다.

2026-10-14 요구사항 반영 기록: 사용자 열 가지 조건과 첨부 화면의 참고 범위를 위 명세·네 작업의 완료 기준에 반영했다. 이번 변경은 개발 요청/인수 조건 추가이며 Slack UI·저장·워커 구현, 서버 배포, 테스트/경보 메시지 발송 및 실제 Slack 수신을 수행한 것이 아니다. 문서의 조건 누락과 diff 형식만 확인하며 기능 시험을 통과한 것으로 표시하지 않는다. 기존 프로젝트 변경·운영 데이터·Git main을 보존하고 commit/push/병합은 하지 않는다.

2026-10-14 SLACK-UI/SEC/RUNTIME 구현·격리 검증 진행: 관리자 설정 화면/API·별도 암호화 저장·공식 Slack DNS 고정/TLS 전송·관리자/CSRF/테스트 제한·영속 outbox/커서·독립 알림 워커와 공통 런타임v2/003 마이그레이션을 구현했다. 기존 여섯 워커와 검증된7개 룰의 명령/옵션/revision을 유지한다. 후보 공개 소스 SHA `5eb39ed5332a16f1d6115a97c403d98a6de14193a20e24faa15ea7d1597cd6f6`·이미지 `3b2b5e74…`를 준비했으나 이 기록 시점에는 운영 미적용이다. 관련 파일은 `notifications/{transport,store,worker}.py`, `portal/{app,auth}.py`, `prototype/settings-slack.*`, `deployment/*`, 공통 Compose/정책·관련 회귀 시험이다. 운영/실제 채널 수신 완료와 구분한다.

마지막 구현 기준 Linux 격리91 passed(신규/기존 업그레이드·중단 재실행/실패 복구·WAL 온라인 백업/복원·키 유지·최초/재활성화/URL변경/재시작 중복 제어·응답 유실 보류 포함), UI/설치기208 passed/1 조건부 skipped, Ruff/diff·Bandit 중간이상0을 확인했다. 네트워크 없는64MiB 격리 워커에서 ES 라이브러리를 포함해 합성1000건 처리/최대RSS46,448KiB·재시작 추가발송0·암호화키 동일을 확인했다. 실제 Flask/Chrome PC1440·모바일390×두 테마에서 웹 등록/변경/OFF/삭제·URL 비반환·합성 sender 테스트/실제 탐지 엔진 fixture 경보 발송·JS0/HTTP오류0/넘침0을 확인했다. 이 브라우저 시험의 외부 Slack 호출은0이며 실제 채널 수신 근거가 아니다. 브라우저 시험기의 이전 성공 문구 기대/비동기 저장 대기 문제는 시험 코드에서 수정했고 제품 코드 추가 변경은 없었다. 전체 Python은 마지막 구현 이후 최종 실행 중이며 이전 중간 실행은 완료 수치에 넣지 않는다.

보호 사전 점검: 이전 두 업그레이드의 불변 온라인/중지후 SQLite 백업 사본46개만 압축하고 해제 SHA/SQLite memory restore 무결성을 확인했다(약1.07GB→16.69MB). 운영 원본/운영 WAL/키/인증서/체크포인트는 변경하지 않았다. 압축 후 실제 여유3,502,501,888bytes, 후보/격리 시험 후 최신 계획 여유3,467,272,192bytes 대 필요2,936,668,160bytes였다. 메모리는 전체한도+512MiB=7,516,192,768bytes 대 실제 교체가능7,553,720,773bytes로 통과했으며 적용 직전 다시 검사한다. 기존6개 키/역할 추가권한0·상태identity6개와 신규 알림 전용 읽기키 추가만 계획에 포함됐다. 다른 중앙192.168.32.60은 접속/변경하지 않았고 빈 Ubuntu 실서버 신규 설치는 미검증이다. 실제 웹 등록/테스트 채널 수신/신규 실경보 채널 수신·운영 적용 후 재검증은 남아 있어 모든 Slack 체크를 미완료로 유지한다. 운영 방법/실패·중복 보장 한계는 [공통 배포 문서](runtime_deployment.md#slack-관리자-알림런타임-v2)에 기록했다.

2026-10-14 수신 미확인 수동 재전송 보완: 관리자 전용20건 단위 목록/API와 중복 경고·확인 후 수동 재전송/API를 구현했다. 현재 설정 revision/generation·unknown 상태·알림 ON 여부(테스트 제외)를 확인하고 관리자/CSRF·테스트와 합산30초/15분5회 제한을 적용한다. 이미 대기/전송/영구 실패인 항목과 설정 변경 전 이력은 차단한다. 요청자·시각·ID·이전 시도 횟수의 별도 감사 기록을 영속 보존하고 알림 커서/탐지 체크포인트/원래 경보는 변경하지 않는다. URL/암호문/payload는 목록에 반환하지 않는다.

이 보완 후 최종 후보는 공개 SHA `a83a9adf6411c143b0a13f92b45e103cf558eb0f35d5866815aad79405f8ee9b`/이미지 `6626bc5d…`다. 이전 후보는 운영 적용하지 않았다. 최종 관련 Python51 passed/Windows symlink1 skipped·동일 이미지 Linux93 passed(이 symlink 검사도 통과)·UI/설치기208 passed/조건부1 skipped·Ruff/diff·Bandit 중간이상0·PC1440/모바일390×두 테마/미확인 행 표시·위험 확인 취소 시0회/확인 후 합성 재전송 성공·JS0/HTTP오류0/넘침0을 확인했다. 최종64MiB/네트워크none의1000건 처리·재시작 추가발송0·키 동일·최대RSS46,104KiB도 통과했다. 이 보완 전 전체 Python은58% 이후 중단한 중간 실행이며 완료로 계산하지 않는다. 최종 전체 Python을 새로 실행 중이며 운영 미적용을 유지한다. 새 후보 준비 후 계획의 실제 여유3,446,947,840bytes/필요2,936,668,160bytes, 교체가능 메모리7,559,459,892bytes/필요7,516,192,768bytes가 통과했으나 적용 직전 다시 검사한다. 실제 Slack 수신 두 단계는 여전히 미검증이다.

2026-10-14 22:11 KST 최종 전체 Python 완료: 마지막 코드 변경 후1,193 passed/조건부16 skipped/257 subtests(894.32초), Linux93/UI208/최종 브라우저·보안·소스SHA 대조를 통과해 로컬 인수 gate를 고정했다. 중간 전체 실행의 미완료 수치를 합산하지 않는다. 이 결과 확인 이후에만 적용 직전 자원·구성 동일성 재검사와 온라인 보호 백업/복원 검증을 포함한 운영 적용을 시작한다. 실제 운영 적용·OOM/재시작·여섯 워커/기존 AUTH/대시보드·실제 웹 등록과 테스트/신규 실경보 채널 수신은 별도 후속 결과 전까지 미검증이다.

2026-10-14 22:16 KST 보호 적용: 최종 전체 회귀 이후 자원 gate를 다시 통과하고 공통v2/003 마이그레이션을 적용했다. 기존키 교체0·기존 경보/통지6문서 해시·사건/대시보드7개 저장행을 보존했다. 첫 중첩 CLI 시도는 백업/서비스 중지 전에 ValueError로 중단돼 기존v1/6워커가 계속 실행됐다. 계획/보호파일/계약의 읽기 전용 재대조에서 차이0을 확인하고 같은 공통 apply의 안전 검사를 유지한 단일 실행이 성공했다. 첫 오류의 세부 조건은 미확정이며 기록을 보존한다. 내용이 없던 진단 스크립트의 sudo 요청은 자동 승인 검토에서 거부됐고 실행되지 않았다. 알려진 기록 조회·내용을 검토한 읽기 전용 진단으로 대체했다. 안전 gate를 완화하지 않았다.

적용 후 실제6워커 모두 success·checkpoint 전진/33~57초 지연·새 정규화168건 중 실제 원본20개 재현/정확참조, CA 검증 HTTPS/API10개·초기통지조회/Slack worker heartbeat·기존AUTH3건 각 정확근거10건을 확인했다. 실제Chrome 홈/개인×PC1440/모바일390×두테마8조합 및 조사근거/새Slack설정화면·JS0/HTTP오류0/넘침0·로그아웃401을 확인했다. 여섯워커/Slack/포털 OOMKilled false·자동RestartCount0·적용후OOM event0이며 ES/Kibana healthy다. 이는 신규AUTH의 Slack 수신 인수를 대신하지 않는다.

사용자가 Cloud SOC 웹에 Webhook을 직접 등록하고 테스트 `594b9e4d469d41c59dc592b95952fa84`의 실제 `#soc-alerts` 채널 수신을 확인했다. 서버 접수도 sent/attempt1이었다. 별도 확인에서 저장된 알림은OFF/revision1이어서, URL을 읽거나 바꾸지 않고 승인된 관리자 웹 UI로 ON/HIGH를 저장해 revision2/서버ON을 확인했다. 테스트는OFF에서도 허용되는 설계이므로 테스트 수신만으로 ON을 추정하지 않았다. 당시 발송은 테스트1건/과거경보0이었다. ON 설정 DB와 암호화키의 온라인 백업·압축/해제 SHA/SQLite memory restore·키쌍 검증을 통과했다. 첫 OFF 사본도 보호 상태로 보존한다. 알림 워커 단독 계획 재시작 후 키·설정·마지막 테스트/발송 이력 동일·추가발송0·기존6컨테이너ID/시작시각 불변을 확인했다.

새 실제SSH 시험은22:20:50~22:21:15 KST의 단 한 번10회다. 실제 두 경로20문서/정확원본참조20개·중복제거후고유실패10건을 확인했으며 최종900초 유예를 유지한다. 22:36 이후 최종AUTH/정확근거10건·대시보드·자동전송과 실제채널 수신은 아직 대기 중이다. 이후 사용자 요청에서도 같은 시험을 재사용하고 추가 실패를 중복 발생시키지 않았다. 첫v2 적용의 불변 백업30개만 압축/해제SHA/SQLite복원 검증했다(789,184,512→3,784,294bytes·압축후실제여유3,409,575,936bytes). 운영원본/키/인증서/체크포인트는 유지한다. 재업그레이드 계획·보존과 최종실경보 채널수신은 별도 후속 인수로 남긴다.

2026-10-14 22:36~22:38 KST 신규 실제AUTH→Slack 종단 인수 통과: 원래900초 유예를 유지해 `security-alerts`에 새AUTH-001/HIGH `2a9021c7afe12cfe5fe7ce28a541e2b3e61d3da769d3947dcd5a5b0c469fccb6` 1건을 생성했다. 중복제거 고유10건/정확근거10개·모든 정규화 해시/조직/불변원본참조, 6워커success/31~39초지연·HTTPS API10개를 검증했다. 별도 알림 outbox는 해당ID/final/revision0/HIGH/sent/attempt1/slack_accepted이며 전체발송2건은 앞선테스트1+신규최종1뿐이다. 과거경보발송0·불필요한중복0이다. 사용자가 실제 `#soc-alerts`의22:19 테스트ID와22:36 최종 경보ID/룰/위험도/관측10건의 메시지 원문을 이 채팅에 제공해 두 단계를 각각 확인했다. HTTP200만으로 수신을 추정하지 않았다. 실제URL은 요청/출력/작업문서에 기록하지 않았다. 이 종단 인수 통과와 아래 재업그레이드 수정의 최종인수는 구분한다.

재업그레이드 검사에서 새 알림키의 ES canonical 반환형식 호환성 결함을 발견해 보완 중이다. ES는 빈applications/run_as/metadata·transient_metadata.enabled와allow_restricted_indices:false를 붙여 반환하므로 raw JSON 동일성 비교가 사전검사에서 거부됐다. `deployment/migrations.py`의 공통 검증 함수와`preflight.py`를 수정해 이 표준 기본값만 수용하고 정확한2인덱스/read·view_index_metadata/추가역할0·cluster/run_as/application/remote/write/와일드카드/DLS/FLS/제한인덱스/알수없는필드를 계속 거부한다. 기존 키를 업데이트/재발급해 우회하지 않는다. 수정 후보 SHA `649b3801caae7f8553e7d937528bb3549bec6d617e50054f2f33fdb9a478e7ff`/이미지 `14c92057…`는 현재운영a83과 배포검증2파일만 다르며 탐지/정규화/알림전송/UI는 유지한다. 관련109 passed/Windows조건부1 skipped·동일이미지Linux110 passed·UI208/조건부1 skipped·모바일포함브라우저·Ruff/diff/Bandit중간이상0을 확인하고 마지막전체Python을 다시 실행중이다. 브라우저시험기의종료후응답본문조회경합은대기/종료순서만고쳐재시험을통과했다. 제품코드를그시험문제로변경하지않았다.

수정 후보의 실제읽기전용재계획은기존알림읽기키검증/6identity검증/새워커0/권한추가0·교체0으로통과했다. 메모리7,591,770,780bytes 대필요7,516,192,768bytes·디스크3,397,615,616bytes 대필요2,936,872,960bytes였다. 첫중첩실행방식의메모리영향도읽기전용재현했다: 부모RSS19.3→61.4MB가유지되는동안자식사전검사의교체가능메모리7,461,471,022bytes가7,516,192,768bytes에못미쳐동일자원guard가거부했고단일검사는통과했다. 원래첫실패의상세메시지는마스킹됐으므로이재현과구분하며최종적용은불필요한중첩프로세스없이공통진입점의동일guard를사용한다. 마지막전체회귀완료전수정후보운영적용은하지않는다.

### 2026-10-14 Slack 최종 인수 결과

22:50:45 KST에 마지막 전체 회귀가 끝난 수정 후보 `649b3801caae7f8553e7d937528bb3549bec6d617e50054f2f33fdb9a478e7ff`/이미지 `sha256:14c9205773581ee4ae7f413f106a6615acf2e562ea924a68a2da1c79081a76d9`를 공통 CLI로 재업그레이드했다. 실행 직전 자원/구성/기존 상태 guard를 통과했고 새워커0·키교체0·경보/통지10문서/저장행7개를 보존했다. 이전 실제 인수 소스a83과 다른 운영파일은 배포 검증2개뿐이며 탐지·정규화·알림전송·UI는 동일함을 manifest로 확인했다. 원래6개 명령/시작점·키/인증서 등 보호파일45개·Webhook 암호화키·설정revision2/generation·알림커서2개·sent기록2개(각attempt1)가 동일하며 추가/과거/중복발송0을 확인했다. 처음부터 선택된 검증7룰만 유지하고 탐지/파서/정규화/룰 파일31개와 사용자 `docs/latest_release_20261014.md`는 시작 전 해시와 같다.

| 인수 범위 | 최종 결과 | 실제/격리 구분 |
| --- | --- | --- |
| 웹 설정·보호 저장 | Cloud SOC 자체 관리자 UI/API·URL 재반환 없음·ON/HIGH/revision2·키쌍 온라인 백업/복원 | 실제 등록은 사용자 직접 입력, 변경/삭제·권한/CSRF·수동 재전송 실패 경로는 격리 |
| 테스트 메시지 | `594b9e4d469d41c59dc592b95952fa84`·sent/attempt1·22:19 `#soc-alerts` 수신 | 사용자 실제 확인 |
| 신규 실제 AUTH | SSH 실패10회→두 수집 경로 정규화20문서→고유10관측→900초 유예→최종AUTH-001/HIGH1·정확근거10 | 실제 수집/탐지, 미러 문서를 삭제하지 않고 관측 단계에서 중복 제거 |
| 최종 Slack 수신 | `2a9021c7afe12cfe5fe7ce28a541e2b3e61d3da769d3947dcd5a5b0c469fccb6`·final/revision0/HIGH/sent/attempt1·22:36 실제 채널 수신 | 사용자 메시지로 ID/룰/위험도/관측10건 대조·과거경보0·중복0 |
| 900초 유지 대조 | 마지막 정규화 관측 이후 실제 전송까지936.108초 | 원래900초 옵션/엔진 유지, 유예를 단축하지 않음 |
| 전체 Python | **1,210 passed / 조건부16 skipped / 257 subtests**, 989.31초 | 마지막 배포 검증 코드 변경 이후 재실행 |
| Linux 격리 | **110 passed**, 네트워크none/512MiB/CPU1·운영 DB/볼륨/키/인증서/네트워크 미연결 | 신규/기존/중단 재실행/실패 복구·WAL/키/권한·중복/재전송 포함 |
| UI/설치기·보안 | **208 passed / 조건부1 skipped**, Ruff/diff/Bandit 중간이상0·64MiB/1000건·RSS46,080KiB·재시작 중복0 | 마지막 코드 기준 격리·PC/모바일/두 테마·알림 OFF/미설정 독립성 |
| 최종 실제 API/대시보드 | HTTPS/TLS/API10·새정규화240건중 원본20개 재현·AUTH근거10·6워커success/36~47초지연 | 22:53 최종 재적용 이후. 원본 참조/정규화 해시를 확인했으며 원문 자체 해시 검증을 대신 주장하지 않음 |
| 최종 실제 브라우저 | 홈/개인×1440/390×두테마8조합·신규AUTH 표시/근거10·Slack ON/미확인목록·JS0/HTTP0/넘침0/로그아웃401 | 실제 서버, Webhook 필드 조회/변경/촬영 없음 |
| 운영 상태 | 기존6워커+Slack 정상·ES/Kibana healthy·전체 적용 구간 OOM event0/OOMKilled false/자동RestartCount0 | 의도한 적용/재시작과 자동 장애 재시작을 구분 |
| 최종 보호 백업/자원 | 마지막 불변SQLite32개789,389,312→3,959,617bytes·해제SHA/SQLite복원통과·최종여유3,382,972,416bytes 대필요2,936,872,960bytes | 운영 원본과 검증된 압축 보호본/키/설정 모두 유지 |
| 최종 메모리 | 전체한도6.5GiB+512MiB=7,516,192,768bytes 대교체가능7,600,189,402bytes | 실제MemAvailable3,286,261,760+관리working4,313,927,642bytes; 다른컨테이너20,520,632bytes는 회수량에서 제외 |

빈 Ubuntu 실서버의 신규 OS 설치, 접속 불가 다른 중앙192.168.32.60의 실제 적용, 호스트 전원 손실/독립 DR·장기 부하, 운영 Slack 장애 주입/실제 중복 수동 재전송은 **미검증**이다. 해당 서버를 수정하거나 운영 데이터를 초기화해 시험하지 않았다. 이 한계는 Linux 격리 인수 및 지정 집 서버의 실제 종단 인수와 구분한다. Incoming Webhook의 응답 유실은수신 미확인으로 보류하고 관리자 확인 후 수동 재전송할 수 있으나 중복 가능성이 있어 exactly-once를 보장하지 않는다. 기존 P2-02 독립DR 보류와 다른 상위 작업의 잔여 인수는 바꾸지 않는다.

운영 방법은 [공통 런타임/Slack](runtime_deployment.md#slack-관리자-알림런타임-v2), 비밀을 제외한 코드/시험 근거는 `notifications/*`, `deployment/{migrations,preflight,host,contract,verify}.py`, `prototype/settings-slack.*`, `tests/test_{slack_notifications,deployment_parity}.py`다. Git제외 `state/slack-20261014`에 최종 전체/격리/브라우저·실제 수신 확인을 구분한 근거를 보존하고 서버 `runtime/upgrades/20261014T135011023160Z`에 최신 보호 설정/검증 압축 DB/적용 영수증, `runtime/acceptance.json`에 최종 자동 인수를 보존했다. 자동 HTTP 인수의 채널미검증 문구는 정확히 유지하고 별도 사용자 확인 기록으로 실제수신을 증명한다. 브랜치 `codex/runtime-parity-20261014`/HEAD `7bb5fa0`·로컬main `ab62019`를 유지했다. **commit/push/main 병합을 하지 않았다.**

## 2026-10-14 서버 기능 일치·공통 업그레이드 체계 요청

사용자 최신 요청으로 개별 서버의 임시 overlay보다 공통 실행 구성·버전별 마이그레이션·자동 인수 검증을 최우선으로 진행한다. 집192.168.235.128과 기존중앙192.168.32.60의 차이를 재현한다. Git commit/push는 하지 않으며 기존 문서 변경과 완료 이력을 보존한다. 기존 DB/체크포인트/원본·인증서/키/계정·선택 검증 룰을 보존하고 미검증 클라우드 룰은 활성화하지 않는다.

- [x] PARITY-01 완료(2026-10-14 공통 코드·격리/집 서버 범위): 최신 main의 필수 워커/권한/지원 설정을 버전 있는 공통 Compose·런타임 계약으로 정의하고 신규 설치와 업그레이드의 같은 진입점에서 검사한다. 사양/실행 구성 차이·누락·예상 밖 확장은 적용 전에 드러낸다.
- [x] PARITY-02 완료(2026-10-14 격리 장애·실제 보존/재업그레이드 범위): 백업/복원 검사·변경 전 조건·버전 ledger·재시도/중단·명시적 검증 룰 gate가 있는 마이그레이션을 구현한다. 기존 상태 identity/키/CA·사용자 설정을 덮어쓰거나 재발급하지 않는다.
- [x] PARITY-03 완료(2026-10-14 Windows/Linux40개·실제 AUTH 인수 도구): 두 서버 차이·새 설치/기존 설치·실패 재개를 재현하고 실제 API·새 원본의 정규화/정확 참조·탐지/대시보드의 자동 인수 도구를 구현한다. 격리 검증과 실제 서버 인수를 구분해 기록한다.
- [x] PARITY-LIVE-01 완료(2026-10-14 집 서버 실제 인수·다른 중앙 접속 확인 범위): 공통 경로로 집 서버의 보호 업그레이드와 실제 인수를 수행하고, 다른 중앙은 접근 가능 여부를 먼저 확인한다. 접근 불가를 두 서버의 실제 동등 인수로 표시하지 않는다. 실행 전 사양/권한·변경안과 실행 후 근거를 보존한다.
- [ ] PARITY-FRESH-OS-01 미검증/보류: 빈 Ubuntu 실서버 신규 설치. 사용자는 별도 VM을 만들지 않고 통과한 Linux 격리 신규 설치/복구 시험을 이번 인수 근거로 사용하도록 명시했다. 운영 서버/볼륨/키를 재설치 시험에 전용하지 않는다.
- [ ] PARITY-CENTRAL-LIVE-01 미검증/보류:192.168.32.60 실제 업그레이드/동등 인수. 최종 SSH도 timeout이며 사용자 지시로 수정·초기화하지 않는다. 기존5워커 구성 재현 시험과 실제 적용은 구분한다.

2026-10-14 20:47 KST 최종 인수: 공통6워커/검증7룰·버전1 마이그레이션·RO 독립 사본 preflight·실제 가용/working set 예산·중복 차단·중단 journal/영수증 실패 복구를 구현했다. 전체 Python1,138 passed/15skip/257subtests 후 국소 최종 보강 Windows40/Linux40·UI/설치192·Ruff/Bandit 중간높음0/diff 통과. 집 서버 첫 보호 적용4a539a8… 후 실제6워커 재시작에서 identity/체크포인트 전진/대기 참조20개/키·CA·저장행을 보존하고, 최종716331c…/이미지e94f689… 재업그레이드에서 새worker0/누락index0/키 교체0·기존4문서/7행 보존을 확인했다. 실제 SSH10실패→미러20문서/고유10정규화→900초 유지 최종AUTH1/근거10 정확 참조·정규화 해시→HTTPS9API/홈·개인8화면/실제경보 링크·근거상세/JS·HTTP0/로그아웃401을 통과했다. 기본 과거 탐지 약7,104초 적체는 실시간priority39/34초와 분리해 경고를 유지한다. Kibana1.5GiB/heap1GiB·ES3GiB/heap1.5GiB 예산, 실제working set 약1.01/2.57GiB·healthy/새OOM·fatal·자동restart0을 확인했으며 장기 안정성은 별도다. 신규실서버/다른중앙/7룰전체새공격/독립DR는 미검증이다. commit/push/main병합 없음. [결과·파일·보존/자원·실패 보정·시험 범위](runtime_parity_validation_20261014.md).

2026-10-14 추가 인수 조건: 사용자는 거부된 contract.py/host.py 변경의 실제 미반영 확인과 안전한 대안, WAL 포함 SQLite 온라인 백업, 수동/override 워커 중복 방지, 기존 인증/통지/경보/운영 DB 보존, 검증된7룰 제한, 실제 가용 메모리와 ES/다른 워커 사용량을 반영한 Kibana 예산을 요구했다. 신규/업그레이드/중단 재실행/실패 복구를 모두 통과하기 전 전체 배포 완료로 표시하지 않는다. Git push/main 병합은 금지하며 다른 중앙 접속 불가는 미검증으로 남긴다. 현재 운영 DB 디렉터리 RW preflight mount 거부안은 적용하지 않았으며 호스트 online backup의 독립 복사본만 RO로 검사한다. 관련22개와 기존 Windows 실행 정책 의존2개를 프로세스 한정 RemoteSigned로 재검증해24 passed이며 운영 적용/실수신 인수는 아직 미실행이다.

## 2026-10-14 최신 Git 통합·지정 VM 배포 요청

2026-10-14 사용자 후속 지시: Git 푸시는 하지 않는다. 이번 배포 기록은 로컬 미커밋 문서로 보존하며 원격 main에 쓰지 않는다.

2026-10-14 최종 인수: 사용자가 정확한 초기 통지 읽기 권한 추가를 명시 허용해 기존 역할을 백업하고 soc-alert-notices-v1의 read/view_index_metadata만 보완했다. 인덱스/키/비밀번호/쓰기 권한은 변경하지 않았다. 초기 컨테이너 root의 private 디렉터리 접근 차단은 기존 앱UID로 보정했고 보호 권한을 완화하지 않았다. 실제 미설정200과 홈/개인8조합의JS0/HTTP오류0/넘침0/로그아웃401·앱3개최신이미지/restart0을 확인해 배포/조회 범위만 완료했다. Git commit/push는 하지 않았다. 약15시간 분석 적체·Windows/웹 신규수신미확인·기존Kibana heap 재시작8회·새worker/룰활성화/독립DR는 남는다.

2026-10-14 배포 결과/남은 조치: main7bb5fa0·Windows/Ubuntu Actions38528572643 success·공개 실행259개 Git SHA/import/pipcheck/14룰offline 검증 후19:03:46 KST에 지정VM의portal/normalizer/detector만0099d8b7…로 적용했다. SQLite8개 online backup/각memory restore·각중지시점8개 추가보호·기존명령/900초/상태identity·키/CA/수집기·경보2개/사건/저장dashboard를 보존했다. 관련223 Python/2subtests·21UI·Ruff/diff, 실제TLS 세션로그인/8API200·정적4파일·홈/개인×PC/모바일×두테마8조합/JS0/가로넘침0/로그아웃401을 확인했다. 배포후Linux시스템128/네트워크310건 수신 표본을 확인했지만 같은 표본Windows/웹0·신규정규화0이며 약15시간 적체가 남는다. 현재기본AUTH프로필을보존했고 다른중앙의priority/additional/회고worker나7룰활성화를이VM에복제하지않았다.

첫 적용은 Kibana 자체자동재시작을 보존검사가 감지해 이전 앱이미지로복귀/DB불변 후 재적용했다. Kibana의기존Node heap out of memory/FATAL과후속restart count8을확인해안정화미완료로남긴다. 실제초기통지API503은조회계정의soc-alert-notices-v1 읽기권한누락/해당index부재로진단했다. 정확read/view_index_metadata만추가하는백업/복귀변경안을준비했으나자동승인검토가별도보안권한변경이라며차단해미실행·사용자명시승인을요청했다. 이 시점에는 조회 문제의 승인을 기다려 UPDATE-RELEASE-20261014를 unchecked로 유지했다. [실제결과/실패보정/활성명령/보호본/제한](latest_release_20261014.md).

- [x] UPDATE-RELEASE-20261014 완료(2026-10-14 최신 소스 보호 배포·포털 조회 범위, 적체/Kibana 안정화는 잔여): 사용자 최신 요청에 따라 현재 Git을 원격 main으로 최신화하고 지정 중앙 VM에 검증된 소스를 보호 배포한다. 사용자가 이번 대상을 `192.168.235.128`로 다시 확정했다. 기존 운영 명령/선택 룰·체크포인트·DB·경보/사건·개인 대시보드·키/CA·수집기를 보존한다. Git 최신화·CI·실제 배포·실수신은 각각 검증하며 기존 통합 설치/클라우드 미인수 작업은 완료로 바꾸지 않는다. main 직접 push/강제 push/자동 병합은 수행하지 않는다.

2026-10-14 사전 확인: 작업 트리는 깨끗했고 기존 `codex/unified-site-agent-20261013`을 원격 main `7bb5fa0328c9611681d64d88e8faca3d1fc364d5`까지 fast-forward했다(47개 파일의 기존 병합 변경 포함). Actions38528572643의 Windows/Ubuntu 두 job success를 확인했다. 이전 중앙192.168.32.60은 SSH timeout, 사용자가 확정한192.168.235.128은 SSH 도달/기존 host 검증 가능하나 키 인증은 불가하여 기존 비밀번호 인증이 필요하다. 아직 새 배포/실수신 인수를 수행하지 않았다.

- [x] DUAL-LIVE-WIN-20261014 완료(2026-10-14 지정 시험 서버·7룰 선택 범위): 사용자 지정 최우선인 priority/기존 과거 처리 병행·공통ID/create-only·실제 홈/개인 상태 분리·WIN 실행worker의9→10경계·재시작/기존상태보존을 검증한다. 457e358 전체1072 Python/150UI·Ruff/Bandit·Actions38513272451 success, 보호 배포290개SHA·portal5DB backup/restore·원래AUTH900초/과거처리기불변·별도WIN검증state60초를 확인했다. 실제9개정규화/raw참조·window9/pending0·frontier마지막실패초과/경보0 이후177초내10번째실패를발생시켰으며최종경보1건/정확근거10개와후속재시작보존인수를완료했다. 실제홈은정규화39초/탐지37초·과거미완료구간0건·조회오류없음/1280px넘침없음을확인했다. 과거수백만건처리진척과실시간상태를별도표시하며지원밖/평가제외경고를유지한다.
- [x] DUAL-RETRO-20261014 완료(2026-10-14 코드·격리14룰·실제7룰 선택 범위): 이후늦게도착하는과거로그를실시간worker의900초frontier/DB를되감지않고 별도영속상태/수신체크포인트·정확근거창으로재평가한다. 유효필드/조직·상한/완전한검색·중복/create-only·문서불변을보존하고회고평가임을표시하며누락필드를정상/공격부재로판정하지않는다. 기존실시간경보와같은고유ID의재게시와늦은시퀀스연결·재시작/장애복구를검증한뒤명시선택된실제검증룰만운영적용한다.

## 2026-10-14 실제 이벤트 생성·조건부 활성화·배포 요청

- [ ] DET-EXT-ACTIVATE-20261014 진행 중: 사용자가 전체 검증 후 정상 룰의 활성화·기능 브랜치 일반 push·중앙 배포와 데이터 부족 시 실제 시험 이벤트 생성을 요청했다. 기존 DET-EXT-LIVE-01의 실제 인수를 우선한다. 지정 Ubuntu/Windows/AWS에서 제한된 인증·404·종료 flow와 정상/경계 이벤트를 발생시켜 정확한 원본→정규화→경보·포털 및 재시작을 대조한다. 필수 입력/권한이 없는 클라우드 룰은 격리 검증과 실제 수집을 구분하며 운영 활성화를 주장하지 않는다. 기존 상태·체크포인트/경보·초기 통지·개인 자료를 보존하고 먼저 정규화 지연을 해소한다. 실제 감사 중단·권한 부여·공개 관리 포트 변경은 승인된 격리 자원 없이 실행하지 않는다.

2026-10-14 최신 사용자 우선순위: 과거/실시간 이중 처리·create-only/공통ID·과거 적체와 실시간 상태의 별도 대시보드 표시를 최종 구조로 지정했다. priority의 보호 검증/배포 → WIN 실제9/10 경계 인수 → 늦은 과거 도착의 별도 재평가를 우선한다. 실제 OCI 제외·기능 브랜치 일반push/배포 요청·전체 기존 이력을 보존하며 과거 삭제/체크포인트 초기화는 하지 않는다. 023730f의 전체1064 passed/15skip/257subtests와 Actions38511072568 Windows/Ubuntu success, 기존5개서비스 그대로·portal/priority별도 state 보호 적용을 확인했다. 과거 처리기의현재 미완료75분 구간에서3599313건 처리 중 대 priority약45초 지연을 따로 관측했다. Windows10/SSH9대10·분산10·임시5실패→성공→root true·15종 종료Flow·웹20개의 실제 정규화/정확raw참조·엔진근거를 대조했다. 첫 진단의 비색인detail 필드 쿼리 기대는 실제색인범위/_source 엔진 평가로 보정했다. 임시시험계정은잔류 systemd user세션을 해당UID만 종료하여계정/true전용sudo정책을제거했다. 이 실제입력/읽기엔진인수는 아직추가운영worker의 최종경보/9→10지속실행/재시작인수와 구분한다.

2026-10-14 후속 범위/검증: 사용자 명시로 OCI-IAM-001은 이번 실제 시험/활성화에서 제외한다(기존 코드/격리 검증은 보존). 화면의 AWS 계정897722691159를 확인했으나 EC2 IAM 역할 없음·PC default STS InvalidClientTokenId로 실제 API 인증이 불가하다. 접근키 본문을 출력/기록하지 않고 기존 자격 증명 갱신 경로를 요청했다. 정규화 5분 전진 대비15분 중복 읽기와 약3시간 지연을 확인해 명시적 window-minutes1..60/interval10..3600을 추가했다. 기본5/60·15분 overlap/30초 안정화·page 상한·원래 시작점/SSH floor·미완료 구간의 재개/불변 create를 유지한다. 관련214 passed/9subtests, 전체1053 passed/15skip/257subtests·147UI·Ruff/Bandit 통과. 실제 지연 해소·통합 탐지·추가 활성화 인수는 진행 중이다.

2026-10-14 단계별 실제 결과: 60eedbd 일반push·Actions38509157919 Windows/Ubuntu success를 확인했다. 중앙 공개289파일/SHA·후보import/pipcheck·SQLite8개 online backup/격리restore 및 중지 후3개backup 뒤 portal/normalizer/detector만 de73b11b…로 적용했다. 기존AUTH/early/runtime 시작점·SSH floor·900초/비밀·ES/Kibana/gateway ID·사건/저장dashboard를 보존한다. 실제 Windows loopback SMB로 존재하지 않는 시험 계정의4625 9→10건/IP127.0.0.1/type3을 관측했으나 중앙 정규화/탐지 인수와 분리한다. 초기 잘못된 SMB 경로의 오류67을 기록·보정했고 권한/방화벽/계정을 바꾸지 않았다. 대량 기존 수신 때문에 과거 처리 지연이 남아 독립 priority 상태/지정수신floor와 별도status를 추가한다. 기존AUTH를 복제/초기화하지 않는 additional-rules 별도state/status·early소유 거부와 대시보드 추가 탐지 장애 표시를 보완해 관련69 passed/9subtests를 확인했다. 기본 프로필과 원래 체크포인트는 유지하며 실제 검증 전 후보 활성화는 보류한다.

## 2026-10-14 시험 서버 재시작·AWS 주소 변경

사용자가 AWS 새 주소13.208.191.1/기존 osaka 키와 중앙192.168.32.60/Windows192.168.1.138을 제공했다. 이전 승인 호스트 키를 사용해 동일 AWS 인스턴스·세 SSH 접속/수집 서비스·중앙 수신을 읽었다. 주소 변경으로 기존 웹 릴레이가13.208.175.237에 연결해 실패하며 seq5를 유지하는 상태다.
- [x] WEB-ROUTE-20261014 완료(2026-10-14 기존 전송 복구·raw 수신 범위): 기존 고정 AWS 호스트 키로 새주소/동일instance/container/조직·stream을 검증하고 목적 키의 제한 export를 확인했다. state/web-route-20261014T032810Z에 config/known_hosts/기존모듈·SQLite backup/무결성/격리restore 후 검증된 기존 Git의 주소 설정 지원 모듈을 적용했다. 새주소 핀과 config·transport binding만 조정하고 stream/전달seq5를 유지해126까지 이어갔다. root publisher/키/CA·정규화/탐지 상태·기존 경보hash/다른서비스 재시작은 변경하지 않았다. 새 raw121건 중 정상GET1회의302/200 두 문서 실제 source03:28:48UTC→receipt03:28:57UTC를 대조했다. 보호 배포/초기근거를 유지한 실제 새 수신이며 공격 룰 인수는 아니다.

2026-10-14 재기동 점검 제한: Windows 두 사용자 정의 수집서비스 Running/최근 중앙1970건·정상 인증유형3/5를 확인했으나 실제4625 실패/필수IP 시험은 하지 않았다. AWS CloudTrail 최근0/웹은별도이며 새IAM/과금/공개포트·새키/CloudTrail 설치·13개룰활성화는 하지 않았다. producer source_gaps1 경고/queue_gap=false를 보존했다. 중앙 normalizer checkpoint00:26:16UTC 대 실제03:30UTC로 약3시간 지연 중이며 새web 두 문서의 실제 정규화 참조는 아직 없다. 처리 위치를 되감거나 합성 정규화/경보를 넣지 않았다. 기존에 수집된 큐119건과 이번 새정상GET2건을 구분한다. 초기 소스바이트 해시의 Windows CRLF/Linux LF 차이는 적용 전 중단됐고 LF 정규화 SHA679dd31b…를 대조한 뒤 재개했다. 임시 원격 scripts만 정리했다. 이번 운영 복구 기록은 로컬 변경이며 새commit/push/전체앱배포는 하지 않았다.

## 2026-10-14 전체 14개 룰셋 구현·자동 검증 요청

사용자 새 요청을 최우선으로 적용한다. 지정 codex/dashboard-platform-20261013은 기존 33db896에서 검증된 최신 d49a4af로 fast-forward했다. 개인 Word/JSON·운영 DB/체크포인트·기존 경보를 보존한다. 전체 룰의 격리 실행·평가 불가 표시·엔진/근거/포털/사건 연동과 자동 회귀를 보완하고 일반 commit/push·CI를 확인한다. 실환경 필드/정상·경계 검증이 없는 룰의 운영 활성화는 하지 않는다.

- [x] RULESET-14-01 완료(2026-10-14 코드·격리 자동 인수·Git/CI 범위): 기존14개 엔진/정의를 재사용해 전체 격리·개별 선택/미검증·평가불가와 근거·조직·개인정보·재시작·장애 재시도·포털/사건/대시보드를 인수했다. 전체1,042 Python/15skip/257subtests·147UI/Ruff/Bandit/pipcheck/pip-audit·12개 브라우저 조합과 a1125fe의 Windows/Ubuntu GitHub Actions 모두 통과했다. 실제 수집/탐지 인수와 코드·격리 완료는 분리하며 운영13개 추가 활성화·배포는 하지 않았다. [룰별 결과·26개파일·제한](ruleset_14_validation_20261014.md).

2026-10-14 로컬 인수 완료·Git/CI 진행: 고정14개 profiles/CLI·raw/event ID 중복·SSH mirror/현행v2 및 두 웹 어댑터·필수 scope/bounds·source_events/assessment/포털 이력을 보완했다. 전체1,042 Python/15skip/257subtests·147UI/Ruff/Bandit 중간높음0/pipcheck·새프로세스14개/실제FlaskAPI·격리대시보드/이력12화면 조합 JS/HTTP0·가로넘침0 통과. 기존 중앙30일 읽기에서 SSH256/sudo51/Windows89/웹5/네트워크220,094·CloudTrail/OCI0을 구분했고 기존AUTH 근거10개의 경보ID가 새 코드와 같다. 운영은 기존AUTH/early 유지·새13개 미활성/미배포다. 초기 fixture/합성 API/도구venv 보정과 파일·실환경 제한은 [룰별 결과](ruleset_14_validation_20261014.md)에 기록했다. 개인정보/Word/JSON/state는 제외한다. 원격 CI를 확인한 뒤 이 로컬 코드·자동 검증 요청을 완료 표시한다. 상위 DET-EXT-LIVE-01은 미완료로 유지한다.

2026-10-14 최종 Git/CI: 구현 a1125fec0f3b14fa7b5633487df928878b0d523b를 지정 기능 브랜치에 일반 push했고 [Actions45](https://github.com/Gandalem/cloud-soc/actions/runs/38498674935)의 Windows/Ubuntu 두 job success를 공식 API로 확인했다. Ubuntu1,041 passed/18skip/255subtests·coverage90.1%·147UI·이미지빌드/게이트웨이4passed/18subtests도 확인했다(OS별 수치를 합산하지 않는다). 실제 임시 읽기 스크립트/localhost viewer·브라우저를 종료/정리했고 개인Word2개/JSON 최초SHA·main eec0717를 보존했다. 마지막 완료/CI 기록만 별도 문서 commit/push하며 동일 구현의 CI를 중복 실행하지 않도록 [skip ci]로 표시한다.


## 2026-10-14 기존 중앙 Ubuntu 최신화·배포 요청

사용자는 이번 대상을 기존 중앙 Ubuntu 192.168.32.60으로 확인했다. 최신 기록의 별도 VMware 192.168.235.128 배포와 구분한다. 원격 main eec0717의 공개 소스를 최신화하고 현재 실행 구성/개인 파일/서버 운영 변경·상태·키·CA·경보/사건·대시보드를 보호한 뒤 필요한 애플리케이션 서비스만 갱신한다. 새 프로필/수집기 설치·키/권한 변경·다른 서버 배포·공개 인증·CA 추가는 범위가 아니다. 최초 요청은 최신화/배포였으며 이후 사용자가 폼 소스 수정·commit/push까지 명시 허용했다. codex/vm-form-layout-20261014에서 결과를 검증·반영한다.

- [x] UPDATE-VM-20261014 완료(2026-10-14 지정 기존 중앙 최신화/배포 범위·ISSUE-12 일부): PC/192.168.32.60 저장소를main eec0717로 fast-forward하고 공개288개 개별SHA/import/pipcheck·관련158 Python/21subtests·145UI/Ruff/diff·main Windows/Ubuntu CI를 확인했다. SQLite8개/이미지3개/설정·키·CA 보호/개별restore와 중지 후3개상태 backup 후 portal/normalizer/detector만 적용했다. private endpoint/원래명령·시작점/900초/mount·ES/Kibana/gateway ID·저장 dashboard2/revision13/사건·경보hash를 유지했다. LAN 인증/API200·Ubuntu 두 수집기 recent·기존 web5 정확 참조와 checkpoint 전진을 확인했다. 분석 지연 해소/오늘 AWS 신규 수신/ES 독립DR은 미인수로 구분한다. [결과/실제 이미지/중단·보정/제한](ubuntu_update_20261014.md).

- [x] FIX-SITE-FORM-20261014 완료(2026-10-14 소스/실제 포털 폼 범위): 실제929px에서flex 사이트 높이2358px·dialog623/858px 넘침을 재현했다. agents.html의 선택 class·agents.css 세로 배치로 수정하고 실제4폭/2테마/3OS24조합·웹 선택/해제/시작 시각·JS/HTTP0·가로넘침0·UI145를 검증했다. 당시portal이미지/override·portal5DB의 backup/restore 후 정적2파일만 적용하고 다른5서비스·저장설정/사건을 유지했다. 최종portal498ca9e7…/patch c4438a03…이며 소스·실행 파일 해시를 대조한다. 패키지/토큰/키/설치는 생성하지 않았다.

2026-10-14 후속 Git 요청: 사용자가 프로젝트 폼 수정과 commit/push를 명시 허용했다. codex/vm-form-layout-20261014에 CSS/HTML·배포 기록/관리표·해당 브랜치 CI 실행 설정만 명시 stage한다. 개인Word2개/JSON의 최초SHA·비밀/state/원문 제외를 검사하고 main 직접push/자동PR병합은 하지 않는다. 실제 이미지의 base eec0717와 두 파일patch c4438a03…을 구분한다. 원래 분석 checkpoint를 전진시키며 남은 backlog를 전체 인수 완료로 바꾸지 않는다.

## 2026-10-14 통합 사이트 에이전트 요청

새 명시 요청으로 우선순위를 VM 임시 파일 정리 → 지정 AWS DVWA 실제 수신 → 통합 설치기 → 선택형 네트워크 → 상태/대시보드 연동으로 변경한다. 현재 `codex/unified-site-agent-20261013`에서 기존 미커밋 복구 변경과 완료 이력을 보존한다. Windows 키 만료 검사는 제외한다. 새 과금 자원·공개 포트·IAM 변경·main 직접 push/자동 병합은 실행하지 않는다.

- [x] SITE-CLEAN-01 완료(2026-10-14 실제 VM 정리): Ubuntu VM의 디스크/활성 경로를 읽고 재생성 가능한 임시 파일·빌드 캐시만 식별·정리한다. 서버 데이터·SQLite·설정·키·큐·기존 검증 및 복구 백업은 보존하고 정리 전후 용량과 실제 서비스 상태를 기록한다.

2026-10-14 사용자 추가 지시: 오래된 이미지·ES 스냅샷·백업도 삭제 대상으로 변경한다. 현재 실행 이미지/데이터·종류별 최신 백업을 식별해 남기고 구버전만 정리한다. 날짜가 오래된 ES 저장소 안의 최신 snapshot 및 실제 마운트 경로를 먼저 확인하며 저장소 파일을 임의로 지우지 않는다. 실제 시험 대상은 사용자가 기존 `56.155.117.55` → `192.168.235.128`로 확정했다(새 요청의 학교 주소/AWS 구주소 연결 timeout).
- [ ] SITE-AGENT-01 진행 중: 사이트 설정과 독립적인 시스템/웹/네트워크 선택을 단일 패키지에 반영하고, OS 지원·Filebeat 중복 방지·전송 전 민감정보 제거·수집 시작 범위·정확한 근거 참조를 검증한다. 기존 DVWA 수집·SSH 경보·사건과 사용자 대시보드는 유지한다. 코드/격리 시험·실제 배포·실수신은 각각 기록하며 지원하지 않는 범위는 차단한다.
- [ ] SITE-LIVE-01 진행 중: 요청 주소 AWS `13.208.175.237`와 중앙 `192.168.32.60`의 현재 접근/안전한 경로를 먼저 확인한다. 이전 지정 VMware/AWS 수신 이력을 새 대상의 검증으로 대신하지 않는다. 실제 웹 이벤트→ES→정규화→화면 대조 후에만 완료하며, 사설 경로 부재 시 공개 포트를 임의로 열지 않는다. 검증된 기능 브랜치 코드·문서를 commit/push하고 원격 CI를 확인한다.

## 2026-10-13 최신 main 배포·VM 스냅샷 복구 요청

- [x] LAB-RECOVERY-01 완료(2026-10-13 지정 VMware 최신 배포·Windows 미시작 스냅샷 복구·AWS 웹 전달/수신 범위, P0-02/P2-03/P5-01/02·ISSUE-12 일부): 사용자 요청으로 원격 main `ab62019`를 fast-forward pull하고 `codex/lab-recovery-20261013`에서 기존 기록을 보존했다. DB/처리 상태·이전 세 이미지·ES SUCCESS snapshot을 보호하고 최신 포털/정규화/탐지기 공개 파일 282개를 검증·적용했다. 기존 시작점/SSH floor/상태·상한/900초/AUTH·키/CA/Linux 설정과 원래 대시보드/경보를 유지해 약22시간 분석 지연을 같은 체크포인트에서 복구했다. Windows의 오래된 시각·검증된 미시작 예약 파일을 보존 복구한 뒤 최신 토큰 통합 설치의 실제 양 수집기 수신/complete·SYSTEM task 결과0을 확인했다. AWS 고정 IP를 보호 설정으로 보완하고 목적 전용 제한 SSH pull로 VM에 웹 raw7/정규화7/실제 관리자 포털7행을 대조했다. 관련200 Python/새 웹43/UI145·실제12화면/JS0·로그인/로그아웃·최종포털백업복원 통과. 기존 Restricted 설치기2건의 실행 제한·운영 도구 실패/보정은 남겼다. Windows 초기 과거 이벤트 재수집/전체 분석 소진·모든 위험 해석·CloudTrail/웹 공격/새프로필·독립DR은 완료하지 않았고 상위11/24/P2-02 보류를 유지한다. 코드 수정·이번 기록은 미커밋/미푸시이며 [결과·실제 구성·복구·제한](lab_recovery_20261013.md)에 근거를 보존한다.

후속 대조: 23:41 KST 복구 후 Windows 실제 4624 로그인 성공의 raw→정규화 정확 참조·windows_security_v1/login/success를 확인했다. AWS producer 공개3개는 최신 main 해시와 일치한다. 23:31 표본의 Windows 로그383,031/네트워크2,988은 새 수집기에서 과거 보존 이벤트도 읽은 수치다. 정규화 한 회차의 미지원382,655건을 위험 평가 성공으로 표시하지 않으며 해석 범위·초기 물량 소진/처리량은 P3/P5 잔여로 유지한다. 기존 수집 범위 설명의 ‘이번에 AWS/DVWA 실수신 미확인’은 Git 최신화 전 읽기 당시 기록이며 이번 지정 VMware/AWS 실제 웹 수신 인수와 구분한다.

## 2026-10-13 AWS DVWA 웹 수집 최우선 요청

새 명시 요청으로 ISSUE-04의 실제 DVWA 접근 로그 수집·정규화·포털 조회를 최우선으로 바꾼다. Windows 키 만료 확인/교체·인증 실패·CloudTrail 구축·공격 시험·새 탐지 규칙 활성화는 후순위로 두며 이번 범위에서 실행하지 않는다. 기존 기능 브랜치/개인 파일·SSH AUTH/early·900초 유예·체크포인트·대시보드를 보존한다. 지정 AWS/중앙의 기존 승인 접속과 웹 전용 코드/서비스·최소 권한 구성·보호된 변경 서비스 적용·기능 브랜치 일반 commit/push는 요청 범위다. 새 과금/IAM/공개 포트/VPN·개인 SSH 키 중앙 복사·공개 관리자 인증·TLS 우회는 금지한다.

- [x] WEB-LIVE-01 완료(2026-10-13 지정 AWS/중앙 실제 수신 범위): regular/combined Apache·Docker 중복·회전/개인정보·직접443/9200 timeout·기존 중앙→AWS22를 읽고 목적 전용/제한 SSH pull을 선택했다. 메타데이터 큐→실제 중앙5건→정규화5건→포털 참조/해시를 대조했다. 원래 Apache/DVWA와 기존 서비스/키를 보존했다.
- [x] WEB-LIVE-02 완료(2026-10-13 실제 정상 GET 범위): 정상 GET4회가 redirect 포함5개 실제 Apache 이벤트로 수신됐다. 실제 시각/peer IP·ID·중복/정확 참조를 대조했으며 합성 이벤트/공격/과거 재수집을 하지 않았다.
- [x] WEB-LIVE-03 완료(2026-10-13 격리 privacy/허용 목록 회귀 범위): 웹32개 격리 시험에서 query/cookie/Authorization/token/body의 큐/export 미포함·잘못된 형식/시각/허용 외 필드·위조 scope/ID를 거부하고 IP 미관측을 추정하지 않았다. 실제5건도 동일 스키마 검증 통과. 실서버 민감 canary는 실행하지 않았다.
- [x] WEB-LIVE-04 완료(2026-10-13 격리 회전·실제 재시작 범위): 격리 rename/copytruncate/누락/상한/실패 재개를 검증했다. 실제 producer 재시작 stream/4건 유지, relay 정지 중 GET1건 보관→기존cursor4에서5로 재개·409무중복을 확인했다. 실제 Apache 강제회전은 미실행, 손실 가능성을 보고서에 남겼다.
- [x] WEB-LIVE-05 완료(2026-10-13 코드·보호 적용·실제 관리자 읽기 범위): 실제5건의 web 어댑터/raw/normalized/시간/HTTP/조직/해시·목록/상세와 OS Linux를 인수했다. 전체852 Python/19skip/257subtests·145 UI/Ruff/Bandit/diff·소스Windows/Ubuntu CI 통과. 초기portal/normalizer·OS후속portal만 보호 적용하고 다른서비스/사건/dashboard2/revision13을 보존했다. [웹 수집 보고서](aws_dvwa_web_collection_20261013.md)에 파일/이미지/근거/실제 viewer 범위·장기운영 제한을 기록했다.

2026-10-13 추가 요청/진행: 사용자 화면에서 AWS web 수집기의 OS가 '정보 없음'으로 표시되는 결함을 WEB-LIVE-05에 포함한다. 실제 raw의 host.os.type=linux와 수신 현황의 name-only 투영 차이를 수정한다. OS 이름이 없으면 명시된 OS 유형/센서 태그만 사용하고 AWS/IP로 OS를 추정하지 않는다. 통합 로그의 cloud 분류는 '해당 없음 (클라우드 API)'으로 표시한다. 서비스 수신 상태를 heartbeat로 바꾸거나 Windows 접근/키 작업을 재개하지 않는다.

2026-10-13 WEB-LIVE 작업 기록: src/cloud_soc/web·deploy/web·portal security_detail/log_contract/log_query/agent_status·processing contract·통합로그 UI/회귀/CI를 반영했다. 웹 소스8626b57, 새 web-only receipt8a8b5bd, OS후속fe61a65를 기능 브랜치에 일반 push했다. 최초8개DB/이미지2개·OS후속8개DB/당시portal이미지와 실제override/키/CA를 보호하고 개별 SQLite 무결성/격리restore·실제 이미지 파일 해시를 대조했다. 마지막 portal image97a31880…/normalizer a41dafd7…이며 source/assets의 범위를 보고서에 구분한다. 실제 LAN CA/IP 검증 API·읽기전용 localhost viewer에서5행/상세·Linux·1440/768/390 두테마/JS0·document넘침0을 확인하고 임시 viewer/browser를 닫았다. 평상시 첫 source→receipt9.07초는 단일 관측이며 지속SLO가 아니다. 개인Word2개/JSON의 원래SHA·main b67eefa·기존AUTH1/early/900초/사건/dashboard2/revision13을 보존했다.

WEB-LIVE 남은 운영 범위: PC CA 경고(추가 신뢰 거부 유지)·직접AWS→중앙 경로·source IP/목적키 만료 관리·큐 상한/회전 손실 가능·ES 장기보존/독립DR/다실계정/지속SLO는 미인수다. 기존 위험 평가 누락·미지원 경고를 숨기지 않았다. Windows 키/실패·CloudTrail·공격/새규칙활성화/ngrok 인증을 실행하지 않았다. 이번5개 체크 완료는 지정 정상 웹 수집 인수이며 기존 P0~P7의11/24·전체 운영 기준을 변경하지 않는다.

## 2026-10-13 전체 장애 이력·운영 안정화 요청

새 명시 요청에 따라 기존 수정의 재구현보다 FIX-01~14/HIST-01~07의 현황 대조와 ISSUE-02 실제 사건 업무를 우선한다. 최신 기준은 main b67eefa·기능 브랜치7968915이며 Windows/Ubuntu CI 성공을 공식 API로 확인했다. 개인 Word/JSON·비밀/상태·원래 완료 이력을 보존한다. 코드 검토·읽기 점검·격리 회귀·기능 브랜치 commit/일반 push를 수행한다. 사용자 기존 서버 접속/포털 시험 범위의 사건 기록/보호 재시작을 사용하며 ES 설정/복원·AWS 리소스/새 에이전트·CA 신뢰·공개 인증 전송·신규 규칙 활성화·main/PR는 제외한다.

- [x] AUDIT-01 완료(2026-10-13 이력/읽기 대조·보고 범위): 제품 편집 전 관리표를 작성하고 FIX14/ISSUE15/HIST7의 최초 참조/증상/원인/기존 수정/코드·현재 지정 서버·재현/회귀·잔여·우선순위를 대조했다. 4상태 분류와 실제 관측 제한은 [통합 보고서](cloud_soc_issue_audit_20261013.md)에 보존한다. 전체 운영 완료를 뜻하지 않는다.
- [x] ISSUE-02 완료(2026-10-13 실제 HTTPS API·Basic/admin 범위): 실제 AUTH-001 근거10개를 대조해 시험 사건 d868e3a5291543adbacdb286e74bae00을 생성·배정·메모·사용자 선택 benign/closed 판정·종결했다. 목록/동일 요청 재시도/재인증·두 포털 보호 갱신 후 전체 사건/이력5개/근거10개·원래 경보 해시/사용자 dashboard2개 revision13 동일을 확인했다. 시험 사건은 남긴다. 이번 직접 browser는 CA 신뢰 제한·화면은 합성이며 추가 실제 세션/조직·전체 장애 복구는 상위 기준에 남긴다.
- [ ] ISSUE-12 부분 완료(2026-10-13 도구·현재 읽기/복구 기록): runtime_audit.py/runtime-audit.py의9개 회귀·실제6서비스/active override CLI·복사7파일 해시/이미지·start/floor/프로필/DB·키/CA·타5서비스 불변을 대조했다. runbook을 실제517178d 포털/3b9 worker/92d13c0 checkout으로 보완했다. 전체 source tree 동일화·다른 서버/VM 재부팅·독립복구는 미인수로 남긴다.
- [x] ISSUE-13 완료(2026-10-13 코드·격리/화면·포털 적용 범위): 초기 실패/재대조/전달·입력 미완료가 있어도 final 성공만으로 healthy가 되던 결함을 신규9 실패/1 통과로 격리 재현한 뒤 숫자·누락·오류/명시 이유를 보완했다. 전체818 Python/144 UI·4화면×3폭×2테마/JS0·현재 portal early observed 투영을 확인했다. 실제 초기 장애 주입·지속 SLO는 미실행이며 실제 제외warning은 유지한다. e301783/517178d·portal image04daf08f…이며 worker는 바꾸지 않았다.
- [x] ISSUE-08 이번 격리 회귀 완료(2026-10-13·전체 실계정 인수는 미완료): 기존 before_request의 admin 전역 조회·분석가/조회자/타조직403·ES미조회를 유지하고4개 세션 회귀를 강화했다(history와23 passed). 권한 코드를 재구현하거나 실제 계정/조직을 만들지 않았다. 상위 추가 실계정 인수는 미완료 상태를 유지한다.


2026-10-13 작업 기록: 사용자 승인 후 cloud_soc_agent_monitor에 두 정확한 history index의 read/view_index_metadata만 추가해 실제503→200/no_index를 복원했다. reader_maintenance.py/reader-history.py의6개 회귀·stale review/DLS-FLS 거부·기존 grant/user/password/key/문서 불변을 대조했다. 포털 적용 전 새 사건을 포함한 DB5개/이미지/override/키/CA를 새 보호 경로에 보관했고 최초8 SQLite 개별 online backup/격리restore도 통과했다. 전체818 passed/19 skipped/257 subtests(99.05초), UI144 passed, Ruff/Bandit/diff, e301783/517178d Windows/Ubuntu CI 성공이다. 원격 main b67eefa·개인 Word2개/JSON·기존11/24·P2-02 보류를 유지했다.

현재 제한/다음 순서: ES snapshot repository/path.repo 없음으로 전체 ES/독립DR은 미실행(primary미할당0/replica3의yellow). AWS SSH/DVWA GET200·ap-northeast-3·수집 경로 부재/중앙 AWS·HTTP0, Windows SSH/두 수집 서비스/발견 task 정상·4625 최근7일0, Flow 필드9/정확 정규화9를 읽었다. 신규 후보는 비활성이다. Windows 관련 유효 키2개가10/14 15:50 KST 만료하지만 현재 collector 연결은 미확정이므로 **실제 설치와 키 연결의 읽기 확인을 먼저** 준비한다. 키 발급/교체/폐기는 승인하지 않았고 실행하지 않았다. 이어 독립 백업·실제 Windows/AWS/웹 수집·선택 규칙·SLO/다계정/수명주기 인수 순서다. CA 추가/SSL 우회/공개 인증·ES/수집기/worker/gateway 재시작·새 AWS 자원·main/PR는 수행하지 않았다.

## 2026-10-13 직접 LAN IP 빈 화면 진단

사용자의 실제 브라우저 화면 지적으로 직접 `https://192.168.32.60/` 접근 문제를 우선 검토했다. CA/IP 검증을 유지한 무인증 실제 요청에서 IP Host는 HTTP200·본문0 bytes·인증 challenge 없음, 동일 LAN 주소/기존 도메인 Host는 HTTP401·JSON88 bytes·Basic challenge였다. 현재 Caddy의 공개 Host 전용 라우팅과 일치한다. 이전 실제 포털 인수는 기존 Host를 지정한 LAN 프록시 경로였으며 직접 IP 주소창 접근의 인수가 아니었다. 그 검증 범위 차이를 이전 요약에서 충분히 설명하지 못했다. 원래 기능/실수신 인수 이력을 취소하거나 직접 IP 인수 완료로 바꾸지 않는다.

- [x] FIX-LAN-01 완료(2026-10-13 코드·지정 중앙 보호 적용·직접 접속 인수): 명시 HTTPS 사설 IP alias·정확한 Host별 Origin과 기존 인증/CSRF/공개 주소/수집 endpoint를 보존하는 포털/Caddy/Compose를 수정했다. 실제 Caddy 두 구성·이미지/설정/SQLite 보호·격리 restore 후 포털/게이트웨이에만 적용하고 직접 IP의401 로그인 요구·인증200/HTML·API200·타 Host Origin403·실제 브라우저 홈1440/390/개인·동일 구성 저장/재조회·확정 통지1/JS 예외0을 인수했다. 관련91 passed/4 subtests·전체789 passed/19 skipped/257 subtests(94.83초)·Ruff/Bandit/diff 통과. ES/Kibana/정규화/탐지 실행·비밀/CA/TLS를 유지했다. 사용자는 CA 신뢰 추가를 원하지 않아 신뢰 저장소를 바꾸지 않았고 일반 브라우저 인증서 경고는 남는다. [파일·실제 이미지/patch·보호/복구·검증 제한](lan_portal_fix_20261013.md).

## 2026-10-13 시험 서버 보호 적용·검증·Git 반영 요청

새 명시 요청으로 FAST-LIVE-01 사전 점검·보호 배포·통제된 SSH 인수와 검증 소스의 현재 기능 브랜치 commit/push를 허용한다. main 직접 push·강제 push·PR 생성/병합·원본/상태 초기화·AWS 자원 변경은 허용하지 않는다. 기존 대시보드 완성 코드/개인 Word·JSON·상태/접속 자료와 이력을 보존한다. 현재 실제 중앙 서버·권한·백업이 확인되지 않으면 배포를 중단하고 로컬 검증/Git 반영은 계속한다.

- [x] DEPLOY-EARLY-01 완료(2026-10-13 지정 시험 중앙·기본 AUTH·관리자 인수): 보호 확인 후 승인된 정규화 추가·초기 AUTH/포털만 적용하고 정상SSH·실제9/10·검색 관측→화면25.894초·최종 frontier/같은 notice·proof10·탐지/포털 재시작·원래 행/키/CA·수집 유지·관리자 두 크기/테마를 검증했다. snapshot은 미지원으로 미실행이며 사용자 승인 범위에서 기존 ES 원본을 수정·삭제하지 않았다. 전체 ES 재해 복구·추가 역할/신규 후보/Windows·AWS 위험 인수는 완료하지 않는다. [결과·소스·이미지·시각·복구·제한](early_deployment_validation_20261013.md).
- [x] GIT-FAST-01 완료(2026-10-13 기능 브랜치 commit/일반 push): 초기 탐지18dabf7·대시보드/연동000659f·정상 키 보완3b9aff9·검증 문서d718ec9를 명시 stage/review하고 codex/dashboard-platform-20261013의 원격 SHA/파일·Windows/Ubuntu CI 통과를 확인했다. main=b67eefa를 유지했고 개인 Word/JSON 해시·비밀/state/output 제외·문서 링크/비밀번호 미포함·diff를 검사했다. 마지막 Windows 후속 결과/완료 기록도 같은 브랜치 일반 push로 보존한다. [결과](early_deployment_validation_20261013.md).

2026-10-13 진행 기록: 사용자가 현재 중앙 서버 192.168.32.60과 관리자 권한을 확인하고, 기존 해시 백업 후 포털 admin 비밀번호만 변경 및 누락된 정규화 서비스 추가를 별도 승인했다. 기존 원본 문서/매핑·수집 endpoint·기존 키와 ES/Kibana/수집기 실행은 보존한다. ES snapshot repository/path.repo가 없어 snapshot은 미실행이며 기존 문서 수정·삭제 없이 새 수신 시점부터 처리한다. 포털 이미지·설정·키/CA, SQLite 온라인 백업과 격리 복원은 통과했다. 소스 000659f 기반 후보 이미지의 누락 의존성을 기존 서비스 교체 전에 발견·고정 requirements로 보완했다. 포털/정규화/기본 AUTH 탐지+early만 적용했고 start=2026-10-13T02:35:47.839670+00:00, lateness=900초를 유지한다. 실제 SSH journal 9/10회, 정규화 미러 18/20건→고유 실패 9/10건·초기 통지 0/1건·proof10개 참조/해시 일치를 확인했다. 실제 검색 관측 02:53:24.451157 UTC→Chrome 표시 02:53:50.345 UTC(약25.894초)이며 최종 frontier·재시작 인수는 아직 진행 중이다. 두 기능 커밋 18dabf7/000659f를 현재 기능 브랜치에 일반 push하고 원격 SHA 일치를 확인했다. Ubuntu CI는 통과, Windows CI는 확인 중이다. 자격·원문·개인 파일은 기록/Git에서 제외했다.

- [x] MULTI-HOST-01 완료(2026-10-13 지정 서버 점검·수신 범위): Ubuntu 인수 후 AWS 정상 SSH/DVWA GET200·중앙 수신0/경로 부재를 확인하고 사용자 선택에 따라 현재 점검 결과만 기록했다. Windows는 기존 동일 키의 보호 복원 후 HP SSH·두 수집 서비스·새 OpenSSH 성공1/HP4624 2→정규화 정확 참조2/성공/LogonType3→LAN 포털API200·실제 화면/JS 예외0을 검증했다. Windows 유효 source IP0과 비활성 후보는 유지하고 Windows 실패 공격·AWS 센서/감사 구성·신규 탐지 위험 인수는 미완료로 분리했다. 공개 인증 전송 대신 CA 검증 LAN을 사용했고 임시 프록시/브라우저를 종료했다. [범위·시각·제한](early_deployment_validation_20261013.md).

2026-10-13 MULTI-HOST-01 기록: AWS의 정상 SSH·DVWA GET 최종200 및 중앙 감사 수신0/기존 수집 경로 부재를 확인했다. 사용자는 현재 점검 결과 기록을 선택했으므로 AWS 설치/자원 변경은 하지 않았다. Windows의 실제 HP·관리자 그룹·기본 Match·파일 owner/ACL·인코딩은 정상이나 현재 관리자 키 파일에는 지정 공개키가 없었다(등록 여부 False). 같은 승인 키만 현재 지정 VM에서 보호 백업 후 추가하는 콘솔 절차 실행을 기다리며 Windows 직접 SSH 시험은 미검증으로 남긴다. 중앙 Windows 최근 수신·필드 표본은 별도로 확인했고 비활성 Windows/AWS 규칙의 실제 탐지 완료로 간주하지 않는다.

2026-10-13 MULTI-HOST-01 후속 완료 기록: 사용자가13:08 KST 기존 관리자 키/ACL 백업 후 동일 승인 키 추가를 완료했다. 이후 실제 정상 SSH·서비스·새 보안 이벤트→중앙/정규화 직접 ID/provenance→포털 API/화면을 인수했다. HP4624 2건의 LogonType3은 보존되지만 source IP는 없는 실제 관측이며 OpenSSH 본문의 출발지를 Security 이벤트에 대입하지 않았다. 미실행 Windows 실패·미구성 AWS 감사·비활성 신규 프로필의 인수는 DET-EXT-LIVE-01/P3-01/P4-01에 남긴다. 개인 파일을 보존하고 `state/deploy-early-20261013/windows-live-report.json`·Git 제외 화면을 검증 증거로 보관한다.

2026-10-13 신규 후보 실제 필드 후속: 최근15분 네트워크 receipt7,297건과 처리 시간을 둔 표본100건에서 종료Flow6·필수 필드 충족5→정규화 정확 ID/provenance5를 대조했다. 최근 정규화 http_access0·AWS 감사0은 미수집/경로 인수 제한으로 기록했다. [5개 후보별 실제 데이터/잔여](early_deployment_validation_20261013.md)를 추가하며 신규 프로필을 활성화하거나 DET-EXT-LIVE-01을 완료로 바꾸지 않는다.

- [x] FIX-AUTH-KEY-01 완료(2026-10-13 코드·실제 보완 적용): 정상 publickey 성공의 제한된 ED25519/RSA/ECDSA SHA256 suffix를 인식하고 지문은 결과에 남기지 않는다. 실제 형식 대조·12개 추가 경계/개인정보/실패 회귀, 관련92 passed/7 subtests·전체774 passed/19 skipped/257 subtests(89.34초)·Ruff/Bandit 중간/높음0을 통과했다. 3b9aff9를 일반 push하고 Windows/Ubuntu CI 통과 및 동일 소스 이미지 적용 후 새 정상 성공6문서·출발지 경보0·기존 final 전체문서SHA/proof/identity와 원래 행/키/CA 보존을 확인했다. 원래15분 겹침 구간에서는 이전 unclassified와 별도 성공 해석이 추가될 수 있으며 원본/이전 해석을 삭제하지 않고 start/체크포인트를 되감거나 전체 과거 재처리하지 않았다.

## 2026-10-13 빠른 초기 경보·탐지 확장 우선 요청

새 명시 요청에 따라 FAST-01/DET-EXT-01을 우선 구현한다. main 기준 b67eefa와 codex/dashboard-platform-20261013의 미커밋 대시보드·개인 Word/JSON을 보존한다. 기존 900초 지연·AUTH 9/10건·create-only 경보·상태 identity·권한·마스킹을 유지한다. 이후 사용자가 지정 서버/키로 테스트를 허용해 TCP/SSH·기존 서비스 및 DVWA 정상 GET 준비 확인을 추가했다. 신규 기능 운영 배포·프로필 활성화·키 발급·실제 공격/AWS 자원 변경·commit/push/merge는 실행하지 않는다.

- [x] FAST-01 완료(2026-10-13 코드·로컬/합성 인수): 명시 early-auth의 독립 sidecar/불변 notice revision·최종 링크 outbox와 5상태, 논리 ID별 최신 조회/기간·홈/개인 widget/정확한 초기 proof·시각을 구현했다. 9/10·원본/정규화 버전/미러·조직/IP/창·900초/final checkpoint 독립·부분 spool·전송/409/최종 장애·링크 큐 overflow·새 worker process 재시작·권한/0/미설정/503·1440/768/390 두 테마 인수를 통과했다. 합성 ES/실제 Flask·Chrome 3회에서 생성10~13ms/화면최대10.529초다. 운영 60초는 미측정이며 FAST-LIVE-01로 분리한다. [보고서](realtime_detection_20261013.md).
- [x] DET-EXT-01 완료(2026-10-13 코드·명세·합성 인수): 기존 AUTH/sequence/ATTACK01~03/cloud single을 재사용하고 metadata-cardinality-v1·5패턴 실행 코드를 추가했다. default AUTH만 유지, 명시 include-patterns는 SSH 다수 계정 후보만 추가하며 Windows/웹404/종료flow포트/AWS콘솔4개는 비활성이다. DET01~11의 필드/정상·오탐/한계와 WEB01~05 미지원 gate를 기록했다. 임계값·누락/식별자/시각·raw/flow/event ID·조직·정상/성공/HTTP오류·대량 중복·cooldown/순서·identity 거부·회귀를 통과했다. 실제 운영 활성화/인수는 DET-EXT-LIVE-01로 분리한다.
- [x] FAST-LIVE-01 완료(2026-10-13 지정 중앙·기본 AUTH·관리자): 실제 명령/이미지·명시 start/SSH receipt floor/lateness900·전용 키/notice exact mapping·최소 read/create_doc·두 탐지 DB 일관 backup/격리 restore를 확인했다. 실제 고유9/10→초기0/1·25.894초 Chrome 표시·실제 최종 frontier/근거10/같은 notice·재시작 불변 경보SHA/설정/proof·수집 유지가 통과했다. 합성 수치를 대신 쓰지 않았으며 1회 LAN 관측/초기000659f 측정과 후속 정상 키 보완3b9aff9의 범위를 [보호 인수](early_deployment_validation_20261013.md)에 구분했다. sustained SLO·다른 역할/프로필·ES 독립복구는 별도다.
- [ ] DET-EXT-LIVE-01: Windows 현재 SSH 인증·Ubuntu 중앙 읽기/실수신·AWS 기존 메타데이터 수신 경로를 확인하고 신규 후보의 실제 필수 field gate·정상/경계/오탐을 인수한다. 현재 네 후보 비활성과 기존 P0~P7 완료 수/기준은 유지한다.

2026-10-13 FAST-01/DET-EXT-01 기록: src/cloud_soc/detection/{early,patterns}.py·portal/notices.py·metadata_patterns.yml·alert-notices.js/css 및 detector CLI/registry/telemetry/최종 링크·setup/monitor read-only 권한·portal API/세션·홈/개인 provider를 추가했다. 최종 전체 Python762 passed/19 skipped/257 subtests(86.94초), UI142 passed, Ruff·Bandit 중간/높음·diff 통과. 브라우저 JS 예외0·가로/modal 넘침 없음, 의도한503은 기대된 실패다. 초기 전체 role 기대 누락·fixture options 공유/종결 역전 기대를 수정했으며 동일 원본의 정규화 버전 중복과 malformed UI를 보완 후 전체 회귀를 다시 통과했다. Git 제외 output/playwright/early-notices에 화면/실측 JSON을 보존한다. 사용자 제공 AWS 키의 기존 ACL 메타데이터를 보호 보관하고 일반 그룹 상속 읽기를 제거해 ec2-user 접속을 확인했다(키 내용/발급·서버 변경 없음). AWS DVWA HTTP80/기본GET302와 SOC 수집기 not-found, Ubuntu 두 수집기/timer active(중앙은권한미확보), Windows TCP22/현재키인증거부를 확인했다. 접속/Running을 중앙 저장·배포·위험 탐지 성공으로 간주하지 않는다. 제공 키/비밀/원문은 tracker에 기록하지 않았다. 운영 배포/활성화·실제 공격·AWS 자원 변경·commit/push/merge는 미실행이고 개인 Word/JSON·기존 대시보드 이력을 보존한다.

## 2026-10-13 사용자 맞춤 대시보드 확장 우선 요청

사용자의 새 명시 요청에 따라 이번 구현은 발표 사건 시연보다 대시보드 확장을 우선한다. 기준은 main b67eefa이며 codex/dashboard-platform-20261013에서 개인 Word·검증 JSON과 기존 이력을 보존한다. 운영 배포·실수신·커밋/푸시/병합은 이번 요청에 포함하지 않는다.

- [x] DASH-02 완료(2026-10-13 코드·로컬/합성 인수): 계정별 다중 대시보드 생성/빈 화면/4개 목적 템플릿/이름 변경/복제/삭제 확인/기본 지정/즐겨찾기, 독립 위젯·포인터/키보드 그리드·설정·검색 라이브러리·저장/취소/Undo/복원과 기존 실제 API 연결을 구현했다. 기존 /api/dashboard·설정 행 보존, 31개 후보(관리자 26개·일반 역할 23개 활성), 서버 허용 목록·revision·사용자/조직/역할·CSRF·XSS·형식 4/3/2 및 기존 백업 호환, 1440/768/390px 두 테마 브라우저·회귀를 통과했다. [결과·파일·명령·한계](dashboard_platform_validation_20261013.md). 운영 배포·실제 데이터/계정 인수는 미실행이며 DASH-01/P6/P7 전체 기준은 유지한다.

2026-10-13 DASH-02 작업 기록: main b67eefa에서 개인 Word/검증 JSON을 보존해 codex/dashboard-platform-20261013을 생성했다. 새 dashboard_collections 테이블·/api/dashboards·역할별 카탈로그, 개인 편집 UI 3개 자산과 기존 HTML 연결, 백업 형식4/이전 복원·로그 data_state를 추가했다. 기존 홈·탐지/수집/사건/원문 권한과 P2-02 보류는 유지한다. 최종 전체 Python 726 passed/19 skipped/257 subtests(78.51초), 전체 UI136 passed, Ruff·Bandit 중간/높음·diff 검사 통과. 전체 검사 이후 추가한 독립 앱 프로세스 재로그인 시험을 포함해 신규 파일31 passed를 별도 확인했으며 수치는 중복 합산하지 않는다. 브라우저 CRUD/취소/409/재로그인·드래그/리사이즈/키보드/복원·24개 위젯2요청/오래된 응답/0·미수집·403/503·중단·그래프·허용 높이5/7·4템플릿×3크기×2테마에서 최종 JS예외0·가로 넘침/주요 경계 넘침 없음이다. 의도한 403/409/503 HTTP 콘솔 오류는 기대된 실패다. 초기 상태 API 기간 생성/좁은 요약 카드/저장 후 비활성 버튼과 시험의 비동기 대기/백업 목적지/Windows DB 연결/이전 형식 기대를 수정·재검증했다. 증거는 Git 제외 output/playwright/dashboard-platform에 보존한다. 운영 서버·실제 ES/수집기/키·큐·새 규칙·커밋/푸시/PR/병합은 하지 않았다. 실제 역할·위젯 데이터·보호 배포/포털 재시작·운영 복구는 후속이다.

## 현재 상태 — 2026-10-12

목표: **위험 징후 수집 → 이해 가능한 경보 → 정확한 근거 → 사건/메모 저장 → 재시작 후 보존**.

기존 상위 P0~P7 완료는 **11/24개(45.8%)**입니다. 이 수치는 서로 다른 코드·격리·실제 검증 범위를 포함하는 작업 체크 기준이며 제품 배포 완성도를 뜻하지 않습니다. 이번 정리로 완료 수나 분모를 바꾸지 않았습니다.

| 단계 | 확인된 범위 | 남은 범위 |
| --- | --- | --- |
| 코드·로컬 시험 | 기존 탐지/권한/마스킹, 신규 홈·개인 대시보드, 고객 메뉴 정리 | 최신 전체 인수는 각 작업의 기준에 따름 |
| 실제 배포·복구 | 기존 정규화 복구와 신규 홈/개인 포털·세션 로그인 실제 보호 배포 | 추가 조직/역할과 실제 위험 경보·사건 전체 인수 |
| 실제 수신 | 배포 후 네 수집기 새 수신 ES→API, 실제 관리자 대시보드 숫자·설정/재시작 대조 | 추가 조직/역할의 실제 계정 화면 인수 |
| 실제 위험 시나리오 | 지정 VMware SSH 실패 9/10회·실제 경보/근거/대시보드, Windows 4625 원본·정규화 대조 | 범용 PAM·선택 프로필·AWS 및 사건 저장 전체 인수 |

날짜·완료 범위·테스트 수치·기존 인수 기준은 [전체 작업 이력](work_history_20261012.md)에 보존합니다. 최신 실제 보호 배포는 [2026-10-12 보고서](archive/validation/protected_deployment_20261012.md), 이전 고객용 복구는 [고객 개선 기록](archive/validation/customer_readiness_20261012.md)을 참고합니다. 과거 기록의 “당시 미배포”와 이후 실제 배포를 구분합니다.

## 다음 우선순위

2026-10-12 사용자 발표 일정 임박 요청으로 **발표 준비는 아래 기존 전체 인수 순서보다 우선**한다. 사용자는 이번 주 내 마무리와 제한된 사용량을 명시했다. 핵심 실제 시연을 먼저 완성하고 관련 검사·결함 수정 후 최종 전체 검사를 수행하며 동일 검사를 이유 없이 반복하지 않는다. 상위 완료 수·기존 인수 기준·검증/보류 이력은 유지하며 발표 범위를 제품 전체 완료로 표시하지 않는다.

| 발표 순서 | 작업 | 확인할 결과 |
| --- | --- | --- |
| 1 | P0-02 · P2-03 · P5-01/02 사전 점검 + P3-01 · P5-03 · P5-05 경보 시연 | VM/서비스·현재 키 만료·새 수신/분석 진행을 먼저 확인하고, 기존 AUTH 규칙의 통제된 정상/조건 충족 시험에서 새 원본→정규화→실제 경보→대시보드·정확한 근거를 대조한다. 가짜 경보 삽입이나 임계값 완화로 대신하지 않는다. |
| 2 | P6-02/04 · P7-01 사건 시연 | 검증된 경보에서 사건 생성→메모/판정→목록 재조회→재로그인/재시작 후 보존을 실제 포털에서 확인한다. |
| 3 | P7-02 발표 자료·재현 준비 | 검증된 흐름의 짧은 시연 순서·화면 증거·백업/복구 방법·현재 한계를 정리하고 안정된 시연 버전을 고정한다. 핵심 흐름을 막는 결함을 먼저 수정한다. |
| 4 | DASH-01 · UX-02 추가 조직/역할 | 관리자 시연 외 역할 시연이 필요하면 승인된 시험 계정을 준비해 조직/역할·개인 설정 격리를 검증한다. 실제 계정 인수가 없으면 기존 미완료 상태와 코드/격리 시험 범위를 명시한다. |

AWS 실제 연동·선택 공격 프로필 확대·독립 저장소/보존 정책과 전체 운영 인수는 발표 후 후속으로 남긴다. P2-02 사용자 보류는 그대로 유지한다. 발표 시연 일부 완료를 이들 상위 작업의 전체 완료로 바꾸지 않는다. 이번 기록은 진행도 분석/우선순위 정리이며 코드 수정·VM 변경·새 시험 이벤트·커밋/푸시·배포를 수행하지 않았다.

기존 전체 인수 순서는 다음과 같다.

발표 순서 1의 핵심 AUTH 실제 시연은 LIVE-AUTH-01에서 완료했다. **다음 발표 우선 작업은 P6-02/04·P7-01의 이번 실제 경보→사건 생성·메모/판정·재조회·재시작 보존**이다. P3/P5 전체 기준과 다른 프로필·조직/역할의 잔여는 유지한다.

| 순서 | 작업 | 인수 기준 |
| --- | --- | --- |
| 1 | P3-01 · P5-03 · P5-05 실제 위험 경보 인수 | 새 UI·관리자 로그인/로그아웃·설정 재시작·실수신 대조 배포 완료 후 SSH/PAM 정상/경계/조건 충족 경보·근거·화면 검증 |
| 2 | DASH-01 · UX-02 추가 조직/역할 인수 | 승인된 일반 계정이 준비되면 조직 범위·조회자/분석가·개인 설정 격리를 실제 서버에서 대조. 현재 정책 일반 계정은 0개 |
| 3 | P6-02/04 · P7-01 조사·저장 | 경보→근거→사건·메모/판정, 목록/필터 재조회와 권한·재시작/장애 후 보존 |
| 4 | P0-02 · P2-03 · P5-01/02 운영 잔여 | 최신 패키지·부팅 재발·수집 보고/오류·평가 제외 1건·정규화 참조/실패를 운영자 경로로 확인 |
| 5 | P4-01 · P5-03 AWS 실제 연동 | 계정/리전/최소 권한·수집 범위 승인 후 관리 이벤트 실제 필드·조건·근거 대조 |
| 6 | P7-02 운영·시연 마무리 | 실제 검증된 신규/갱신·백업/복원·키/CA 만료·인계·한계·재현 순서 |

새 요청인 고객 화면·문서 정리를 먼저 수행했습니다. **수집 상태·분석 진단·과거 분석 이력과 중복 관제 화면은 고객 메뉴에서 제외**하고 홈을 관제 시작점으로 사용합니다. 운영용 직접 경로/API·수집/분석 기록·권한은 유지합니다. 기술 위젯은 숨기되 기존 저장된 개인 설정은 자동 이행/삭제하지 않습니다. 로그 수신 확인은 통합 로그/에이전트 수신 현황, 분석 미완료 경고는 홈에서 제공합니다.

P5-05의 현재 고객 인수 기준은 기간별 실제 경보/수신 추이·미종결 사건 집계, 경보 펼침/근거 진입, 조회 실패/미측정/0건 구분, 분석 중단·지연 경고입니다. 기술 품질 보고·해석 범위 도넛은 고객 홈의 필수 위젯에서 제외합니다. 소스별 오류/큐 진단은 P2-03과 운영 검증에 남깁니다. 이전 기준과 P5C-02 완료 이력은 삭제하지 않았습니다.

## 신규·부분 작업

- [x] LIVE-AUTH-01 완료(2026-10-12 코드·로컬·지정 VMware 보호 적용·실제 수신/브라우저, P3-01/P5-03/P5-05 일부): SSH 신원·수집/처리 키 유효성·새 수신/분석 진행을 확인했다. 실제 정상 SSH 및 실패 9회→경보 0·5분 내 실패 10회→높음 AUTH-001 경보 1·정확한 근거 10개·홈/개인/조사 화면을 검증했다. 실제 journald/ISO 형식과 두 경로의 1ms 차이 중복을 보완하고 원본·정규화 두 경로를 보존했다. Windows 실제 4625 원본/정규화도 대조했으나 SSH 프로토콜 미확정으로 평가 제외를 유지한다. 기존 키/수집 설정·시작점/체크포인트·임계값/프로필·과거 문서를 보존했다. [결과·제한](archive/validation/live_auth_validation_20261012.md). 사건 저장·재시작과 상위 전체 인수는 후속이며 사용자 요청으로 완료된 코드·시험·기록을 Git 반영 대상으로 확정했다.

- [x] CI-08 완료(2026-10-12 코드·로컬·원격 CI): PR #8의 Windows/Ubuntu 자동 검사 실패를 재현·수정하고 같은 기능 브랜치에 반영했다. 두 OS 모두 감사 백업의 형식 2 고정 기대와 대시보드를 포함한 실제 형식 3의 불일치에서 실패했으며 현재/이전 형식의 감사 복원을 함께 검증했다. 수정 커밋 `6287688`의 원격 두 OS 전체 검사가 통과했다. 테스트/문서 범위이며 실제 배포·수신 검증과 구분한다.

- [x] CHART-01 완료(2026-10-12 코드·검증·커밋/푸시·지정 포털 배포, P5-05 일부): 24시간 집계 버킷이 일반 메타데이터 배열 제한으로 가려지는 문제를 고정 숫자/시각 차트 투영으로 해결한다. 개인정보 필터·API/조직 권한·5분 집계·응답/버킷 상한은 유지하고 정상 경보 0건은 0선/명시적 안내로 표시한다. 실제 경보·사건/분석 상태를 읽기 전용으로 대조하며 허위 경보/사건·새 프로필·과거 재처리를 만들지 않는다. 기존 구현/테마/문서·완료 이력을 보존해 검증 후 사용자 요청대로 커밋·푸시·보호 배포를 진행한다.

- [x] THEME-01 완료(2026-10-12 코드·로컬·지정 포털 배포): 밝게/어둡게 전환을 공통 헤더의 현재 화면 이름 옆 버튼으로 이동하고 메뉴 hover/active/focus 대비와 모든 업무 화면의 색상을 정리한다. 페이지 이동·새로고침·개인 구성 취소에서 전역 테마가 유지되도록 하며 기존 개인 구성/권한·검증 이력은 보존한다. 브라우저에는 허용된 테마 값만 저장하고 로그·비밀 값은 저장하지 않는다. 로컬 회귀·브라우저 검증 후 앞선 시험 포털 배포 요청 범위에서 보호 업데이트·실제 화면을 대조하며 커밋/푸시는 하지 않는다.

- [ ] DASH-01 진행 중: 홈·계정별 대시보드 코드/격리 시험 완료. 계정별 위젯·순서·너비·기간·테마, 저장 충돌·CSRF·역할/조직·재시작 검증은 [가이드](dashboards.md). 지정 VMware 관리자 배포·로그인/로그아웃·설정 재로그인/재시작·숫자/실수신 대조는 완료했습니다. 실제 일반 계정/추가 조직·역할 인수는 남습니다. 미측정 CPU/메모리·차단/안전 등급은 표시하지 않습니다.
- [ ] UX-02 진행 중: 고객 개선과 보호 배포/분석 복구의 기록은 보존합니다. 새 홈의 관리자 실제 데이터·설정/재시작·로그아웃 인수는 완료했습니다. 실제 위험 경보→조사→사건 저장과 운영 잔여 오류 인수가 남습니다. [전체 기존 기준](work_history_20261012.md#현재-실행-범위--2026-10-12-정리)
- [x] CLEAN-01 완료(2026-10-12 코드·로컬 화면·문서): 고객 메뉴/위젯·홈 경보 탐색·문서 보관·README·현재 목록 정리. 완료 기준은 메뉴/경보/기존 설정·권한·브라우저 회귀, 링크/상위 체크·완료/날짜 이력·개인 자료 보존 확인이며 실제 배포를 포함하지 않습니다.

## 상위 작업 체크

체크 상태와 완료 범위는 기존 목록을 그대로 유지했습니다. 각 ID의 상세 인수 기준·제한·검증 근거는 [이력의 P0~P7](work_history_20261012.md#p0-설치와-실제-수신-확인)을 따릅니다. 아래 요약은 기존 기준을 대체하지 않으며 P5-05의 고객 화면 변경은 위에 명시했습니다.

- [ ] P0-02 대표 Windows·Ubuntu 최신 패키지/동일 설치 복구·로그/네트워크 실제 수신 인수
- [x] P0-03 양 OS 실제 문서 ES → API → 브라우저 대조(지정 VMware 범위)
- [x] P1-01 조회 필드·시각·권한 계약
- [x] P1-02 인증된 로그 검색·상세 API
- [x] P1-03 통합 로그 실제 API 화면
- [x] P1-04 실제 검색·상세·보호 원문 필드 통합 검증
- [x] P2-01 마스킹·조직/역할·보호 원문·감사 정책(지정 VMware 범위)
- [ ] P2-02 보류: 독립 저장소·보존/삭제·운영 백업/격리 복원
- [ ] P2-03 수집 상태 보고·오류/큐 계측의 운영 인수
- [ ] P3-01 Windows/Linux 인증·SSH/PAM 필수 필드 실제 대조
- [ ] P4-01 AWS CloudTrail 실제 권한·계정/리전·서비스·수신 인수
- [x] P4-02 CloudTrail 로그 조회 연결(격리 검증)
- [x] P4-05 OCI Audit 로그 조회 연결(격리 검증)
- [ ] P5-01 정규화·원본 참조·불변 저장·지연/재시작/중복 인수
- [ ] P5-02 최소 권한 처리/탐지 서비스·상태·복구 인수
- [ ] P5-03 AUTH/선택 ATTACK 규칙 정상·경계·조건 충족 실제 인수
- [x] P5-04 경보·정확한 근거 조회(격리 검증)
- [ ] P5-05 홈 경보·수신 추이·사건 요약 실제 조회 인수
- [x] P6-01 사건/경보 연결·SQLite 업무 API(코드/격리)
- [ ] P6-02 실제 경보 이유·정확한 근거·조직 권한 조사 인수
- [x] P6-03 메모·판정·변경 이력 영속 저장(코드/격리)
- [ ] P6-04 실제 사건 큐·필터/집계·경보→사건 저장 인수
- [ ] P7-01 수집→탐지→조사→저장과 중단/재시작 전체 통합 검증
- [ ] P7-02 운영·설치/갱신·복구·만료 대응·시연 문서 최종 인수

## 보류·범위 밖

**P2-02는 사용자 보류를 유지합니다.** 독립 저장소 준비·운영 보존/삭제 승인·실제 백업/격리 복원을 완료로 표시하지 않습니다. 기본 보호 백업은 계속 필요합니다.

전체 비마스킹 원문/내보내기, 과거 ES 삭제·일괄 재처리, 새 공격 프로필 자동 활성화, 유료 자원·새 센서·범용 자동 업그레이드는 이번 정리에서 수행하지 않습니다. 앞서 제외한 확장/중복 항목 22개 원문·사유는 [후속 기록](deferred_work_20261012.md)에 유지합니다.

## 작업 규칙

기능 브랜치에서 현재 Git 상태를 먼저 확인하고 사용자 변경을 보존합니다. 코드 구현·단위/격리 시험·실제 배포·실제 수신을 구분합니다. 기존 날짜·완료/검증 기록은 수정하지 않으며 비밀번호·키·실제 민감 로그를 기록하지 않습니다. **커밋·푸시·배포는 별도 요청 시 진행합니다.**

## 이번 작업 기록

2026-10-12 DASH-01·UX-02·P5-05 보호 배포 진행 중(사용자 요청): Ubuntu 시험 포털 192.168.235.128에 최신 홈/개인 대시보드·메뉴 정리를 반영하고 실제 로그인 방식/로그아웃 버튼 차이를 진단한다. 실서버는 Basic 인증·세션 계정 파일 미설정·기존 정책 일반 계정 0개를 확인했고 기존 admin 해시를 재사용해 세션 로그인/로그아웃을 적용한다. 개인 설정 DB 포함 백업 format 3과 기존 format 1/2 호환을 보완해 관련 37건을 검증했다. 기존 관리자 비밀번호·계정/조직 권한·키/큐/처리 시작점·체크포인트·완료 이력을 보존하며 포털 DB/설정/이전 이미지를 보호한 후 포털만 적용한다. 로그인과 실제 데이터/개인 설정/재시작·로그아웃 인수는 별도로 기록하고 P2-02 보류·새 공격 프로필 미활성화·커밋/푸시 미요청은 유지한다.

2026-10-12 CLEAN-01: 기능 브랜치 `codex/protected-deployment-20261012`와 기존 미커밋 변경을 확인했습니다. 고객 메뉴를 7개(보안 관제 4·에이전트 3)로 줄이고 기술 위젯을 제외했습니다. 홈 경보는 최신 8건/펼친 최대 50건과 정확한 근거 진입을 유지하며 사건 수는 실제 미종결 쿼리 집계를 사용합니다. 기본 위젯은 6개, 과거 기술 위젯 설정은 읽기/취소 호환을 유지하고 명시적 저장 때만 현재 선택을 반영합니다.

README·문서 색인·현재 작업 목록을 갱신했습니다. 과거 설계/중복 안내 12개와 날짜별 검증/개선 11개는 보관 폴더로 옮기고 상대 링크를 보정했습니다. 정리 전 전체 작업 기록과 README, 완료 11/24·사용자 보류·개인 DOCX/포트폴리오 자료를 보존했습니다. 이번 요청에서는 VM 접속·배포·키/큐/ES 변경·커밋·푸시를 하지 않습니다.

검증: 관련 Python 58 passed·7 subtests·기존 Windows Restricted 설치기 2 deselected, 전체 화면 회귀 최종 123 passed, Ruff/diff 통과. 합성 Chrome 18개 검사(기존 두 화면/두 크기/두 테마·저장/충돌·장애/빈 결과·조회자 격리 14, 옛 설정/취소 보존·기술 위젯만 있는 설정 복구/독립 경고·8→50건/35건 실제 쿼리 집계/홈 복귀·개인 화면 복귀 4)에서 JS 예외 0. 상대 문서 링크 최종 509개에 파일·앵커 누락 0. 보관된 추적 문서 21개는 기존 HEAD와 링크 대상을 제외한 본문이 일치하며 정리 직전 전체 작업 이력·상위 24개 체크 순서/상태와 개인/포트폴리오 12개 파일을 대조했다. Windows 텍스트 줄바꿈 차이와 새 홈 앵커의 옛 회귀 기대를 구분·보정했다.

근거 파일: `prototype/shell.js`, `dashboard.js`/HTML/CSS, `investigation.js`, `portal/app.py`·`dashboards.py`, 관련 회귀 테스트, [README](../README.md)·[문서 색인](README.md)·[정리 검증](archive/validation/customer_cleanup_20261012.md). 브라우저/링크/보존 대조 자료는 Git 제외 `state/cleanup-20261012`에 있다. CLEAN-01은 요청한 로컬 정리만 완료이며 DASH-01·UX-02·P5-05의 신규 실제 배포/통합 인수는 미완료로 유지한다.

## 2026-10-12 새 대시보드·로그아웃 실제 보호 배포

사용자 요청에 따라 지정 Ubuntu 192.168.235.128의 포털만 21:28 KST에 새 이미지 `e821ca36…`로 교체했다. 기존 기본 인증과 세션 검증 화면의 차이로 로그아웃이 보이지 않았으며, 실제 정책의 일반 계정 0개를 확인하고 기존 admin 비밀번호 해시를 그대로 사용한 세션 로그인으로 전환했다. 계정/조직 정책·원문 보호·키/큐·시작점/체크포인트·분석 프로필은 변경하지 않았다. 다른 여섯 컨테이너의 이미지/ID/시작 시각은 준비 전부터 최종까지 동일했다. 기존 전체 작업 기록과 완료 상태 11/24·P2-02 보류를 유지했다.

소스 249개/manifest·오프라인 의존성을 검증하고 DB·CA/비밀 설정/기존 활성 구성·이전 포털 이미지를 0700 보호 경로에 백업했다. 개인 설정 DB의 format 3 지원 및 구형 format 1/2 호환·권한 관련 Python 37건을 통과했다. 실제 format 3의 백업/verify/격리 restore와 최종 원래 화면 구성 revision 2 대조를 완료했다. 패키지 12·키 이력 22·등록 15·감사 34의 기존 행/BLOB을 보존했고 실제 사건은 0건이었다. 같은 VM 디스크 보호이며 독립 백업/보존 정책 완료가 아니다.

CA·주소 검증 HTTPS를 거치는 루프백 중계/Chrome으로 실제 사용자 비밀번호 입력·Secure/HttpOnly/SameSite=Strict 쿠키·로그아웃 버튼·로그아웃 후 옛 토큰 401·재로그인을 검증했다. 두 대시보드×1440/390px×두 테마에서 API 수신/경보/미종결 사건 집계와 일치하고 JS 예외 0·가로 넘침 없음. 실제 개인 설정 저장·새로고침/재로그인·포털 단독 재시작 후 유지와 기존 표시 설정 복원을 확인했다. 조회 시점 수신 로그는 424,265~424,346건, 경보/사건은 0건, coverage는 제외 기록에 따른 warning이었다. 실제 경보가 없어서 경보 생성/근거→사건 저장을 완료로 간주하지 않는다.

배포 후 네 수집기의 새 문서 1건씩을 ES→보호 상세 API의 index/ID·조직·agent ID·서버 수신 시각으로 대조했다. 약 21:34 KST 표본까지 새 수신은 Ubuntu 네트워크 1,610·Windows 네트워크 2,078·Ubuntu 로그 72·Windows 로그 9건이었다. 실제 수집기·키·큐는 변경하지 않았으며 수신은 위험 탐지 성공이나 전수 무손실을 뜻하지 않는다. API의 마이크로초 시각 계약과 ES 나노초 차이를 구분했다.

초기 이미지 ID 옮김 오타는 적용 전 일치 검사에서 중단 후 실제 기록값으로 수정했다. 첫 브라우저 검사에서 별도 API 클라이언트의 HTTP Secure 쿠키 처리 차이와 ES/API 시각 정밀도 기대를 보정한 뒤 실제 브라우저 재검증을 통과했다. 실패 기록은 보존했다. Ruff/diff 통과, 커밋·푸시 미수행. [배포 보고서](archive/validation/dashboard_deployment_20261012.md), Git 제외 `state/cleanup-20261012/live-browser` 및 서버 `state/deployment-20261012-4973e31/dashboard-release-20261012`에 근거/백업/활성 Compose를 보존한다. 브라우저·실제 수신·DB 복원 각 단계를 구분하며 DASH-01/UX-02/P5-05는 잔여 실제 조직·위험 시나리오·사건 인수 때문에 미체크를 유지한다.

## 2026-10-12 공통 테마·대비 실제 배포

사용자 요청으로 홈의 화면 드롭다운을 제거하고 모든 업무 화면의 현재 이름 옆에 다크/화이트 전환 버튼을 추가했다. `theme.js`의 검증된 전역 테마와 `theme.css` 공통 팔레트로 홈→개인→로그→사건 이동/새로고침, 메뉴 일반/선택/hover/키보드 focus, 필터/표/상세/폼 대비를 보완했다. 기존 서버 개인 구성의 테마는 명시적 전역 선택이 없을 때만 받아들이며 편집 취소로 전역 선택을 되돌리지 않는다. 브라우저에는 허용된 테마 두 값만 저장하고 로그·비밀 값·위젯 구성을 복제하지 않는다.

검증: 전체 UI 127 passed, 관련 Python 52 passed/2 기존 Restricted 설치기 deselected/4 subtests·새 공개 테마 자산 보안 재검사 1 passed·Ruff/diff 통과. 합성 Chrome 42개(10화면×두 크기×두 테마 40, 로그/사건 상세 1, 개인 편집 취소 1)에서 최종 JS 예외 0. 처음 숨긴 생성 패널을 기다린 시험 선택자 오류를 실제 조사 패널로 보정 후 재검증했다.

기존 DB·설정/CA/계정 해시·활성 Compose·이전 이미지를 보호 백업하고 새 소스 252개/manifest·오프라인 의존성을 검증해 21:58 KST에 포털 이미지 `6ec0adbf…`만 교체했다. 실제 HTTPS CA·주소 검증 중계/Chrome 18개(홈/개인/로그/사건×두 크기×두 테마 16, 실제 로그 상세 1, 개인 취소 1)에서 전역 테마/메뉴 hover·focus 대비 4.5 이상·화면 가로 넘침 없음·로그아웃·JS 예외 0을 확인했다. 최종 개인 구성 1행·패키지 12·키 이력 22·등록 15·원문 감사 34 및 사건 테이블의 모든 행이 배포 전과 일치했고 format 3의 실제 최종 백업/격리 복원을 통과했다. 다른 여섯 컨테이너 ID/이미지/시작 시각과 관리자 비밀번호/세션 설정·키/큐·분석 프로필은 유지했다. 같은 VM 보호이며 독립 백업 완료가 아니다.

부수 발견(P5-05 잔여): 실제 기본 24시간 추이 차트가 확인 불가로 표시된다. `api_call`의 메타데이터 배열 제한(256)과 5분 버킷의 24시간 배열(약 289개) 계약 차이를 소스에서 확인했다. 이번 테마 코드가 숫자·권한 검사를 완화하거나 가짜 차트로 대체하지 않았다. 현재 요청의 테마 인수와 별개로 고정 집계 범위/응답 정책을 보존하는 차트 보완·실제 응답 인수가 남는다. 실제 사건은 0건이어서 사건 상세의 색상은 합성 범위, 실제 서버는 목록/직접 진입과 로그 상세 범위를 검증했다.

근거: `prototype/theme.js`·`theme.css`·`shell.js`, 대시보드 HTML/JS/CSS·각 페이지 공통 자산, `portal/app.py`, 회귀 시험, [테마 보고서](archive/validation/theme_validation_20261012.md). Git 제외 `state/cleanup-20261012/theme-browser`·`theme-live-browser`와 서버 `state/deployment-20261012-4973e31/theme-release-20261012`에 검증/보호/활성 Compose를 보존한다. 코드/격리/배포/실수신 단계를 구분하며 이번 작업의 새로운 실제 수신 검증이나 공격 시나리오를 주장하지 않는다. 기존 상위 완료 11/24·P2-02 보류·미커밋 변경·날짜/완료 이력은 유지하고 커밋/푸시하지 않았다.

## 2026-10-12 CHART-01 코드·커밋 준비

일반 메타데이터 배열 상한은 유지하고 `display_summary`에서 고정 4종 차트의 최대 1,000개 버킷에 숫자 count·유효 UTC time만 별도로 투영한다. 모든 나머지 필드/경보 메타데이터는 기존 개인정보 필터를 통과하며 추가 버킷 필드는 공개하지 않는다. 5분 집계·기간/조직·전체 수·응답 상한은 유지했다. 0건이면서 실제 집계 구간이 있는 경보 추이는 0선/최대 0건으로 표시하고 경보·사건의 실제 0건 안내를 명확히 했다.

관련 Python 144 passed·16 subtests·기존 Restricted 설치기 2 deselected, UI 127 passed·Ruff 전체 src/tests/tools·diff 통과. 실제 인증 API 경로의 289개 버킷/개인정보·원본 불변, 일반 배열 차단 유지·1,000개 상한·잘못된 숫자/시각 fail-closed·0건 인수를 검증했다. 합성 Chrome 8개(두 대시보드×두 크기×두 테마)의 긴 추이/0선·가로 넘침·JS 예외 0을 확인했다. 실제 서버 읽기에서 ES 전체 경보 0·사건 0·최신 AUTH-001 평가 입력 246/새 경보 0을 확인했으며 새 공격 프로필·허위 경보/사건·과거 재처리를 수행하지 않았다.

사용자 요청대로 이전 보호 복구·홈/개인 대시보드·로그아웃/전역 테마·문서 보관 변경과 이번 차트 보완을 기능 브랜치에서 함께 커밋·푸시한다. origin/main을 fetch해 HEAD와 동일 기준 4973e31을 확인했고 개인 DOCX/포트폴리오·기존 검증/완료 상태를 보존했다. 실행 상태·비밀 파일은 Git 제외한다. 실제 차트 수정 배포/인수는 다음 단계로 기록하고 CHART-01은 현재 미체크 유지한다.

2026-10-12 커밋·푸시: `51187aa`로 이전 미커밋 제품/문서 변경과 CHART-01 코드를 origin 기능 브랜치에 반영했다. 신규 파일 두 개의 EOF 빈 줄을 캐시 diff 검사에서 발견해 동작 변화 없는 형식 보완을 추가한다. 커밋된 Git 바이트로 배포 소스를 묶어 실행 상태/비밀 파일 제외와 파일 해시 일치를 검증한다. 실제 배포·차트 인수는 아직 다음 단계다.

## 2026-10-12 CHART-01 실제 인수·배포 완료

`51187aa` 제품/문서 개선 및 `37f9587` 파일 형식/배포 기록을 기능 브랜치에 커밋·푸시한 뒤 커밋 `37f9587317e18668f168ec970b033bf3d57787da`의 Git 바이트 252개/manifest로 이미지 `2ddb2204…`를 빌드했다. 기존 DB/CA·세션 계정/개인 구성·활성 Compose·이전 이미지를 보호 백업·격리 복원하고 22:21 KST에 지정 Ubuntu 포털만 교체했다. 준비/최종에서 다른 여섯 컨테이너의 ID/이미지/시작 시각과 관리자 비밀번호·개인 구성/기존 포털 행은 동일했다. 수집기·키·큐·분석 프로필·시작점/체크포인트는 변경하지 않았다. 최종 format 3 백업/verify/격리 restore 통과, 같은 VM 보호이며 P2-02 독립 백업 완료가 아니다.

실제 HTTPS 인증서/주소 검증 중계·Chrome 10개에서 두 화면×1440/390px×밝게/어둡게 8 및 1시간/7일 2를 인수했다. 24시간 289개 버킷/수신 447,074~447,345건, 1시간 13개/7일 169개 버킷이 유효하며 API 합계와 그래프가 일치했다. 실제 경보 0건의 전 구간 0선·최대 구간 0건을 확인했고 개인 설정은 바뀌지 않았다. JS 예외 0·가로 넘침 없음·로그아웃 통과. 경보·사건 자체 0건과 최신 AUTH-001 평가 입력 246/새 경보 0은 별도 ES/DB 읽기로 대조했다. 제외 기록에 따른 coverage warning은 유지하고 안전 판정으로 바꾸지 않았다.

배포 이후 22:26 KST까지 새 수신은 Ubuntu 네트워크 1,510·Windows 네트워크 1,870·Ubuntu 로그 60·Windows 로그 64건이며 각각 최신 실제 참조/시각을 읽었다. 수신을 공격 탐지나 전수 무손실로 간주하지 않는다. 앞선 실제 수신 이력과 이번 포털/그래프 인수를 분리한다.

관련 Python 144/16 subtests·기존 Restricted 2 제외, 추가 포트폴리오/화면/증분 탐지 회귀 20 passed, UI 127·합성 Chrome 8·전체 Ruff·문서 링크·최종 diff 검사 통과. 추가 회귀의 첫 잘못된 파일명은 시험 실행 전 중단 후 실제 파일로 보정했다. 비밀번호는 메모리 입력으로만 사용하고 커밋 대상 106개에서 실제 비밀번호와 실행 상태가 없음을 검사했다. 브랜치의 원격 자동 CI는 main/JEONGRIM-SEO/integration와 PR 트리거여서 이번 기능 브랜치 푸시의 CI 통과를 주장하지 않는다.

이전 24시간 차트 확인 불가 기록은 보존하며 해당 버그는 이번 인수로 해결했다. 실제 양성 경보→근거→사건 저장/조직·역할·SSH/PAM 시나리오와 제외 1건 검토는 P3/P5/P6/P7의 잔여여서 상위 완료 11/24를 그대로 유지한다. 완료 근거는 [차트 보고서](archive/validation/chart_validation_20261012.md), Git 제외 `state/cleanup-20261012/chart-live-browser`·서버 `state/deployment-20261012-4973e31/chart-release-20261012`의 manifest/백업/활성 명령·실수신/최종 보호 자료다.

## 2026-10-12 CI-08 PR 자동 검사 복구

사용자 요청으로 [PR #8](https://github.com/Gandalem/cloud-soc/pull/8)의 자동 검사 복구를 우선한다. 커밋 `a48d425`의 Windows 275 passed/Ubuntu 683 passed 검사에서 동일한 감사 백업 형식 기대 테스트 하나가 실패했다. 로컬에서도 수정 전 실패를 재현했다. 개인 대시보드 DB가 있는 백업은 이미 형식 3을 쓰므로 테스트를 현재 형식 3 및 대시보드 이전 형식 2의 두 실제 백업/verify/격리 restore로 보완했다. 두 형식 모두 보호 원문 조회 감사의 `granted` 행이 복원되고, 대시보드 DB 포함 여부가 맞는지 확인한다. 기존 형식 지원·제품 코드·CI 검사 강도·배포 상태는 변경하지 않는다.

로컬 검증: `tests/test_source_access.py`·`test_portal_backup.py`·`test_dashboards.py` 46 passed/2 subtests, 전체 src/tests/tools Ruff 및 diff 통과. 원격 기능 브랜치와 일치한 상태에서 테스트/현재 작업 기록만 커밋·푸시하며 새 커밋의 두 OS 자동 검사는 별도로 확인한다. 실제 배포·새 에이전트 수신 검증을 수행한 것으로 기록하지 않으며 상위 11/24 및 P2-02 보류를 유지한다.

원격 결과: 수정 커밋 `628768832bc407ed40eb3a80de38ab161a4289a6`의 [자동 검사 38257240344](https://github.com/Gandalem/cloud-soc/actions/runs/38257240344)에서 Windows·Ubuntu 작업 모두 success를 확인했다. Ubuntu 전체 Python 684 passed/18 skipped/254 subtests, UI 127 passed, Bandit·의존성 취약점·Compose/실제 이미지 빌드와 격리 게이트웨이 4 passed/18 subtests까지 통과했다. Windows의 Python·PowerShell/오프라인 에이전트·UI 단계도 포함한 전체 작업이 통과했다. 별도 배포나 실제 위험 탐지 인수를 추가로 주장하지 않는다.


## 2026-10-12 LIVE-AUTH-01 실제 위험 탐지 인수

사용자 요청으로 P3/P5 실제 시연을 실행했다. 최신 main `93e0422`의 이전 PR 병합을 확인하고 동일 소스 트리에서 `codex/live-auth-validation-20261012`로 기존 우선순위 기록을 보존했다. VM SSH 지문·두 OS 수집 서비스·네 수집 키 및 두 처리 키의 실제 ES 미폐기/미만료·새 수신/분석 진행을 확인했다. 기존 AUTH-001 조건/10건·300초/900초 유예를 유지한 실제 SSH 인증 성공·실패를 발생시켰다.

첫 실패 9회의 원본 18개/PAM 18개는 기존 파서가 실제 journald 본문/ISO auth.log를 지원하지 않아 SSH 실패로 해석되지 않았다. `linux_ssh_v2`, journald 프로세스/PID 읽기, 고정 수신 적용 시작점 및 두 수집 경로 중복 보완을 구현했다. 새 형식 시작 시각은 `2026-10-12T14:24:26.354369+00:00`으로 SQLite에 고정했고 기존 시작점/체크포인트를 유지했다. 초기 미지원 시험을 재해석하지 않은 것을 확인했다. 첫 시각 일치 비교의 실제 1ms 차이는 추가 대조에서 발견해 유예 종료 전 탐지기만 중지·상태 보존했다. 동일 호스트/프로세스/접속/사용자/행위/인증 방식·서로 다른 수집 경로·5ms 이내를 함께 검사하는 수정으로 실제 10쌍/9쌍을 후보에서 네트워크 없이 검증하고 재개했다. 재개 전 경보 0건을 확인했고 잘못된 경보 삭제·문서 덮어쓰기·상태 초기화를 하지 않았다.

최종 전체 Python 698 passed/15 조건부 skipped/기존 Restricted 설치기 2 deselected/256 subtests. 시각 차이 변경 후 관련 123 passed/16 subtests, Ruff/diff 통과. 최초 코드 편집 도구의 Windows 기본 인코딩 오류는 해당 파일을 수정하기 전에 중단돼 UTF-8로 보정했다. 준비 도구의 /data 마운트·로컬 이미지 참조·호스트 Python 의존성 및 브라우저 기간 인자 차이는 실제 계약으로 보정하고 초기 실패 기록을 보존했다. 두 경로 시각 차이를 반영한 후 의미 있는 최종 전체 회귀를 재실행했다. 새 패치 원격 CI는 미실행이며 앞선 PR #8 성공과 구분한다.

23:24 KST에 정규화/탐지 형식 지원 후보, 23:44 KST에 탐지기 시각 차이 보완을 보호 적용했다. 기존 포털 DB format 3 백업/verify/격리 restore, 처리 DB·키/CA/설정과 두 이전 이미지를 보호했다. 실제 실패 9회는 두 경로 18개·고유 9회·최종 경보 0, 별도 IP의 실패 10회는 두 경로 20개·고유 10회·높음 AUTH-001 경보 1이었다. 판정 frontier가 두 시험 종료를 지난 상태에서 양성/음성을 확인했고 경보 근거 10개가 고유 관측 집합과 정확히 일치했다. 관리자 API의 모든 근거가 exact_reference/normalized_hash_verified였고 홈·개인×두 테마 및 조사 상세·개인 설정 불변·로그아웃 401·JS 예외 0을 확인했다. 실제 Windows 시험 인증의 4625 1건도 원본 record ID/조직/시각/참조·실패 정규화와 대조했다. SSH 프로토콜 미확정으로 평가 제외한 기존 1건/시험 1건을 그대로 유지한다.

23:48 KST 최종에서 기존 패키지 12·키 이력 22·등록 15·감사 34·개인 구성 1·사건 모든 행은 동일했고 Linux 수집 설정/keystore와 실제 시험 원본 38개 해시를 보존했다. 다른 다섯 컨테이너의 ID/이미지/시작 시각은 동일하며 최종 백업/격리 복원·처리 무결성 통과. 적용 이후 네 수집기의 새 수신은 Linux 로그 731/네트워크 3,206·Windows 로그 281/네트워크 4,464였다. 같은 VM 보호이고 독립 복구/보존 P2-02는 계속 보류다.

근거: `parsers/linux_security.py`, `processing/contract.py`·`worker.py`·`__main__.py`, `detection/engine.py`, `tests/test_linux_ssh_live_formats.py`, [실제 인증 보고서](archive/validation/live_auth_validation_20261012.md). 최신 활성 처리 구성은 서버 `state/live-auth-20261012/drift/compose.active.json`이며 normalizer `7e77b84a…`/detector `09164ed5…`의 미커밋 공개 패치다. 로컬 `state/live-auth-20261012`에 관리자 화면 증거·검증 도구를 Git 제외로 보존한다. 원문/비밀번호/키는 작업 목록에 기록하지 않는다. 이번 작은 시연 완료를 상위 P3/P5 전체 완료로 바꾸지 않고 11/24를 유지한다. 범용 PAM·선택 ATTACK/AWS·추가 조직/역할·사건 저장/재시작 인수는 남는다. 현재 요청에서는 새 패치 커밋·푸시를 하지 않는다.

화면 시각 문구 잔여(P5-05): 경보의 실제 `@timestamp`는 `window_end`이며 유예 후 저장/확인 시각과 다르다. 현재 홈 하단의 “경보는 저장 시각 기준” 문구는 이 계약과 맞지 않아 후속 고객 시각 설명에서 보완해야 한다. 이번 경보 시각 23:28:41과 실제 화면 확인 23:44를 혼동하지 않는다. 시연 검증/보고서에는 해당 구분을 적용했고 전체 고객 화면 인수를 완료 처리하지 않는다.

## 2026-10-12 LIVE-AUTH-01 Git 반영 요청

사용자가 완료된 작업의 커밋·푸시를 요청했다. 원격 main `93e0422`와 미생성 원격 기능 브랜치를 확인했고 `codex/live-auth-validation-20261012`에서 완료된 소스 5개·회귀 시험 1개·운영/검증/작업 기록 5개를 반영한다. 앞선 배포 보고서의 “미커밋”은 당시 상태로 보존한다. 비밀·원문·실행 상태·브라우저 캡처·개인 자료는 커밋 대상에서 제외하고 검증된 코드·staged diff·비밀 포함 여부를 확인한다. 새 코드 변경 없이 이미 확인한 698 passed/256 subtests와 실제 수신·브라우저 결과를 사용하며 원격 CI·추가 배포·병합을 별도 완료로 추정하지 않는다. 상위 11/24·P2-02 보류와 다음 P6/P7 사건 시연 우선순위는 유지한다.

## 2026-10-13 수집 범위 설명·DVWA 시험 대상 구분

사용자는 AWS 연결을 진행했다고 알렸고 DVWA는 임시 테스트 대상이라고 명시했다. 현재 저장소의 AWS 수집기는 CloudTrail LookupEvents 관리 이벤트 범위이며 EC2 내부 OS/웹/앱 로그와 별도다. Windows는 활성 지원 이벤트 채널/허용 로그 경로, Ubuntu는 journald/허용 텍스트 로그 경로를 수집하며 모든 파일·비활성 감사·네트워크 본문을 수집하는 기능이 아니다. 웹 접근 파서는 선별 메타데이터를 해석하지만 웹 공격 전체 탐지 완료를 뜻하지 않는다. 수신·필드 해석·위험 경보 생성을 구분해 설명한다.

이번에는 소스/문서만 대조했으며 사용자가 새로 연결한 AWS의 실제 계정/리전/수집기나 DVWA 실행 위치·로그 경로·Docker 마운트·새 수신은 확인하지 않았다. 연결 성공만으로 P4-01 또는 실제 웹 로그 인수를 완료 처리하지 않는다. DVWA 자체를 제품의 필수 기능으로 확장하지 않으며 수집이 적은 원인은 P0-02/P2-03의 실제 소스 선택·로그 생성·읽기 권한·중앙 수신과 P5의 해석/탐지를 단계별로 대조해야 한다. 사용자 확인 없이 새 AWS 데이터 이벤트/감사 정책·비용·공격 프로필을 활성화하지 않는다. 발표 핵심 범위·기존 11/24·보류/검증 이력은 유지하며 이번 설명에서는 코드·배포·수집 설정을 변경하지 않았다.


2026-10-14 SITE-CLEAN-01 결과: Ubuntu의 다운로드 캐시·사용하지 않는 빌드 캐시, 구버전 백업/복원 사본24개·미사용 Cloud SOC 이미지17개·ES snapshot2개를 사용자 추가 삭제 지시에 따라 정리했다. 최신 SQLite8개(개별 integrity ok)/현재 설정과 새 SUCCESS snapshot `unified-site-20261014` 하나를 남겼다. 여유는 최초2,271,354,880→마지막4,631,547,904 bytes(약2.1→4.3GiB). 처음 최신 ES snapshot은 당일 Windows 인덱스2개의 미할당 primary 때문에 실패했으나 공간 확보 후 SUCCESS·미할당 primary0을 확인했다. ES replica yellow는 남는다. 운영 데이터/마운트·키·큐·모든 기존 컨테이너 ID/실행 이미지·서비스 실행 상태를 유지하고 재시작하지 않았다. 과거 보고서의 이전 backup/rollback 경로는 당시 검증 이력이며 현재 복구 경로로 사용하지 않는다. 현재 최신본은 서버 state/unified-site-20261014/latest-backup과 기존 snapshot repository의 새 snapshot이다. 공개 정리 결과/실패·후속 근거는 Git 제외 state/unified-site-20261014 및 state/protected-deployment-20261012/unified-*.json에 보존했다.

2026-10-14 SITE-AGENT-01 코드/격리 진행: 선택형 시스템·웹·Packetbeat 패키지·사이트 이름/종류/파일/고정 시작 시각·디렉터리 중복 제외·전송 전 웹 허용 목록·신규 정규화/정확 참조·웹 전용 권한 검색·선택 상태/웹 위젯을 구현했다. 설치 원본은 불변으로 유지하며 개별 선택 값은 별도 switch 파일에서 동적 재읽기한다. 신규 Ubuntu/Amazon Linux 2023/Windows 경로와 기존 패키지 계약을 대조했다. 전체 Python882 passed/15 skipped/257 subtests, 후속 관련124 passed/67 subtests, UI/Windows native/웹157 passed, 설치/네트워크/기존 privacy72 passed/1 skipped와 Ruff/diff 확인. 전체 검사 뒤 추가 switch/64바이트 설정·OS별 실제 시험과 신규 코드의 배포는 별도 인수로 남기며 문서는 unified_site_agent.md다.

2026-10-14 SITE-LIVE-01 실제 AWS 진행: 사용자 확정한 AWS56.155.117.55의 amzn/2023·기존 DVWA/producer를 확인하고 정상 GET200에서 새 실제 Apache2건을 발생시켰다. 기존 출발지 제한/고정 지문/목적 SSH pull을 유지해 중앙 soc-host-raw-web-dvwa-v1→실제 정규화2건의 정확 index/ID/불변 참조를 대조했다. producer/DVWA/relay 재시작·원본/SQLite/키 변경·공개 포트/IAM/새 자원·Windows 키 검사는 없었다. 신규 범용 Filebeat 배포·AWS 시스템/네트워크 및 실제 신규 브라우저 인수·커밋/push/원격 CI는 아직 확인 전이며 기존 DVWA 수신 성공으로 대신하지 않는다.

2026-10-14 후속 격리: 별도 switch/고정 경로 설정 후 관련124 Python/67 subtests·추가16 사이트 검사·Windows 실제 native6/UI145/웹6(총157), 문서 링크575와 Ruff/diff를 확인했다. 실제 Filebeat 격리의 초기 지연/시험 전송 파일 kopo 소유권 차단을 기록하고 설치와 같은 root 소유권·독립 시험 registry·정확 script config 경로로 보정했다. 운영 registry/큐를 지우거나 파일 소유권 검사를 완화하지 않았다.

2026-10-14 추가 검증/보완: 실제 Filebeat9.5.2 독립 실행의1건·native access 시각·민감 canary 부재·운영 서비스 불변을 확인했다(콘솔 시험, 중앙 게시 아님). 실제 monitor 최소 읽기 권한으로 신규 항목 상태6개 표본/부족한 이전 web 보고 unknown을 확인했다. 8ba91d8 일반 push·수동 CI38430324552의 Windows/Ubuntu 모두 success. 마지막 검토에서 웹 미선택/중지에도 일반 탐색 또는 journald 중복으로 access 원문이 전송될 수 있는 우회를 보완했다. 기본 웹 디렉터리 제외와 표준/Docker access 줄 차단의 관련59 Python·14 JS 회귀를 통과했으며 기존 SSH/DVWA 경로를 유지한다. 최초 후보 이미지는 아직 적용하지 않았고 후속 보완의 새 후보/CI를 준비한다.

2026-10-14 실제 배포 진행: a8e8c0a/290공개파일·이미지 a29ab108…를 검증해 포털/정규화기만 보호 적용했다. SQLite8개 최신본을 갱신하고 원래명령/체크포인트·키/CA/수집기ID/설정·다른5서비스/대시보드행을 대조해 보존했다. 이후 정상 GET의 실제 Apache2건도 새 코드 정규화 정확참조로 확인했다. 실제 브라우저24시간 조회에서 runtime source 필터의 대량 문서 평가가4초제한을 넘는503을 발견했다. 범위/제한을 늘리거나 부분결과를 성공으로 바꾸지 않고 고정 keyword 검색 및 매핑검사를 추가해41 Python/14 subtests로 회귀했다. 이 마지막 검색 보완의 실제 재적용·브라우저·최종CI는 진행 중이다.

2026-10-14 검색 실환경 보완: 기존 동적 labels.log_source는 text+keyword, DVWA는 keyword임을 확인했다. 고정 매핑 변경 없이 두 검색 필드로 후보를 먼저 좁히고 원본 소스 값의 정확 일치를 확인한다. 실제19 shard/24시간/웹11건 조회0.028초·부분응답없음과34 Python/14 subtests를 통과했다. cf27fa6의 keyword 전용 검사 가정은 후속 호환 보완으로 대체하며 그 중간 후보를 실제 적용하지 않았다.

2026-10-14 최종 기록: 코드009de94 일반push·CI38437154683 Windows/Ubuntu success. 실제 포털 조회11건/신규Apache4건 상세·신규패키지1개 SHA/멤버15·PC/모바일/두테마/JS0/넘침0/로그아웃401·개인구성 불변·실자료2위젯 미리보기를 대조했다. 마지막 검색 보완은 포털만 보호 적용해 정규화/탐지/기존수집기를 추가 재시작하지 않았다. 최신SQLite8개/설정·SUCCESS snapshot unified-site-final-20261014 하나로 갱신하고 중간 snapshot/미사용 후보/임시전송·격리파일을 정리했다. 여유4,496,531,456 bytes/primary미할당0·replica yellow. [최종 결과·활성 명령·보호 경로·실수신/격리 구분](unified_site_validation_20261014.md). SITE-AGENT-01/SITE-LIVE-01은 신규3OS전체설치/개별스위치실수신/AWS시스템·네트워크사설경로 인수가 남아 unchecked로 유지한다. 실제웹수신과신규코드 검증을 전체 통합 설치 완료로 표시하지 않는다.

2026-10-14 DUAL-LIVE-WIN-20261014·DUAL-RETRO-20261014 재개(사용자 요청): C 드라이브 공간 부족으로 중단했던 미커밋 변경과 기존 개인 파일을 보존해 검증·일반 push·중앙 Ubuntu 보호 배포를 재개한다. 지정 VM SSH와 cloud-soc-web-relay.service active를 확인했다. 기존 Windows 실제 9회 경보0/10회 경보1은 확인 완료이며 재시작 후 경보·정확 근거 불변 검증이 남는다. 늦은 웹 로그의 실제 수신/별도 회고 평가 및 최종 전체 검사·CI·배포는 진행 중으로 유지한다. AWS 감사 API 자격 증명 미확보와 OCI 제외는 기존 한계로 유지하며 미검증 룰을 운영 활성화하지 않는다.

2026-10-14 DUAL-RETRO-20261014 코드/격리 완료·실환경 적용 준비: src/cloud_soc/detection/retrospective.py의 별도 수신 spool/영속 review job·완전한 조직/그룹 근거 조회·event-time 쿨다운 ledger·create-only 동일 경보ID·재시작/실패 재시도·기존 실시간DB 거부를 구현했다. 대시보드/API는 과거 재평가 표시와 실시간/과거 적체/늦은 평가 상태를 분리하고 발생 구간 시각 안내를 보정한다. 실제 20건/15종 종료flow 근거 gate를 확보한 WEB-404-001·NET-PORT-001을 명시 선택 가능하게 하며 기본 AUTH와 기존 초기통지를 유지한다. 최종 독립 환경 전체 Python1101 passed/15 skipped/257 subtests(420.90초), UI152 passed, 추가 회고/API37 passed, Ruff·Bandit 중간/높음·pip check·pip-audit 통과. Windows 에이전트 전체110 중108 passed/1 skipped/기존pwsh 복구1 timeout 후 해당 파일 단독10 passed로 재검증했다. 공유 환경의 무관한 패키지 충돌과 초기 임시 검사 wrapper의 spawn 재실행은 독립 D 드라이브 검사 환경/실행 guard로 보정했으며 프로젝트 의존성/설치기 코드는 변경하지 않았다. 실제18분 전달 지연 guard 후 relay active를 확인했다. 사용자 개인Word/JSON·기존 체크포인트/문서/계정·키는 보존하며 새 코드 운영 배포/최종 경보·재시작 인수와 CI는 후속 검증 전이므로 위 실환경 작업을 완료로 바꾸지 않는다.

2026-10-14 후속 CI/실제 배포: 2c2e4c2 일반 push·소스291개 SHA·SQLite10개 online backup/격리 memory restore를 검증해 포털/priority와 별도6룰 additional/7룰 retrospective worker를 적용했다. 원래 AUTH900초/초기 통지·과거 처리 DB·ES/수집기·기존 사건/대시보드·키/CA·개인 파일을 보존했다. 실제7개룰 경보의 정확 근거를 확보하고 실시간 worker가 최신 구간까지 추적했으며 과거 재평가 대기 구간은 별도 표시한다. PC/모바일·두테마/홈·개인8조합 API조회 완료·JS0/넘침0/화면 오류0. 18분 지연20개 웹로그의 최소정규화지연1095초를 확인했다. Actions38524112869 Windows success·Ubuntu는 기존DB거부 시험fixture가 SQLite기본0644로 만들어져 독립DB거부보다 private-mode거부에 먼저 걸렸다. 보호 로직을 완화하지 않고 시험fixture에0600을 명시해 관련27 passed·Ruff를 재검증했다. CI·늦은 실제 경보/재시작 최종 인수는 후속 확인 전으로 유지한다.

2026-10-14 16:10 KST 최종 인수: 배포 코드2c2e4c2/시험보정194e308의 Actions38525476052에서 Ubuntu·Windows 전체 job success를 확인했다. 14개 룰은 구현/자동·격리 검증 완료이며 실제 운영 선택은 AUTH-001·AUTH-SEQ-001·AUTH-SPRAY-001·ATTACK-01·WIN-AUTH-001·WEB-404-001·NET-PORT-001의7개다. 실제경보/정확근거는 AUTH10·sequence6·spray10·sudo연결7·Windows10·web20·종료flow15로 대조했고 포털7종 행/과거표시/근거API200 exact_reference를 확인했다. 실제Windows9→경보0/10→경보1 이후 새 운영프로필에서도 같은 경보ID를 유지했다. 실제18분 지연웹20개(최소1095.8242초)는 별도 회고경보1개/정확근거20개로 저장됐다. 과거수신미완료구간0·회고대기0·priority39초/additional33초·기존초기통지observed를 확인했다.

새 additional/retrospective만 재시작해 상태identity/체크포인트 보존·SQLite backup/memory restore·경보12개 SHA 불변·재시작추가경보0을 확인했다. 기존 portal/normalizer/priority/AUTH/ES/gateway/kibana의ID/시작시각은 해당 재시작 동안 동일했고 배포 전4개 경보도 보존했다. 기존 사건/대시보드/계정/키/CA/수집설정·개인Word/JSON을 보존했다. 실제홈·개인8조합 PC/모바일/두테마 JS0/넘침0/조회실패0이며 과거경보표시는두화면에서확인했다. 전체Python1101 passed/15 skipped/257 subtests·UI152·Windows설치기109개고유pass/1skip(기존timeout1개는파일단독10pass로해소)·Ruff/Bandit중간이상/pip check/pip-audit 통과. Git제외 state/ruleset-14-20261014에 증거를, 서버 state/rules-retro-live-20261014에 DB10개/설정/이전이미지·후속재시작DB2개 보호본을 보존한다.

남은 범위: AWS감사API6룰은 유효API프로필/시험권한·실제수집이 없어 미검증/운영미선택, OCI1룰은 사용자 제외다. SSH.pem을AWS API인증으로간주하지않고 공유IAM 권한/CloudTrail/공개포트는변경하지않았다. 기존 누락필드/평가제외 경고를 유지하며 공격부재로바꾸지않는다. DET-EXT-ACTIVATE-20261014·기존상위P0~P7/P2-02의남은인수와독립DR보류는유지한다. 이번두개DUAL작업의완료는위선택범위에한정한다.

## 2026-10-16 쇼핑몰 로그인 보안 감사 로그

- [x] MALL-DETECT-04C 실제 경보 저장·조회 인수 완료(2026-10-16, 운영 워커·통지·UI 배포 제외): 최신 요청에 따라 실습 ES 정규화4건을 기존 규칙 로더/탐지/경보 생성·create-only 저장 함수로 처리했다. WEB-ACCESS-01 실제 경보1건 및 WEB-AUTH-01 실제0건, 별도 합성37건에서 AUTH 경보1건을 전용 인덱스에 저장·재조회했다. 실제·합성 재처리 증가0건, 일반403 및 조직/계정/키버전/IP 혼합 경보0건, 성공 간격899초에서900초 cooldown 억제, 증거1+6개 원본 역추적을 검증했다. severity medium과 기존45+15=60/high 계산은 별도 필드로 유지했다.

2026-10-16 MALL-DETECT-04C 작업 로그·범위·제한:

- 증적: `docs/security_mall_alert_integration_validation.md`, Git 제외 `state/security-mall-alerts-4c-20261016/summary.json`, VM `/home/kopo/soc-mall-lab/detection-4c/results/`. 실행 식별자 `20261016-f56deb49`; 실제·합성 경보 저장소를 분리하고 실제 3-C 원본·정규화4건씩의 본문/버전/seq_no/primary_term 불변을 확인했다. TLS 검증 및 수명2시간의 최소 권한 키로 실행했으며 create 충돌 후 경보 본문·ID·버전도 불변이었다. 비밀값은 기록하지 않았다.
- 기존 경보 시각은 이벤트 window_end이고 실행 시각은 별도 결과의 evaluated_at이다. 서비스/가명/키버전/원본 이벤트 ID는 기존 증거 참조를 역조회해 확인한다. 기존 위험도 수식과 필드 계약은 수정하지 않았다. 다음 UI는 인덱스 읽기 허용 범위·조직 권한·증거 연결 및 severity/계산 위험도 구분이 필요하다.
- 기존 미커밋 변경은 baseline과 해시로 보존했다. 이번 추적 파일 변경은 이 기록과 신규 실증 문서다. 기존49건 테스트·3-C·Filebeat·쇼핑몰 검증은 반복하지 않았으며 실제 ES 통합 사례만 실행했다. Docker/서비스/운영 탐지기·Slack/대시보드/Git 원격 작업은 하지 않았다. 운영 워커 배포·통지·UI·장기 운용 검증은 이번 완료 범위에 포함하지 않는다.

- [x] MALL-DETECT-04 로컬 구현·관련 검증 완료(2026-10-16, 워커 배포 제외): 기존 single/sequence/증분·경보 저장 엔진에 `rules/security_mall.yml`의 WEB-ACCESS-01(low, order_view/failure/order/not_owner)과 WEB-AUTH-01(medium, 조직/서비스/가명/키버전/IP별 실패5/300초→유효 실패군 마지막 후600초 성공, cooldown900초)을 등록했다. 사용자의 일반403은 경보 없음 명확화를 반영했다. 기본 AUTH-001/기존 SSH sequence v2·초기 통지·기존 위험도 계산은 유지했다. 새 엔진/프레임워크·권한/배포 코드를 추가하지 않았다. 변경은 detection/{engine,registry,sequence,rule_loader,incremental,profiles}.py, pipeline/alerts.py, 신규 규칙, 테스트2파일/기존 ruleset_fixtures.py, docs/security_mall_detection.md와 이 기록이다.

2026-10-16 MALL-DETECT-04 인수·보존·제한:

- 원본 event.id를 조직/호스트/서비스로 범위화한 관측 식별자로 중복 실패를 세지 않는다. 경보 ID는 기존 해시/create-only 구조 안에서 거부 또는 성공의 원본 관측 anchor를 사용해 재정규화·다른 원본 참조/늦은 추가 증거에도 같은 성공/거부의 경보를 중복 생성하지 않는다. 최초 normalized/raw index/id 증거는 기존 저장 계약으로 보존한다. 추후 반복 거부의 자동 우선순위 상향·같은 주문 추정은 구현하지 않았다.
- 선택 success_window만 failure-success-v3/실패창+성공대기 보존/cooldown을 사용한다. 기존 sequence 설정의 의미/버전·영점 cooldown 제약은 보존했다. 기본900초 사건 지연 버퍼/normalized_at 읽기/15분 overlap·frontier 초과 late_event 이력을 기존 증분 엔진에서 재사용했다. 그룹 경계에 없는 계정/IP/키를 추정하지 않는다.
- 3-C의 실제 정규화4건 검색 결과 파일만 SSH/SCP로 읽기 전용 사본화해 먼저 검사했고 WEB-ACCESS-01=1/WEB-AUTH-01=0·complete 증거·low를 확인했다. 빌드/수집/output.file/ES 설치/3-C 검증을 반복하지 않았고 원격 ES/서비스/기존 데이터에 쓰지 않았다.
- 관련 고유시험49 passed/최종 failures0/errors0. 최초38 passed와10 setup errors는 Windows 기본 pytest 임시 폴더 권한 거부가 원인이며 새 프로젝트 basetemp에서 해당10건만 통과했다. 이후 cooldown SQLite 재시작/만료1건만 추가 통과했다. 새 규칙의 임계값/두 시간 경계/기준 미달·시간 초과·계정/조직/서비스/IP/키 분리·null·순서 역전/동시시각·재처리/최초 증거 보존·지연 버퍼/late 기록·프로필/기존 AUTH-001/SSH 시퀀스/초기 통지·실패복구/전체 카탈로그 혼합을 검사했다. 전체 Python/UI/브라우저/성능 시험은 실행하지 않았다. 성공 시험 반복은 없다.
- WEB-AUTH-01의 초기 severity는medium이며 기존 risk 계산은 sequence15점 포함60/high band다. risk 수식은 수정하지 않았다. 일반403/접근 차단을 유출 성공·계정 탈취 확정으로 표현하지 않는다. 별도 프로필/새 상태 선택이 필요하고 기본 AUTH-001/초기 통지 상태를 재사용하지 않는다.
- 기존 미커밋24파일을 state/security-mall-detection-20261016/baseline 및 해시로 보존했다. 그중 작업 기록 외23파일은 최종 해시 불변을 확인한다. 실제4건 사본/안전 요약/JUnit은 Git 제외 경로에만 보존하고 문서·테스트에는 가상 자료만 사용했다. 이번 완료는 로컬 구현/격리 시험이다. 실서버 워커 배포·실제 경보 인덱스 저장/알림 발송·운영 지연 인수는 수행하지 않았다. 기존 서비스·DB·원격 중앙/키·Git commit/stash/reset/push/PR/merge·다음 단계 개발은 하지 않고 종료한다.

2026-10-16 MALL-AUDIT-03C-1 재개/진행 중: 사용자가 이번 범위에서 Elastic 공식 Filebeat9.5.2 tar.gz와 SHA512 다운로드를 명시 승인했다. x86_64/여유8988082176B를 확인했다. 사용자 소유 tools에서 검증 후 압축 해제하고 독립 output.file/복사본4건·합성 거부/같은 registry 재시작만 검증한다. 기존 권한 제한 경로·서비스는 유지하며 sudo/apt/Docker/ES/중앙 접속은 금지한다. 다운로드 실패 시 원인1회 확인 후 중단하고 체크섬 실패 시 실행하지 않는다.

- [x] MALL-AUDIT-03C-1 독립 Filebeat output.file 실제 인수 완료(2026-10-16): 최신 공식 압축본 다운로드 승인으로 사용자 tools 경로에서 Filebeat9.5.2/amd64(공식 SHA512 검증 후 압축 해제·실행)를 사용했다. test config는 Config OK. 별도 filebeat-test의 읽기 전용 기존 감사4건(실패1/성공2/타인 주문거부1)과 별도 합성 정상340B1건을 실제 processor로 수집했다. 총7줄 added/done 중 잘못된 JSON1·미지원 필드/무해한 표식1을 거부해 파일 출력5건(실제4+합성1)을 얻었다.4개 고유ID/전체 감사 필드/가명·키버전/사유 보존, 원문message/event.original 부재·표식의 출력/진단 부재와340B<1024B growing fingerprint 수집을 확인했다. 같은 registry 재시작1회/6초 관찰에서 추가0건, 두 프로세스 SIGINT exit0/정상 종료다. 문서 `docs/security_mall_filebeat_validation.md`, VM `filebeat-test/config/verification-summary.json`에 근거와 재현 경로를 기록했다.

2026-10-16 MALL-AUDIT-03C-1 실제 인수 한계/보존:

- 첫 도구의 root 필드 검사는 output.file이 예약 @metadata를 직렬화하는 점을 놓쳐 실패했다. 실제 수집을 반복하지 않고 이미 생성된 출력의 예약 키6개와 애플리케이션 필드를 구분해 나머지 검증·필수 재시작만 수행했다. processor/기존3-B 설정 소스는 변경하지 않았다. 파일에서 _id/op_type이 보이는 것만으로 ES 메타데이터 반영/Bulk create-only/중복·변조 차단을 검증했다고 주장하지 않는다. 재시작 검사는 고정 입력·정상 종료 조건에 한정하고 장애/회전 exactly-once로 확대하지 않는다.
- 기존 Filebeat MainPID963/시작 시각/active 동일, 쇼핑몰 원본 JSONL SHA256 동일, 현재 임시 Filebeat 프로세스0이다. 기존 서비스/설정/registry/권한·Java 코드/빌드·실제 비밀번호/쿠키/HMAC·Docker/ES/중앙 서버는 접근/변경하지 않았다. 권한 없는 기존 바이너리를 복사하지 않았다. 기존 로컬 브랜치/미커밋 변경은 보존했고 로컬 변경은 작업 기록과 신규 검증 문서뿐이다. 전체/기존 성공 테스트 반복·설치·Git 원격 작업은 없다.
- 다음 단계는 격리 TLS ES/전용 인덱스·CA·최소 권한 키 준비, 실제 Painless/중앙 수신 시각/루트 시각/Bulk create-only, 실제 원본→정규화 참조·중복/변조·회전 인수다. ES 다운로드·접속/정규화·GZIP/부분 줄·파일 회전은 이번 범위에서 실행하지 않았고 부모 MALL-AUDIT-03C는 unchecked다. 이번 output.file 범위만 완료하고 중단한다.

이전 권한 미확보 중단 기록(보존):
MALL-AUDIT-03C-1 실행 권한 미확보로 실제 수집 검증 중단(2026-10-16): 최신 요청에 따라 기존 브랜치/미커밋 변경을 보존하고 지정 3-B Filebeat 예제·Script Processor 및 작업 기록만 확인했다. 지정 키/BatchMode=yes/StrictHostKeyChecking=yes/IdentitiesOnly=yes의 비대화형 SSH 성공. VM 쇼핑몰 PID55637의 실제 JAR 경로와 GET / HTTP200을 확인했고, 기존 cloud-soc-filebeat.service는 active다. 바이너리 `/opt/cloud-soc-agent/filebeat/filebeat`, 서비스 설정 경로 `/opt/cloud-soc-agent/filebeat.yml`을 서비스 메타데이터에서 확인했으나 kopo의 실행 권한 검사가 false여서 버전 실행·test config·독립 Filebeat 실행은 하지 않았다. 비밀 설정/인증 정보는 읽거나 출력하지 않았고 sudo·권한 변경·바이너리 복사 등 우회는 없다.

2026-10-16 MALL-AUDIT-03C-1 사전 확인/미완료 범위:

- CPU4, RAM총8083508KiB/가용5949916KiB(약5.67GiB), swap여유4176528KiB, 배포 경로 파일시스템 여유8991674368B(약8.37GiB). Docker CLI는 존재하지만 현 계정의 docker image ls가 exit1이라 기존 Elasticsearch 이미지/컨테이너 충돌 여부는 미확인이다. 권한을 확대하거나 기존 Docker·운영 중앙에 우회 접속하지 않았다. 자원 수치만으로 격리 ES 실행 가능을 확정하지 않는다.
- 사용자가 명시한 기존 감사4건(실패1/성공2/타인 주문 거부1)은 이번 작업에서 읽기·복사·수정·삭제하지 않았다. 파일별 고유 event_id 통과·보존, 원문 제거/민감정보 차단, 무해한 오류 JSON/미지원 필드 거부는 실제 Filebeat로 미검증이다. 버전/실제 processor 실행·설정 호환성과 test config도 미검증이며 앞 단계 성공으로 간주하지 않는다. 실행 불가가 확인되어 filebeat-test 디렉터리/설정/복사본/registry/출력 파일을 만들지 않았다.
- VM 변경·서비스 재시작·기존 설정/registry 접근·추가 로그인/권한 요청·쇼핑몰 빌드/소스 수정·단위/전체/UI 시험·설치/이미지 다운로드/컨테이너 생성·실제 ES/정규화·Git 원격 작업은 없다. 로컬에서는 이 기록만 갱신했다. 이전 앱 배포 완료와 부모 MALL-AUDIT-03C의 전체 통합 미완료 상태를 유지한다.
- 재개에는 관리자가 기존 서비스·비밀 설정을 건드리지 않고 kopo가 실행 가능한 기존 Filebeat 바이너리 경로/권한을 제공해야 한다. ES 준비 판정에는 관리자 측 읽기 전용 기존 이미지/컨테이너 목록이 추가로 필요하다. 이후 별도 경로 output.file 수집4건/거부·개인정보 보호 실제 시험을 먼저 완료한 뒤 격리 TLS ES 준비를 판단한다. 운영 중앙 사용은 이번 작업에서 분석·접속·승인하지 않았다.

- [x] MALL-AUDIT-03C-APP 쇼핑몰 단독 배포·실제 감사 검증 완료(2026-10-16): 사용자 최신 승인 범위로 독립 Ubuntu VM `kopo@192.168.235.131`의 `/home/kopo/soc-mall-lab`에 최신 로컬 bootJar를 배포했다. 기존 openjdk-17-jre-headless17.0.20.1이 이미 있어 설치를 생략했으며 sudo 대화형 인증이 필요하지만 사용자 홈 배포에는 불필요했다. 공식 패키지 조회/용량·여유 확인만 했고 apt 설치·다운로드는 없다. Windows 기존 JDK17/Gradle Wrapper의 `bootJar --console=plain` 성공(11초), 테스트 재실행 없음. JAR57,487,806B 전송 전후 SHA256 `249e8dd98590ce41c5e4992f0e966dff36670e23001860d1d9363c384c1a0d9d` 일치. PID55637, 루프백127.0.0.1:18080, 전용 H2/가상2계정·타인 주문1개/VM 생성 HMAC 키·보호 설정0600/H2 Console 비활성화/별도 JSONL로 실행했다. 상세 경로와 PID·시작/종료 절차는 `docs/security_mall_lab_deployment.md`에 기록했다.

2026-10-16 MALL-AUDIT-03C-APP 실제 인수/제한:

- VM 내부 HTTP GET / 200, H2 Console404, 실제 로그인 실패1·성공2·타인 주문403/`order_view` failure/not_owner1, 총4개 JSON 이벤트를 확인했다. event_id UUID/고유성·발생 시각·허용 필드·안정적 가명/account_key_id·관측IP·권한사유와 응답 개인정보 미노출, 감사/앱 로그의 시험 비밀번호·쿠키 세션/HMAC·DB 비밀값/개인정보 canary 부재를 검증했다. 결과는 VM의 보호된 `config/verification-summary.json`, 감사 파일은 `/home/kopo/soc-mall-lab/logs/security-audit.jsonl`이다. 비밀값이나 원문 감사 로그는 저장소로 복사하지 않았다.
- 검증 도구의 실패와 앱 동작을 구분한다. IPv4-mapped IPv6 루프백 표기를 문자열 검사에서 놓쳐 포트 검사가 실패했으나 실제 공개 바인딩은 없었다. 리다이렉트의 세션 경로 매개변수를 고려하지 않은 응답 판정으로 첫 성공 세션을 잃어 주문 검증용 로그인1건이 추가됐다. 최초 실패 응답은 보존하지 못했으므로 HTTP 상태 검증으로 주장하지 않는다. 진단 출력에 마지막 시험 세션 값이 포함됐으나 주문 검증 직후 로그아웃으로 해당 세션을 폐기하고 임시 쿠키 파일도 삭제했다. 감사 기록은 삭제/재작성하지 않았다. 앱 코드 수정이나 성공 요청의 추가 반복은 없다.
- 기존 Cloud SOC `codex/security-mall-collection`/쇼핑몰 `codex/access-security-audit`와 미커밋 변경·운영 중앙/기존 인덱스·DB·키/기존 Filebeat 서비스는 보존했다. app/data/logs/config 경로와 비밀 설정·DB는 독립 VM 전용이다. 기존 서비스 재시작·공개 포트·결제 호출·ES/Filebeat 설치·commit/stash/reset/push/PR/merge·탐지/위험도 후속 작업은 없다. 로컬 변경은 이 작업 기록과 신규 배포 문서뿐이며 JAR는 기존 Git 제외 build에 생성됐다.
- 완료는 쇼핑몰 단독 배포와 실제 감사 기능에 한정한다. 부모 MALL-AUDIT-03C는 unchecked로 유지한다. 다음 별도 단계의 Filebeat native processor/격리 TLS ES/Painless/최소권한 create-only/원본·정규화 실제 저장 및 참조/중복·변조·재시작·부분 JSON·회전/GZIP은 모두 미검증이다. 앱은 nohup으로 실행 중이며 재부팅 시 자동 실행하지 않는다. 이번 범위에서 중단한다.

2026-10-16 MALL-AUDIT-03C 쇼핑몰 배포 범위 재개/SSH 성공·Java 미설치 중단:

- 최신 사용자 지시는 이번 범위를 쇼핑몰 실행/실제 감사3종 검증으로 한정하고 Filebeat/ES 신규 설치·수집 인수는 다음으로 남겼다. 지정 `IdentityFile=%USERPROFILE%/.ssh/cloudsoc_mall_lab`, BatchMode=yes, StrictHostKeyChecking=yes, IdentitiesOnly=yes를 사용한 `kopo@192.168.235.131` 비대화형 접속은 성공했다. SSH 인증 설정을 변경하지 않았고 비밀번호/키 암호·개인키 내용을 읽거나 출력하지 않았다.
- VM 읽기 전용 결과: CPU4, RAM7894MiB/가용6192MiB, swap4095MiB, 루트24GiB/가용8.7GiB. 18080 listen 없음. Docker CLI29.8.2 설치 및 docker/containerd 서비스 active. 기존 cloud-soc-filebeat/cloud-soc-packetbeat 서비스도 active다. Java는 PATH·확인한 /usr/lib/jvm 및 /opt Java 후보에 없고 apt-cache의 openjdk-17-jre-headless Installed는 none, 후보는17.0.20.1+1-1~24.04였다(기존 apt metadata 읽기만 수행). Docker 로컬 소켓의 이미지 조회는 현 계정에서 불가하여 Java 이미지 캐시는 미확인이다. Filebeat는 PATH에 없으나 기존 서비스 ExecStart 경로 `/opt/cloud-soc-agent/filebeat/filebeat`를 확인했고 현 계정에서 실행 가능하지 않아 버전은 미확인이다. sudo/권한 변경으로 우회하지 않았다.
- 로컬 Cloud SOC는 `codex/security-mall-collection`, 쇼핑몰은 `codex/access-security-audit`이며 기존 미커밋 변경을 보존했다. HomeController의 로그인 성공/실패 각 감사 호출·관리자7경로 검사·주문 인증/소유권/not_owner, LoginAuditLogger의 HmacSHA256/권한 로거, Logback의 전용 security-audit.jsonl/비전파 파일 로거와 외부 키 설정이 작업 트리에 모두 존재한다. build.gradle은 Java17 toolchain을 요구한다. 과거 브랜치 병합/체크아웃/기존 파일 덮어쓰기는 하지 않았다.
- 필수 Java 실행 환경 미준비 시 무단 설치하지 말고 조치만 보고하라는 최신 조건에 따라 JAR 빌드/전송/실행 전 중단했다. VM `/home/kopo/soc-mall-lab`는 사전 확인에서 absent였고 생성하지 않았다. 실제 HTTP 요청·가상 계정/주문·전용 HMAC 키/H2/JSONL 생성과 감사 로그 검증은 모두 미실행이다. 예상 실행 주소127.0.0.1:18080은 아직 열지 않았다. 기존 로그/DB/비밀키·운영 서버/인덱스는 사용하지 않았다.
- 다음 조치는 별도 승인을 받은 공식 openjdk-17-jre-headless 설치 또는 명시적으로 제공된 기존 호환 Java 실행 환경이다. apt update/install·대용량 다운로드·Docker pull/run·기존 서비스 중지/재시작·포트 개방·전체/성공 시험 반복·commit/stash/reset/push/PR/merge·탐지/위험도 후속 개발은 하지 않았다. SSH/자원/코드 존재 확인은 완료했으나 쇼핑몰/수집 인수는 미완료이므로 MALL-AUDIT-03C는 unchecked로 유지한다. 기록 전 OS 임시 cloud-soc-mall-3c-app-precheck에 기존 추적 문서 사본을 보존하고 이 결과만 추가했다.

2026-10-16 MALL-AUDIT-03C SSH 키 인증 준비 후 재시도/인증 거부 중단:

- 사용자가 VM 호스트 지문 검증 및 SSH 키 인증 준비를 알리고 재개를 요청했다. 기존 Cloud SOC `codex/security-mall-collection` 및 쇼핑몰 `codex/access-security-audit`의 미커밋 상태를 확인·유지했다. `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 kopo@192.168.235.131 ...`로 지정 실습 VM에 한 번 접속을 시도했다. 결과는 exit1, `Permission denied (publickey,password)`이며 이전의 호스트 키 오류 대신 사용자 인증 단계에서 거부됐다. 비밀번호/키 암호를 요청·출력하거나 키 내용을 읽지 않았다.
- 인증이 완료되지 않아 원격 CPU/RAM/디스크·Java/Docker/Filebeat·포트/프로세스/서비스 점검 명령은 실행되지 않았다. SSH 실패 시 보안 설정을 완화하지 말고 중단하라는 최신 지시에 따라 추가 인증 재시도·옵션 완화·설치·배포·서비스 실행·실제 로그/DB/키 생성·ES/Filebeat/정규화 시험을 하지 않았다. 원본3/정규화3과 중복/회전/null 처리는 모두 미검증이다.
- 현재 클라이언트에서 선택되는 공개키/ssh-agent/IdentityFile과 VM kopo의 authorized_keys·권한 일치 여부 확인이 재개에 필요하다. 이번 실패만으로 사용자가 키를 준비하지 않았거나 VM에 런타임이 없다고 단정하지 않는다. 운영 서버/기존 인덱스·키·설정은 접근/변경하지 않았고 기존 로컬 변경을 유지하며 이 기록만 추가했다. commit/stash/reset/push/merge·전체 시험·탐지/위험도 개발은 없다. 3-C는 미완료/unchecked로 유지한다.

2026-10-16 MALL-AUDIT-03C 독립 Ubuntu VM 인수 재개/SSH 사전 확인 중단:

- 최신 사용자 요청은 별도 Ubuntu24.04 VM `192.168.235.131`에 한해 읽기 전용 환경 점검 후 `~/soc-mall-lab/`의 쇼핑몰/격리 ES/Filebeat 배포·실제3이벤트 검증을 허용한다. 운영 Cloud SOC 서버/기존 키·인덱스는 계속 범위 밖이다. Java 미설치 시 공식 패키지/영향 보고 후 승인, Docker/자원 부족 시 중앙 ES 대안 분석/승인 조건을 유지한다. 이전의 로컬 실행 환경 부재를 이번 VM의 런타임 상태로 추정하지 않는다.
- 로컬 Cloud SOC 브랜치는 `codex/security-mall-collection`, 쇼핑몰은 `codex/access-security-audit`이며 기존 미커밋 변경을 유지했다. 지정된 1·2단계 로그인/관리자 검사/주문 소유권/HMAC 감사 코드와3-A 어댑터·3-B 설정5파일 존재를 읽기 전용으로 확인했다. 기존 SSH config/시스템 설정과 config/deploy/tools/docs에서 대상 IP의 접속 사용자 설정을 찾지 못해 사용자에게 질문했고, 사용자가 **kopo / 비밀번호 로그인**으로 답했다. 비밀번호나 개인키 내용은 받거나 읽지 않았다.
- `ssh -o BatchMode=yes -o PreferredAuthentications=password,keyboard-interactive -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 kopo@192.168.235.131 ...`의 결과는 미등록 ED25519 호스트 키로 인한 `Host key verification failed`였다. SSH 서버 응답은 있었으나 인증/원격 명령 실행에는 도달하지 못했다. 후속 공개키 스캔(`ssh-keyscan -T5 -t ed25519`)도 결과를 확보하지 못했다. host 검증 비활성화/무검증 known_hosts 등록/비밀번호 명령 인수 전달·반복 인증은 하지 않았다.
- 사용자 지정 A의 SSH 불가 시 중단 조건에 따라 이후 단계는 미실행이다. VM CPU/메모리/디스크·Java/Docker/Filebeat·18080/19200·기존 서비스/배포 경로권한은 **미확인**이다. JAR 빌드·전송·원격 디렉터리/키/DB 생성·서비스 실행·ES/Painless/Filebeat·실제 이벤트/정규화 저장·중복/회전 시험을 수행하지 않았다. 이전 모의 시험을 실제 인수로 대체하지 않는다.
- 현재 차단은 VM 설치 여부가 아니라 SSH 신뢰와 안전한 대화형 인증 경로 미확보다. Windows에서 사용자 본인이 VM 호스트 지문을 신뢰 가능한 경로로 확인하고, 채팅/명령 인수에 비밀번호를 노출하지 않는 인증 경로가 준비된 후 재개해야 한다. 그 전에는 임의 설치나 운영 중앙 대안 적용을 하지 않는다. 코드/구성/로컬 브랜치·기존 사용자 변경은 보존했고 이 기록만 추가한다(기록 전 OS 임시 cloud-soc-mall-3c-vm-precheck 사본 보존). commit/stash/reset/push/PR/merge·운영/VM 변경·탐지/위험도 후속 작업은 없다. 3-C는 미완료/unchecked다.

- [x] MALL-AUDIT-03C-ES-PREP 설정 작성·전송 완료(2026-10-16, 설치/실행 제외): 최신 사용자 요청 범위에서 `deploy/security-mall/es-lab/`의8파일(.gitignore/compose.yml/init-secrets.py/preflight.py/start.sh/check-https.py/stop.sh/README.md)을 신규 작성해 VM `/home/kopo/soc-mall-lab/es-lab`에만 전송했다. Elasticsearch9.5.2/단일 노드/프로젝트soc-mall-es-lab/신규 이름soc-mall-es-lab-data/127.0.0.1:19200/heap1GiB·컨테이너3GiB/인증·HTTP 및 transport TLS/127.0.0.1 SAN/파일형 비밀번호·UID1000/보호runtime·Git 제외/한정 종료를 구성했다. start.sh는 자원·실제 Docker data-root 여유8GiB·기존 볼륨/프로젝트 충돌을 검사하고 사용자 콘솔 sudo Docker 명령만 실행하도록 작성했다. 기존 볼륨이 있으면 삭제나 재사용 없이 거부한다.

2026-10-16 MALL-AUDIT-03C-ES-PREP 검증 및 경계:

- 사전 SSH 읽기 전용 결과: 대상 es-lab 경로 absent/소유UID1000, Python3/OpenSSL/curl 존재. 사용자가 중지·비활성화한 기존 cloud-soc-filebeat 및 packetbeat가 실제 inactive/disabled임을 확인했으며 Codex는 서비스를 변경하지 않았다.
- 기존 검증 Python/PyYAML로 신규 Python3파일 AST 및 compose YAML의 단일 서비스/버전/loopback포트/heap·메모리/TLS·인증/파일형 비밀번호·read-only mount/Git 제외를 오프라인 검사했다. 신규 테스트 프레임워크·패키지 설치는 없다. VM 전송8파일 SHA256 일치·파일0600/실행 스크립트0700·디렉터리0700, sh -n2파일 통과. 실제 preflight.py 읽기 전용1회 실행은 RAM가용6.65GiB, home 및 /var/lib/docker 파일시스템 각각여유11.0GiB, vm.max_map_count1048576/19200 bind 가능으로 exit0다. Docker Compose 렌더러 및 ES 이미지는 실행하지 않았으므로 YAML 검사와 실제 Compose/ES 인수를 구분한다.
- 비밀번호/인증서 init-secrets.py·start.sh·check-https.py·stop.sh는 실행하지 않았다. VM runtime은 absent이며 비밀값/개인키/API키를 생성하거나 출력하지 않았다. Docker pull/info/compose/config/up/volume/컨테이너 생성도 Codex는 수행하지 않았다. 사용자 콘솔 명령과 HTTPS CA/SAN·401/인증200·버전/health 확인 및 프로젝트 한정 stop은 README에 기록했다. 디스크 계획3~6GiB는 이미지·데이터 추정치이며 실제 미다운로드로 미측정, 시작 전 최소여유8GiB/가용RAM4GiB를 요구한다. 데이터 하드quota/실제 메모리사용은 보장하지 않는다.
- 기존 쇼핑몰 소스/JAR/DB/감사 로그, 기존 Cloud SOC 코드/키/설정, 기존 브랜치/미커밋 변경을 수정하지 않았다. 기존 성공 테스트·전체/UI 테스트·쇼핑몰 빌드·Git 원격/탐지 작업은 없다. 준비 하위 작업만 완료이며 부모 MALL-AUDIT-03C는 계속 unchecked다. 실제 설치·TLS·수신/Painless/최소권한/create-only/원본4·정규화4 인수는 사용자의 설치 후 별도 단계에서 검증해야 한다.

2026-10-16 MALL-AUDIT-03C 격리 Elasticsearch 구축 재개/사전 점검 중단:

- 최신 사용자 요청은 깨끗한 독립 VM에 Elasticsearch9.5.2 이미지 다운로드·별도 Compose/볼륨/localhost19200/TLS·인증을 구성하고 기존 감사4건의 Filebeat 실제 수신·3-A 정규화를 인수하는 범위로 확대했다. 이전 단계의 ES 설치 금지는 이 실습 VM 범위에서 대체되며 운영 중앙/기존 서비스 변경·키 재사용·기존 인덱스·전체 시험·Git 원격 작업 금지는 유지한다. 기존 브랜치 codex/security-mall-collection 및 미커밋 변경을 보존하고 지정된 deploy/security-mall pipeline/template/writer-role만 확인했다.
- 지정 키/BatchMode=yes/StrictHostKeyChecking=yes/IdentitiesOnly=yes SSH 성공. 쇼핑몰 PID55637와 GET / HTTP200, RAM가용6808884KiB(약6.49GiB), 파일시스템 여유11812139008B(약11.0GiB), vm.max_map_count1048576,19200 포트 미점유를 확인했다. 디스크는 사용자 제시14GB 대신 이 실제 조회 수치를 기록한다. Docker Compose CLI5.6.0은 실행 가능하지만 daemon API 조회는 permission denied다.
- 원인1회 확인: unix:///var/run/docker.sock은 root:docker(gid988)/0660이며 현재 SSH 프로세스 그룹 목록에988이 없다. sudo -n true도 실패해 비대화형 관리자 실행이 불가하다. 비밀번호 요청·입력/그룹·소켓 권한 변경/daemon 우회는 하지 않았다. Docker 서버 버전·컨테이너/이미지/볼륨0개 여부를 확인할 수 없으므로 사용자 진술을 실측 성공으로 바꾸지 않는다. 이미지 pull·Compose/볼륨/컨테이너/설정·인증 정보 생성/ES 실행은 시작하지 않았다.
- 기존 cloud-soc-filebeat.service MainPID963/active, cloud-soc-packetbeat.service MainPID964/active다. 현재 계정의 ss에 이 프로세스의 연결 귀속 정보가 보이지 않아 외부 전송 여부는 미확인이다. 연결이 없다고 단정하지 않으며 기존 에이전트 설정/비밀정보·환경·권한을 읽거나 서비스를 종료/재시작하지 않았다. 운영 중앙에는 접속하지 않았다.
- 실제 TLS·인증/Painless compile/_simulate/템플릿/중앙 event.ingested/최소권한/create-only/원본4·정규화4/재전송·덮어쓰기 차단은 모두 미실행이다. 기존 통과 쇼핑몰/단위/output.file 검증을 반복하지 않았고 실제 감사 로그·DB·키·registry·기존서비스는 불변이다. 로컬 변경은 이 기록뿐이다. 부모 MALL-AUDIT-03C는 unchecked로 유지한다. 재개 전 사용자가 VM 콘솔에서 Docker 사용 권한을 준비하고 새 SSH 세션의 접근 가능을 확인해야 하며 관리자 측에서 기존 에이전트의 외부 전송 여부도 확인해야 한다. 이번 환경 차단 상태에서 설치를 강행하지 않고 중단한다.

2026-10-16 MALL-AUDIT-03C 최종 통합 검증 착수 기록(아래 최종 인수 완료): 최신 요청에 따라 이미 사용자가 설치한 soc-mall-es-lab9.5.2에만 TLS 검증 HTTPS로 접근한다. 사전 대상 확인은 CA 검증·401/인증200·클러스터/버전 일치, 실제 감사4개 고유ID, 기존 에이전트2개 inactive였다. 신규 integration-3c 경로에서 3-B pipeline/template/단일 원본 인덱스 최소create_doc 키와 별도 정규화 인덱스를 준비해 실제 Filebeat·동일ID/변조·기존3-A normalize/참조·조건부 회전을 검증한다. Docker/설치·쇼핑몰/output.file/전체시험 반복과 운영 Worker/Detector·중앙접속은 제외한다. 기존 미커밋 변경과原문4건을 보존하고 비밀은 VM 보호파일/keystore에만 둔다.

- [x] MALL-AUDIT-03C 핵심 실제 통합 인수 완료(2026-10-16): 이미 설치된 독립 soc-mall-es-lab ES9.5.2/독립 Filebeat9.5.2를 TLS 검증 상태로 연결했다. 실제 Painless 등록·simulate/위조 수신시각 덮어쓰기/원문 거부·strict 매핑·최소 권한 키를 확인한 후 기존 감사4건(실패1/성공2/타인 주문거부1)을 Filebeat로 전송해 원본4건 저장했다. 기존3-A normalize와 실제 의존18파일을 해시 대조해 독립 실행하고 별도 실습 인덱스에 정규화4건(authentication3/iam1)을 create로 저장했다. event_id/가명/IP/사유/시각/조직·호스트 및 실제 raw index/id 참조를4건 모두 대조했다. 원본 `soc-host-raw-mall-isolated-20261016-8a070063`, 정규화 `soc-normalized-mall-isolated-20261016-8a070063`이다. 신규 문서 `docs/security_mall_integration_validation.md`, 3-B 문서의 후속 링크, Git 제외 state/mall-integration-20261016의 실행 자료·안전 요약과 VM integration-3c/results에 근거를 기록했다.

2026-10-16 MALL-AUDIT-03C 최종 검증/권한/보존:

- 관리자 인증은 pipeline/template/실습 인덱스/키 설정과 simulate에만 사용했다. writer는 원본 단일 인덱스 create_doc/cluster monitor, 정규화는 원본 read/view_index_metadata+정규화 read/create_doc로 분리했다. API Key는 VM0600/keystore에만 저장·2시간 만료다. index/write/delete/manage/auto_configure/read 및 다른 원본 인덱스 권한이 false임을 실제 확인했다. writer의 명시적ID index Bulk 음성대조는403, 실제 Filebeat4건은 저장 성공이었다.
- Filebeat 재전송은 기존4건과 변조한 동일 ID1건을 별도 registry로 실제 전송했고 added/done5·duplicates5·failed0/dropped0이었다. 최초 원본4건 _source/_seq_no/_primary_term은 그대로다. 이 서버 권한·응답/명시적ID 근거로 create-only 동작을 판별했으며 요청본문·인증 헤더의 복호화 trace를 기록하지 않았다. write/index 권한 확대·관리자 전송·우회/데이터 스트림 전환은 없다. 정규화 Bulk create4건도201/실제 저장4건을 확인했다.
- 같은 원본 registry 재시작6초는 새 입력0/원본 불변. 별도 합성 인덱스 `soc-host-raw-mall-isolated-20261016-8a070063-rotation`의 별도 최소권한 키로 rename→새 활성파일/GZIP immutable회전/절반JSON 미게시→나머지+LF 추가 시1건을 실제 Filebeat로 검증해 합성4건 저장했다. 핵심 인덱스는4/4를 유지했다. 모든 임시 Filebeat는 SIGINT exit0으로 종료했다.
- 원본/정규화 허용 필드·message/event.original 부재, 새 설정·결과·진단23파일의 API Key 인코딩/원문·관리자 비밀번호 부재와 비밀파일0600을 확인했다. 쇼핑몰 원본 JSONL SHA256 `e16e0db186d8c03b96c43469fa26fca0ed1c9bf06ec3143b674c27818bb5ada0`과 에이전트2개 inactive 상태는 전후 동일했다. 기존 소스/빌드/DB/HMAC/운영 키·중앙·output.file/registry/미커밋 변경을 보존했다. 원문 검색 근거·비밀은 VM 보호 경로에만 두고 로컬에는 안전 요약만 복사했다.
- Docker/컨테이너/서비스/볼륨 변경·재시작·설치·기존 성공 테스트·전체/UI시험·운영 Worker/Detector/상태DB·Git commit/stash/reset/push/PR/merge·탐지/위험도 후속 개발은 수행하지 않았다. 3-A/3-B 실행 코드는 수정 없이 재사용했고 구현 변경은 없다. 기존 중단 이력은 아래에 보존한다.
- 완료는 사용자가 정의한 핵심3-C(실제 원본4/정규화4·create-only) 및 이번 정상 종료/rename/GZIP/부분 줄 조건의 실습 인수다. 비로그인 null 신규 실서버 사례·copytruncate/유실registry/장기 장애 복구·운영 배포는 미검증/범위 밖이고 exactly-once 전달을 보장하지 않는다. 운영 적용이나 탐지 룰 단계로 넘어가지 않고 중단한다.

이전 환경 미준비 중단 기록(보존):
MALL-AUDIT-03C 환경 미준비로 시작 전 중단(2026-10-16): 사용자 요청에 따라 `codex/security-mall-collection`의 Git 상태/3-B 변경·허용 구성 문서와 로컬 실행 환경만 확인했다. Filebeat/Docker/Elasticsearch 명령이 PATH에 없으며 C/D/E 표준 설치 후보, Filebeat 이름의 OS 임시 폴더와 Git 제외 state 내 정확한 filebeat.exe/elasticsearch.bat/docker.exe 파일명 검색에서도 실행 파일을 찾지 못했다. 준비된 격리 TLS Elasticsearch/Filebeat 환경을 확인할 근거가 없으므로 설치·대용량 이미지 다운로드·서비스 기동을 강행하지 말라는 명시 지시에 따라 중단한다. 이 확인은 전체 PC에 설치가 전혀 없다는 단정이 아니며 다른 설치 경로/준비된 전용 환경이 제시되면 재개할 수 있다.

2026-10-16 MALL-AUDIT-03C 사전 확인 결과:

- A(Filebeat native config/Goja/JSONL/fingerprint/일반·회전·GZIP/배포 경로권한), B(ES mapping/Painless compile/_simulate/중앙 수신시각/최소권한/TLS), C(원본3·정규화3의 실제 저장/null/ID/scope 대조), D(실제 Bulk create-only/중복·변조·재시작·부분 줄·GZIP)는 모두 **미실행/미검증**이다. 앞 단계 A의 실행 환경을 확보하지 못했으며 순서를 건너뛰어 ES에 접속하지 않았다. 이전3-B의 모의49건/하위18 통과를3-C 실제 검증으로 대체하지 않는다.
- 실행 바이너리 이름/설치 경로의 존재만 조회했으며 기존 Docker Compose/데몬·기존 ES/인덱스·포트·원격 서버·실제 쇼핑몰 로그/HMAC 키/DB/운영 상태를 읽거나 사용하지 않았다. 테스트·설치·다운로드·인덱스 생성·서비스 재시작은0회다. 기존 미커밋3-A/3-B 코드·구성·기록을 유지했고 이 중단 기록만 추가했다. 기록 전 추적 문서 사본은 OS 임시 cloud-soc-mall-3c-precheck 폴더에 보존했다. 임의 commit/stash/reset/push/PR/merge·정리/삭제·4단계 탐지/위험도 수정은 하지 않았다.
- 재개 조건은 실행 가능한 호환 Filebeat와 기존 운영 환경에서 분리된 TLS ES의 명확한 로컬 경로·전용 데이터 디렉터리/인덱스·테스트 자격 증명/CA다. 실제 비밀값을 문서에 남기지 않으며 환경 준비나 설치는 별도 범위다. 3-C 완료 기준을 충족하지 않았으므로 unchecked로 유지한다.

- [x] MALL-AUDIT-03B 구성·A격리 검증 완료(2026-10-16, B실제 수신은 미검증): 기존 3-A 미커밋6파일을 OS 임시 `cloud-soc-mall-3b-240199774c334e899aa24e100e6df315`에 보존하고 commit/stash/reset 없이 새 로컬 `codex/security-mall-collection`에서 독립 Filebeat filestream/전송 전 JS 검사·ES final pipeline/strict template/단일 인덱스 writer 제안과 격리 시험을 추가했다. 3-A 구현/계약/시험5파일은 사본과 최종 SHA256 대조해 모두 동일하며 추적 기존 이력도 보존했다. 실제 환경 준비의 근거가 없어 설치/기동을 강행하지 않았고 로컬 모의 검증 범위만 완료로 표시한다.

2026-10-16 MALL-AUDIT-03B 결과/한계:

- 신규 파일은 `filebeat/security-mall/filebeat.example.yml`, `filebeat/security-mall/security-mall-audit.js`, `deploy/security-mall/ingest-pipeline.yml`, `deploy/security-mall/index-template.json`, `deploy/security-mall/writer-role.example.json`, `tests/test_security_mall_collection.py`, `docs/security_mall_collection.md`다. 기존 source/worker/parser/정상 수집 설정/쇼핑몰/탐지/위험도/UI/AWS 코드는 추가 수정하지 않았다.
- native NDJSON 디코딩만으로 중복키·정확한 필드 집합·권한 사유를 보장한다고 가정하지 않고 기존 Filebeat의 filestream + 공식 script processor를 사용했다. 별도 Python 수집 데몬은 없다. 전용 ES5.1 JS에서 bounded scalar JSON·이스케이프 중복키·정수1과1.0/1e0 구분·공통/권한 필드와 사유/시각/UUID/가명/IP를 검사하고 미지원/민감 필드를 큐 전 취소한다. 실패 시 검증표시/drop_event와 ID 유무 gate로 전송을 막고 message/event.original 및 임의 기본 메타데이터는 leaf allowlist에서 제외한다.
- 수집기 설정의 조직/호스트/출처만 사용한다. 원본 scope는 새 `soc-host-raw-mall-isolated-*`이며 template은 해당 예시에만 적용된다. final pipeline은 엄격 구조/관리 scope를 검사하고 검증 앱 시각에서 루트 timestamp를 생성하며 외부 event.ingested를 버리고 _ingest.timestamp로 중앙 수신 시각을 부여한다. template에 index.final_pipeline을 지정해 request pipeline=_none으로 우회하지 않도록 설계했다. Painless/template는 YAML→JSON 변환 가능한 구성만 확인했으며 ES에서 컴파일/설치하지 않았다.
- 원본 ID는 Filebeat 공식 fingerprint 형식의 SHA256(정렬된 조직/호스트/서비스/event_id 필드 이름과 값)이며 경로/offset/수신 시각/계정 키 버전을 넣지 않는다. create-only와 단일 고정 인덱스로 재전송409에서 기존 원본/정규화·최초 수신값을 보존한다. 다른 UUID/scope는 별도 문서다. 모순된 내용이 같은 UUID로 오면 최초 문서를 유지하며 충돌 내용 대조는 제공하지 않는다. source event_id와 3-A의 raw exact-reference/정규화 버전별 ID도 유지했다.
- A 실행: 기존 OS 임시3-A Python venv/기존 Node를 사용해 `pytest -q tests/test_security_mall_collection.py tests/test_web_collection.py::test_normalization_has_exact_protected_raw_reference_and_distinct_version tests/test_web_collection.py::test_unknown_fields_rejected_at_intake_and_adapter tests/test_linux_operational.py`를 실행했다. 신규27·웹7·Linux15 합계 **49 passed / 18 subtests passed / 0 failed**, 3.25초다. 실제 배포용 JS를 Node VM에서 실행했으나 native Filebeat fingerprint/include_fields/framing·gzip/registry와 중앙 ES/Painless는 명시적인 모의 모델/구조 검사다. 합성 JSONL·임시 gzip/부분 줄·모의 create-only 응답으로 로그인 성공/실패·order 거부/익명/관리자 행동, 재전송/회전재독/다른ID, 미지원 필드·민감 canary/오류 원문 배제, 시각과 정확한 참조를 검증했다.
- 인수 뒤 writer 권한 제안을 wildcard에서 사전 생성·final pipeline을 확인한 단일 실제 인덱스명으로 더 좁혔고, 이 변경에 영향받는 설정 시험1건만 재실행해1 passed(0.39초)를 확인했다. 이를 새 고유 시험으로 중복 집계하지 않는다. 나머지 성공 시험은 반복하지 않았다. cluster monitor + 단일 인덱스 create_doc만 제안하며 키는 발급/확대하지 않았다. 빌드별 auto_configure 요구 여부·축소 권한 실인수는 미검증으로 문서화했다. diff 공백 검사도 통과했다.
- 회전 정책은 고정 input.id/독립 영속 registry, 압축 해제 앞64바이트 file fingerprint, active+회전파일 glob, compression:auto(gzip 지원9.5.x)다. LF 없는 마지막 줄은 보류하고 malformed 줄은 취소한다. 64바이트 미만 지연/동일 prefix 지문충돌·보존 전 미수집/삭제·gzip 실패·registry 손실·copytruncate·인덱스 rollover 변경에 따른 손실/중복 가능성을 문서에 명시했다. 정확히 한 번 전달이나 실제 rotation/재시작 인수를 주장하지 않는다.
- B 실제 ES/Filebeat 수신은 **미실행/미검증**이다. 명확히 준비된 격리 서비스의 근거가 없어 실제 Filebeat/ES 설치·기동·접속, 포트/운영 서비스 탐색, Docker/Compose, SQLite/기존 registry·운영 상태 변경은 하지 않았다. 3-C에는 지원 빌드의 native config/Goja·Painless compile/_simulate·strict mapping/final pipeline/TLS/키 권한/null 보존/ID·create409·gzip/registry를 확인하고 합성1~3건을 새 원본/별도 정규화 인덱스에 대조하는 인수가 남는다. 실제 로그/HMAC 키/DB/원격 서버·기존 인덱스 삭제/재색인·commit/push/PR/merge·탐지/위험도/UI 후속 개발은 하지 않고 중단한다.

- [x] MALL-AUDIT-03A 로컬 구현·격리 시험 완료(2026-10-16): 로컬 브랜치 `codex/security-mall-normalization`에서 쇼핑몰의 schema_version1 전용 순수 파서(`security-mall-audit-v1`)와 security_detail/정규화·필드 선택 연결을 구현했다. 기존 추적 미커밋 변경은 OS 임시 폴더 `cloud-soc-mall-3a-bfd7644df98740d5a1f12ac301ad0ff3/work_tracker.md`에 먼저 보존했다. 문서화된 실제 login/관리자7행동/order_view만 허용하고 authentication/iam으로 분류한다. UUID·UTC 시각·IP·HMAC 가명/키 버전·권한 사유 조합·필수 필드를 검사하며 익명 account_id=null을 허용한다. 원본 참조/버전별 재처리ID·event.id와 키 버전 보존, 민감 원문 비복사·신뢰 수집 envelope의 조직/호스트 계약을 가상 이벤트로 검증했다.

2026-10-16 MALL-AUDIT-03A 결과/한계:

- 변경 파일은 신규 `src/cloud_soc/parsers/security_mall.py`, `src/cloud_soc/portal/security_detail.py`, `src/cloud_soc/processing/contract.py`, 신규 `tests/test_security_mall.py`, 신규 `docs/security_mall_audit.md` 및 이 작업 기록이다. worker는 기존 DETAIL_FIELDS 상속을 그대로 사용한다. 명시적 security_mall.audit 하위11필드만 추가했으며 부모 객체/와일드카드/원문을 새로 요청하지 않는다. 쇼핑몰은 docs/security-audit.md와 Git 상태만 읽기 전용 확인했으며 코드/설정 변경과 실제 로그/HMAC 키/DB 읽기는 하지 않았다.
- 기본 python 명령은 실행 별칭이었고 번들 Python3.12에는 pytest/ES 의존성이 없어 위 OS 임시 폴더의 전용 venv에 프로젝트 고정 버전 서버 의존성과 pytest9.1.1만 준비했다. 저장소 의존성/시스템 환경은 변경하지 않았다. 합성 입력·모의 ES만 사용해 `pytest -q tests/test_security_mall.py tests/test_security_detail.py tests/test_processing.py::ProcessingTests`를 실행한 결과 **122 passed / 7 subtests passed / 0 failed**, 1.97초였다. JUnit에는 하위검사를 포함한129건·failure/error/skip0이 기록됐다. 성공한 시험 재실행·전체 Python/UI/브라우저/Docker/대규모 정적 분석은 하지 않았다. diff 공백 검사도 통과했다.
- 로그인 성공/실패, 관리자7행동 허용/거부, 주문 소유/타인/미존재·비로그인, malformed JSON/중복키/NaN/스키마/시각/식별자/알 수 없는 행동/모순 사유, account null·키 버전 구분, 위조 조직/호스트/다른 ECS 주장·민감 canary 배제, 입력 불변·IPv6 peer 표준화, 원본 참조와 event.id/동일 원본 재처리·다른 원본 참조 보존·create-only409를 확인했다. worker의 실제 필드 목록을 적용하는 모의 조회로 null/키 버전/권한 필드가 누락되지 않는지도 검증했다. 기존 Windows/Linux/네트워크/클라우드 정규화와 상세 allowlist·재처리 계약의 관련 회귀도 통과했다.
- 결과는 `event.id/action/outcome/category`, `service.name`, `source.ip`, `cloud_soc.security_mall`의 schema_version/account_id/account_key_id/resource_type/authorization_reason과 기존 provenance다. 가명을 user.name/범위 없는 user.id로 바꾸지 않는다. 계정 연관은 조직/서비스/키 버전/가명을 함께 사용하고 null·키 교체 계정을 추측해서 합치지 않는다. source.ip는 소켓 peer만 의미하며 권한 허용은 후속 CRUD 성공이나 공격 판정을 뜻하지 않는다.
- 3-B 최소 입력은 `soc-host-raw-*`의 기존 유효 _id/_index, 관리 설정으로 바인딩한 organization.id/host.id/labels.log_source=security_mall_audit, 중앙 event.ingested, 검증 앱 시각과 일치하는 루트 @timestamp, 구조화 객체 security_mall.audit다. JSONL은 최대8192 UTF-8 bytes/중복키 거부 후 앱 허용 필드만 객체로 저장해야 한다. 정규화 시각은 기존 마이크로초 정밀도이며 원래 나노초 문자열은 상세 필드에 보존한다. 서비스/키 버전의 안전한 식별자 형식과 오류 코드는 신규 문서에 명시했다.
- 같은 원본 참조 재처리는 같은 정규화ID/create-only 충돌로 처리한다. 같은 event_id가 다른 원본 참조로 수신되면 근거 참조를 잃지 않도록 별도 문서로 유지한다. 3-B에는 신뢰 수집 범위·회전/재전송·안정적 원본 _id·로그 경로/권한·ES mapping·실제 수집 인수가 남는다. HMAC 비밀키는 정규화에 필요 없다. UI/원본 목록 새 출처 필터 확장은 범위 밖이며 배포·실제 수집 성공으로 표시하지 않는다.
- 기존 탐지 룰/위험도·AWS·UI·Filebeat/ES 배포/인증·운영 DB/상태는 변경하지 않았다. 실제 ES·SSH/원격 서버·push/PR/merge·commit과 3-B 개발은 수행하지 않고 이번 단계에서 중단한다.

- [x] MALL-AUDIT-02 로컬 구현·관련 테스트 완료(2026-10-16): `D:/cloud-soc/state/security-mall`의 기존 1단계 미커밋 변경 전체를 Git 제외 `build/stage2-baseline-5b4f9ee11c7b44b592b81832cf4796e0`에 먼저 보존하고 새 로컬 브랜치 `codex/access-security-audit`에서 추가 구현했다. 관리자 7경로(화면/상품 등록·수정 폼 및 처리/상품 삭제/회원 삭제)에서 세션 사용자 ID로 DB 실제 역할을 재확인한 뒤 처리하며, 주문 조회는 인증→주문 존재→DB 소유자 ID를 확인한 뒤에만 모델을 제공한다. 비로그인/삭제된 세션 계정401·권한 부족/타인 주문403·없는 주문404의 상세 없는 오류를 사용한다. 기존 로거/경로/키/로그인 필드를 재사용하고 권한 이벤트에만 resource_type/authorization_reason을 추가했다. 비로그인 account_id는 null이며 전달 IP 헤더를 신뢰하지 않는다.

2026-10-16 MALL-AUDIT-02 검증/범위 기록:

- 변경 파일은 쇼핑몰의 `src/main/java/com/security/securitymall/controller/HomeController.java`, `src/main/java/com/security/securitymall/audit/LoginAuditLogger.java`, 신규 `src/test/java/com/security/securitymall/AuthorizationAuditTests.java`, `docs/security-audit.md`다. 기존 1단계 로그인 분기와 테스트/프로필/Logback/일반 설정·gitignore를 보존했다. 수정하지 않은 기존 미커밋6파일을 보존 사본과 SHA256 대조해 모두 동일함을 확인했다. Cloud SOC에서는 이 작업 기록만 변경했다.
- 첫 실행은 신규 테스트 도우미가 Spring Test multipart 빌더를 일반 빌더의 하위 타입으로 가정해 컴파일 오류1건으로 중단됐다(테스트 실행 전). 설치된 API 선언을 확인해 공통 추상 빌더 타입으로 해당 도우미만 수정한 뒤 `gradlew.bat test --tests com.security.securitymall.AuthorizationAuditTests --tests com.security.securitymall.LoginAuditTests --console=plain`을 실행했다. 결과: 권한24/기존 로그인5, 합계 **29 passed / 0 failures / 0 errors / 0 skipped**. JDK17은 1단계에 마련한 build/test-tools를 프로세스 JAVA_HOME으로 지정했다.
- 관리자 정상7기능, 일반/비로그인 직접 요청의 모든 보호 경로 거부·flush 후 SQL DB 스냅샷 불변, 요청 role/userId 무시, DB 역할 강등과 삭제된 세션 계정 거부, 소유자 허용·일반/관리자 타인 주문 거부·없는 주문·비로그인을 검증했다. 실제 JSONL 파일 파싱/각 판정1건/필드 허용목록/민감 canary·HMAC 키 원문 부재/관측IP·위조헤더 무시/로그인과 동일 가명도 확인했다. 메모리 H2만 사용했고 파일형 `testdb.mv.db` SHA256은 전후 `B78D56F854F3B98020B4F85A2CF75F2A9C39B77F46D29C28AE7EBD744E133342`로 동일하다. CRLF를 고려한 diff 공백 검사도 통과했다. 성공 후 재실행/전체 테스트/브라우저UI/Docker/추가 대규모 분석은 하지 않았다.
- 감사 event_outcome success/failure는 접근 허용/거부이며 이후 CRUD 자체의 성공을 보장하지 않는다. 기존 login 이벤트의 schema_version1/필드9개/HMAC 계약은 그대로이고 권한 이벤트만 필드2개가 추가된다. 수집기는 resource_type/authorization_reason 및 account_id=null을 수용하고 event_action별 접근 허용/거부를 구분해야 한다. 정책 표와 사유6종(admin/admin_required/owner/not_owner/unauthenticated/not_found)은 대상 문서에 기록했다.
- 완료 범위는 로컬 코드/관련 메모리 DB·MockMvc 검사다. 실제 배포·서버 오류 페이지/파일권한·중앙 수집/정규화는 미검증이다. DB 스키마/기존 파일DB·결제API·Cloud SOC 실행 코드/수집기/위험도/룰·원격 서버·UI는 변경/호출하지 않았고 commit/push/PR/merge나 다음 단계 작업도 수행하지 않았다. 기존 비밀번호 원문 비교 등 범위 외 문제는 1단계 관찰 기록을 유지하며 수정하지 않았다.

- [x] MALL-AUDIT-01 로컬 구현·관련 테스트 완료(2026-10-16): 최신 사용자 요청을 우선하여 `ZIYA0614/security-mall`의 HEAD `aba2b423157cdcb4562fb0eaab3694e379b900e4`를 Git 제외 `D:/cloud-soc/state/security-mall`에 별도 복제하고 로컬 브랜치 `codex/login-security-audit`에서 작업했다. 기존 체크아웃/사용자 변경은 덮어쓰지 않았다. 로그인 성공·실패 각 1건의 UUID/UTC 시각/서비스/행동/결과/소켓 IP/HMAC-SHA256 가명 계정/키 버전 JSON Lines 및 비전파 전용 회전 로그를 구현했다. 외부 필수 Base64 키(32바이트 이상), 전달 IP 헤더 비신뢰, 기존 리다이렉트·세션 유지, 민감 원문 비기록을 확인했다. 변경 파일: 대상 저장소의 `.gitignore`, `HomeController.java`, 신규 `audit/LoginAuditLogger.java`, `application.properties`, 신규 `logback-spring.xml`, 신규 `LoginAuditTests.java`, `SecuritymallApplicationTests.java`의 테스트 프로필, 신규 `application-test.properties`, `docs/security-audit.md`. 빌드 설정·User·DB 스키마·Cloud SOC 실행 코드는 불변이다.

2026-10-16 MALL-AUDIT-01 검증/한계:

- 최초 관련 테스트 실행은 JDK17 미설치로 테스트 시작 전에 실패했다. 공식 Adoptium JDK17을 공개 체크섬 대조 후 대상의 Git 제외 `build/test-tools`에만 준비하고 프로세스 JAVA_HOME으로 지정했다. 시스템 JDK나 프로젝트 toolchain 설정을 변경하지 않았다.
- `gradlew.bat test --tests com.security.securitymall.LoginAuditTests --console=plain`: **5 tests, 0 failures, 0 errors, 0 skipped**. 성공1건·실패1건(잘못된 비밀번호/미등록 계정), 실제 JSON 파일 파싱·필드 허용목록/민감 canary 부재·위조 전달 IP 헤더 무시·동일 계정/다른 계정/로거 재생성 후 가명 상관·키 검증·기존302/세션을 검증했다. 메모리 H2만 사용했으며 `testdb.mv.db` SHA256 `B78D56F854F3B98020B4F85A2CF75F2A9C39B77F46D29C28AE7EBD744E133342`는 변경 전후 동일하다. 기존 CRLF를 고려한 `git -c core.whitespace=cr-at-eol diff --check`도 통과했다. 성공 후 동일 테스트 반복·전체 테스트·대규모 정적 분석·성능/UI 시험은 실행하지 않았다.
- 기본 로그 경로는 실행 디렉터리 기준 `./logs/security-audit.jsonl`이며 환경변수로 절대 경로를 지정할 수 있다. 키 관리·가명 계약·회전·접근 권한·파서/연관 키·파일 오류 시 유실 가능성을 대상 문서에 기록했다. 범위 외 기존 비밀번호 원문 비교/사용자 객체 세션 저장은 관찰만 기록하고 수정하지 않았다.
- 이 완료는 로컬 구현/관련 테스트에 한정한다. 운영 배포·실제 파일 권한/디스크 장애·프록시 실제 배치·중앙 수집/정규화는 미검증이다. 다음 연동에는 절대 로그 경로/수집 계정 읽기 권한·회전 처리·schema_version1 필드 매핑·키 버전/신뢰 프록시 정책이 필요하다. 원격 서버/AWS/운영 서비스 접근·재시작·commit/push/PR/merge는 없으며 다음 단계 개발은 시작하지 않았다.

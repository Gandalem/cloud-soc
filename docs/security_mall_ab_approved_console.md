# 7-A/B 승인된 검증 — 사용자 콘솔 인증

2026-10-17. 사용자가 정확한6개 인덱스의2h 읽기 키 발급·실제 읽기 검증·이번 키 폐기를 승인했다. **인증정보는 VM 콘솔에서 직접 입력하며 Codex에 전달하지 않는다.** 기존 보호된 관리자 암호 파일·Portal/수집 키를 읽거나 재사용하지 않는다.

전용 실행기 `deploy/security-mall/run_validation_console.py`가 기존 `validate_correlation_triage.py`를 subprocess로 실행한다. 엔진/탐지/우선순위 수식은 변경하지 않는다. 사용자명과 비밀번호는 TTY에서 getpass 숨김 입력으로만 받고 파일·명령 인자·환경변수·표준출력에 넣지 않는다. TTY가 없으면 인증 전에 중단한다. 원격 Codex 명령에서 입력하지 말고 **사용자의 VM 콘솔**에서만 실행한다.

실행 순서:

1. manifest와 실제 로딩된 CLI/엔진 경로, 정확한6개 설정, 기존6개 사용자 서비스와 Mall 프로세스를 확인한다. 기존 서비스의 환경/비밀 파일은 읽지 않는다.
2. 사용자 인증으로 `manage_own_api_key` 및6개 read/view_index_metadata를 확인한다. 부족하거나 인증 실패면 발급 전에 중단한다. 권한 변경·기존 키 확대는 없다.
3. 승인된 요청 예시를2h·정확한6개·cluster없음·read/view만으로 대조한 뒤 새 키를 **한 번만** 발급한다. timeout 등으로 생성 결과가 불명확하면 자동 재발급하지 않는다.
4. 응답은 출력하지 않고 VM의 `validation-7ab/secrets/reader-<run>.json`에만 id/encoded/expiration을 저장한다. 디렉터리0700/파일0600·소유자·symlink 차단·exclusive 생성·fsync를 적용한다. 잘못된 기존 권한을 자동 수정하지 않는다.
5. 사용자 인증으로 **이번 새ID의 보안 메타데이터만** 조회해 실제 부여된 역할과 만료를 확인한다. 관리자 인증으로 이벤트를 검색하지 않는다.
6. 신규 읽기 키만 기존 CLI에 전달한다. CA·호스트 검증을 유지하며 자체 권한 조회/6개 허용 권한/범위 제한 검색/원본 대조/실7-A·7-B/격리SQLite revision·원자적 rollback을 실행한다. 기존 사건DB는 열지 않는다.
7. 성공·실패·중단 모두 finally에서 **이번 새ID 하나**만 invalidate한다. 새 키가401로 거부되는지 CA 검증으로 재확인한다. 동일 inode의 새 비밀 파일임을 확인한 뒤에만 제거한다. 폐기·401·파일 식별 중 하나라도 불확실하면 파일을 보호 상태로 남기고 실패를 보고한다. 자동 재발급·일괄 폐기는 없다.
8. 기존 서비스 PID/InvocationID/재시작 횟수·Mall 시작 신원을 전후 대조한다. ES 불변 대조는 읽은 문서의 source/seq/term/version 범위이며 상주 수집의 정상 신규 문서 증가를 손실/변조로 해석하지 않는다.

## 사용자 실행 명령

아래 staging은 코드·합성 테스트·요청 예시만 포함한다. 비밀번호를 붙이지 않는다. `elastic` 등 실제 발급 권한을 가진 **ES 사용자명과 ES 비밀번호**를 숨김 프롬프트에 입력한다. Ubuntu 로그인 비밀번호와 혼동하지 않는다. 인증을 알 수 없으면 중단하며 채팅에 보내지 않는다.

```bash
STAGING=/home/kopo/soc-mall-lab/validation-7ab/ab-final-20261017-82cf09
PYTHONPATH="$STAGING/src" \
 /home/kopo/soc-mall-lab/portal-lab/venv/bin/python \
 "$STAGING/deploy/security-mall/run_validation_console.py" \
 --start 2026-10-16T00:00:00Z --end "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

한 번만 실행하고 결과를 기다린다. API Key/비밀번호/Authorization이나 key JSON을 복사하지 않는다. Codex에는 **실행 완료 여부만** 알리면 생성된 비밀 없는 lifecycle/summary를 읽어 보고할 수 있다.

## 결과와 중단 조건

- 결과는 새 `validation-7ab/approved-<run>/lifecycle.json`, 서비스 전후 메타데이터 및 `results/summary.json`, 격리SQLite다. 원본 ES hits나 비밀 원문을 출력하지 않는다.
- lifecycle 종료0은 기존 CLI 종료0·키 폐기·401·파일 제거·기존 서비스 신원 불변이 모두 확인된 경우다. CLI 종료4는 읽기/부분 분석만 성공한 것이며 전체 통합 완료가 아니다.
- 권한 오류, 증거 해시 불일치, 범위 한도, 엔진 오류 등은 읽기 CLI의 고정 사유와 종료 코드로 남긴다. 권한 확대로 우회하지 않는다.
- 키 폐기가 실패하면 재실행하지 않는다. lifecycle에 `cleanup_failed=true`를 남기고 비밀 파일을0600으로 보존한다. 발급 사용자 인증으로 기록된 **새ID 하나**만 폐기하고401을 확인하는 별도 복구가 필요하다. TTL은2h지만 TTL만 기다린 것을 명시적 폐기 성공이라고 보고하지 않는다.
- 발급 응답이 전송 장애로 불명확하고 새ID를 확보하지 못했으면 `issuance_attempted=true`와 실패 사유를 남긴다. 새 키를 또 발급하지 않고 사용자에게 보고한다.

실제 사용자 입력 전에는 신규 키 발급·실제 ES 읽기·폐기 여부가 전부 미검증이다. 합성 lifecycle 테스트의 성공을 실제 인증/연관 성공으로 대신하지 않는다. Portal UI·7-C 개발·서비스 재시작은 수행하지 않는다.

## 사전 실행 기록

첫 staging(c827b1)의 콘솔 실행은 `mall_identity_unavailable`/종료1로 인증 입력 전에 중단됐으며 `key_issued=false`다. Java의 실제 주소는 `[::ffff:127.0.0.1]:18080`이었고, 정확한 IPv4/IPv4-mapped 루프백만 허용하도록 실행기 사전 확인을 보완했다. `0.0.0.0`, `[::]`, 외부 주소·유사 주소는 계속 거부한다. 키 발급이나 서비스 전환 실패가 아니다.

최종 staging(31bca6)은42파일 SHA 일치, manifest `391171f76a09e24fd9d9317df8d0e048d471d376d84efd96256995f4152f8ad3`, 실제6개 설정·6개 사용자 서비스 실행·Mall PID674554 확인을 통과했다. 합성 수명주기7개와 추가 루프백1개, 고유8개 테스트가 통과했고 정적 진단0이다. 시스템Python에는 기존 ES 라이브러리가 없어 처음의 별도 사전 import가 실패했으며, 문서의 기존venv로만 실행하도록 바로잡았다. 패키지를 설치하거나 서비스/인증 설정을 바꾸지 않았다.

## 실제 사용자 인증 결과 — 통합 미완료

사용자 콘솔 실행 `approved-20261017T100446Z-12914f32`는 UTC2026-10-17 10:04:46(KST19:04:46) 시작, 발급 사용자 자신의 권한 확인 요청에서HTTP401로 종료1/`issuer_authentication_failed`였다. **키 생성 API 호출 전에 중단**돼 신규 키·비밀 파일·CLI 결과·격리SQLite가 생성되지 않았다. 폐기할 신규 키도 없으며 기존 키는 조회/변경/폐기하지 않았다.

실제 인덱스별 이벤트 조회,3종 연관,경보 증거 해시,우선순위 점수,revision·조직 격리는 이번 실제 실행에서 모두 미검증이다. 합성8개 테스트 결과와 구분한다. 입력된 사용자명이 무엇이었는지·비밀번호가 맞았는지·정책상 인증 제한인지 추측하지 않으며 인증정보를 요구하거나 저장된 관리자 암호로 우회하지 않는다.

전후6개 사용자 서비스 PID/InvocationID/NRestarts 등 상태 메타데이터가 같고 Mall PID674554/시작 신원이 일치했다. 기존 서비스/키/DB/ES문서 변경 명령은 실행하지 않았다. 전체 ES문서를 재조회해 바이트 불변을 검사한 것은 아니다. 유효한 발급 사용자 인증을 사용자가 VM 콘솔에서 확인하기 전에는 재실행하지 않는다. 인증정보를 채팅으로 전달하지 않는다.

## Mall 리스너 구조 파싱 사전검증 — 2026-10-17

최신 요청은 주소·프로세스 신원 검사 수정과 새 staging 사전 검사만 허용한다. 위 콘솔 명령은 후속 실제 검증 때 사용자가 별도로 실행하는 명령이며 이번 단계에서는 실행하지 않았다. 사용자가 보고한 CA 검증 상태의 elastic HTTP200도 이번 작업에서 재확인하거나 인증정보를 읽지 않았다.

기존c827b1은 부분 문자열 검사,31bca6은 정확한두문자열 허용 방식이었다. 두 기존파일의 실제SHA와 소스 조건을 대조하고 그대로 보존했다. 새 `mall_listener()`는 ss의 단일 LISTEN 행에서 주소와 포트를 분리하고 `ipaddress.ip_address()`/`IPv6Address.ipv4_mapped`로 정규화한다. 정규화 결과가 정확히127.0.0.1이고 포트18080일 때만 허용한다. 외부·wildcard·순수IPv6·다른127대역·zone·잘못된 주소/포트·혼합/복수행·PID누락/복수PID·ss실패를 거부한다.

`snapshot()`은 /proc/stat의PID와양의시작tick을 확인하며 프로세스가 사라지거나잘못된형식이면실패한다. 기존main의전후스냅샷비교와인증/인덱스/revision/비밀파일보호함수는변경하지않았다. AST대조에서기존함수변경은snapshot하나이며mall_listener만추가됐다.

- Windows 관련5메서드통과·Linux전용1개skip, VM에서그1개통과: 신규4/기존회귀2, 고유6개 모두통과. 모의응답하위32사례를포함한다. 인증·ES·서비스명령은대역으로차단했다. 이전전체테스트는반복하지않았다.
- 변경Python2파일Pyflakes진단0·문법통과다.
- 새staging: `/home/kopo/soc-mall-lab/validation-7ab/mall-listener-20261017-9c1e07`.
- manifest SHA256: `9503834cd80d463efff4dc75fbb77bee6f27689ce11c3e1744d6e9a80ab08ec8`. 파일42개 로컬/VM일치.
- 실제읽기전용snapshot통과: MallPID674554/start4406377·현재UID소유·전후동일·기존6unitactive/running및신원불변. 증거는새staging의 `identity-preflight.json`이다.
- 기존staging/로그/DB/registry/서비스변경없음. 신규키/기존키변경·실ES접속·통합검증미실행. 신원검사수준에서는사용자의별도실제검증재개가가능하나,키권한/증거해시/실제3종연관성공을사전검사에서추정하지않는다.

## e50dd618 실제 실행 종료1 분석 — 2026-10-17

사용자가 실행한 `approved-20261017T102713Z-e50dd618`의 저장 결과만 읽었다. 배포manifest9503834c와42파일SHA가 기존패키지와 일치했고 기존기록은 변경하지 않았다.

- 발급사용자인증/권한·새키발급·실제할당역할대조 성공. 새키폐기·폐기후401·비밀파일제거 성공, cleanup_failed=false다. 기존Portal/수집키를 사용하지 않았다.
- CLI summary는 UTC10:27:44.363761(KST19:27:44.363761), 범위UTC10/16 00:00~10/17 10:27:13, reason=`es_http_error`/exit1/elapsed0.022다. 당시HTTP숫자/실패단계/응답본문은저장하지않아기록에서정확한HTTP코드를복원할수없다.
- 확인된CLI결함은할당role키로최초 `reader_policy()`의`GET /_security/user/_privileges`를호출한것이다. [ES9.5.2 공식코드](https://github.com/elastic/elasticsearch/blob/v9.5.2/x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authz/RBACEngine.java#L699-L724)는이경우명시적으로거부하고GetAPIkey정보사용을안내한다. 실제할당role확인·배포실행순서·조기HTTP오류가이경로와일치한다. 기존응답본문이보존돼있다고주장하지않는다. A~J중J(CLI의권한사전검사API계약오류)에해당하며인덱스권한부족/증거불일치/7-A·7-B엔진오류로판정하지않는다.

| 인덱스 | 이번 검색 결과 |
|---|---|
| soc-host-raw-mall-isolated-continuous-20261017-42062f13 | 검색단계 미진입·건수 미확인 |
| soc-host-raw-mall-edge-isolated-continuous-20261017-42062f13 | 검색단계 미진입·건수 미확인 |
| soc-normalized-mall-continuous-20261017-42062f13 | 검색단계 미진입·건수 미확인 |
| soc-host-raw-mall-isolated-20261016-8a070063 | 검색단계 미진입·건수 미확인 |
| soc-normalized-mall-isolated-20261016-8a070063 | 검색단계 미진입·건수 미확인 |
| soc-mall-alerts-lab-live-20261016-f56deb49 | 검색단계 미진입·건수 미확인 |

결과파일은lifecycle/services-before/services-after/results/summary 네개뿐이며 상관/우선순위SQLite가없다. 원본stdout/stderr는기존wrapper가subprocess메모리에서캡처후저장하지않았다. 확보된앱/웹/WAF/경보자료없음·7-A입력/처리없음·7-B처리없음·revision/증거hash검사미실행이다. 실제인덱스데이터가0건이라고뜻하지않는다. 기존6서비스와Mall674554/start4406377은전후같았다.

로컬최소수정은자기키ID정보의할당역할상한검사와기존_has_privileges유효권한검사조합이다. 다른키/관리자권한으로대체하지않고기존해시/조직scope/revision/위험도알고리즘을보존한다. HTTP오류숫자·고정작업종류·단계·인덱스별조회진행/건수·엔진진입표지만추가했다. 원문예외/서버본문/키/계정식별자를진단에복사하지않는다.

해당실패배포본Reader/policy를시험전용fixture로보존해실CLI경로에서미지원응답을재현했고,수정본은그API를호출하지않는것과과도권한/다른키/만료불일치거부를확인했다. 신규3/관련회귀7고유10메서드·33하위사례가통과했다. summary저장실패단계표시영향1개만추가재확인했다. 변경Python3파일정적진단0이다. 모두합성응답/임시SQLite/로컬subprocess이며실ES검증이아니다.

이번에는새키발급/기존키재사용/ES재조회/실행기재배포/서비스변경을하지않았다. 다음실검증에는수정본으로새패키지·manifest를준비하고사용자의별도실행으로임시읽기키를새로발급해기존읽기검증과폐기를한번수행해야한다. 이미폐기된키는재사용하지않으며쇼핑몰재빌드·로그재수집·이전기능검증반복은필요없다. 전체7-A/B통합은미완료다.

## 최종 실제 ES 통합 검증 완료 — 2026-10-17

결과: `approved-20261017T105455Z-c289b4ba`. 사용자콘솔숨김인증으로발급·실제읽기·분석·폐기를실행했고CLI/lifecycle모두종료0이다. 아래결과는실제ES자료이며이전합성테스트결과를대입하지않았다. 이번수정은구형패키지의CLI1파일갱신과manifest재생성·문서기록뿐이며기존10테스트는반복하지않았다.

패키지 `ab-final-20261017-82cf09`의42파일SHA가일치했다. manifest SHA256 `1d9c04bbf60a47addf1975ced4a8ff773baa5ca0b96c0ae13050a73a2c03a197`, zip `0e6c6da0847eee0b57d02e026b4eaab82868fa4281218200011a8ff5c96c70b3`다. 기준시각2026-10-17 19:55:17.439925 KST, 검색범위UTC[2026-10-16T00:00:00Z,2026-10-17T10:54:54Z),읽기/처리0.503초다.

| 정확한 인덱스 | 검색 | 건수 |
|---|---|---:|
| soc-host-raw-mall-isolated-continuous-20261017-42062f13 | 성공 | 21 |
| soc-host-raw-mall-edge-isolated-continuous-20261017-42062f13 | 성공 | 80 |
| soc-normalized-mall-continuous-20261017-42062f13 | 성공 | 101 |
| soc-host-raw-mall-isolated-20261016-8a070063 | 성공 | 4 |
| soc-normalized-mall-isolated-20261016-8a070063 | 성공 | 4 |
| soc-mall-alerts-lab-live-20261016-f56deb49 | 성공 | 1 |

- **7-A 성공:** 원본105/정규화105의event.id/request_id/주요필드/provenance대조105건통과. 격리ledger는app21/web40/waf40의고유101이벤트와105관측을보존했고중복관측4개를병합했다. 요청묶음53개=3종complete8+incomplete36+ID없는unlinked9,ambiguous0이다. incomplete에는web/WAF만32개가포함된다. 누락증거를생성하지않았다. 같은scope/RID/기존시간창으로연결했고52개미경보관측을새경보/사건으로저장하지않았다.
- **실제경보/해시:** ACCESS1/AUTH0. ACCESS의exact원본·정규화증거와기존경보hash1개일치·미해결0이다. 기존ACCESS경보는과거앱증거여서web/WAF누락·confidence limited/partial이며3종증거로보강됐다고표현하지않는다.
- **7-B 성공:** 조사큐53개저장·재조회. ACCESS의base20/severitylow/risklow유지,triage20/low·독립반복가산0이다. 관측웹증거0은해당경보의검증된하한이며실제요청0건을뜻하지않는다. 추가로그종류에는0점이다. 40개항목이DetectionOnly관측을표시하고WAF차단true·공격성공/출처인증확정표현은0이다. 지연증거표시13항목을보존했다. 수동incident priority·운영사건DB는열지않았다.
- **격리저장검증:** 실제자료를임시SQLite에나눠재생한revision sequence1→2,동일재처리/no-op,구revision/동순번충돌/발행자변경거부·atomicrollback·재개지속성·경보항목ID안정성통과다. foreignprincipal빈결과/조직/site/host/service변조거부도통과했다. summary의12개revision_checks가전부true다. 이는실제자료의격리저장검증이며상주발행자재시작/VM장애시험은아니다.
- **범위/보존:** 모든큐항목의scope가mall-isolated/soc-mall-lab/mall-host-isolated/security-mall로일치하고참조105개에raw/norm이보존됐다. 읽은ES211문서source/seq/term/version재대조불변,기존6user서비스/Mall674554/start4406377전후불변이다. 전체클러스터의모든문서를검사했다고주장하지않는다. 실제다른조직데이터를관리자권한으로조회하지않았다.
- **보안정리성공:** 사용자발급권한·새키할당역할·키자신의역할조회/실유효권한·CA/호스트검증통과. 정확한6개read/view/cluster없음·2h키만사용했다. 검증종료후이번신규ID폐기·신규키401확인·동일inode비밀파일제거성공,cleanup_failed=false이며파일부재를확인했다. 비밀/Authorization/원문/가명계정은결과에출력하지않았다. 기존키·ES문서·서비스설정변경없음이다.
- **미검증:** 실제AUTH60/실제독립반복권한거부가산·모호한ID재사용사례·실제다른조직ES권한부정시험은해당실자료에서검증하지못했다. 기존격리테스트와구분한다. 6-E장애·재부팅·7-C/API/UI는이번범위가아니다. 핵심7-A/B실통합은완료이며기존계약을사용한7-C진행이가능하다.

근거는VM새결과의lifecycle/summary/격리SQLite/readback-evidence.json과Git제외 `state/mall-ab-final-20261017`의비밀없는JSON이다. summary SHA256 `bfec8927070dc20f5e8a5cb51109225fe9428869d0cd2aeb4ef207537ff506fd`, lifecycle `2fd23d6ca35fe290198b96bc5768cace3272f7c6f6a4a5307f7cdb2d4571832c`다. 이완료실행을불필요하게재실행하지않는다.

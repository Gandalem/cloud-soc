# Security Mall 7-C 기존 Portal 조사 연결

> 최신 인수(2026-10-17): 실습 Portal 반영·1회 재시작·실제 Edge 155.0.4283.45 화면/증거 링크/조직·원문 차단 검증 완료. 아래 부분 완료·승인 대기 기록은 이전 상태다. 고정 스냅샷 시연 범위이며 실시간 갱신은 제공하지 않는다.

2026-10-17: 로컬 API·UI 구현 및 관련 검증 완료. 실행 중인 VM Portal에는 배포하지 않았으며 실제 브라우저 화면 인수는 미검증이다. 이 단계 전체 완료를 의미하지 않는다.

## 연결 계약

기존 `GET /api/alerts/detail?id=...`에 Security Mall 규칙만 선택적 `investigation` 요약을 추가했다. 경보 목록, 사건 조사(workbench)의 기존 상세 카드가 공유하는 `mall-alerts.js`를 재사용한다. 새 API·DB·테이블·탐지·사건 생성은 없다. 목록의 위험도와 기존 사건의 수동 priority도 변경하지 않는다.

`investigation.state`는 `available`, `not_found`, `evidence_unavailable`, `unavailable`이다. 결과가 없거나 설정·무결성 검사가 실패해도 기존 경보와 증거 조회는 동작하며 화면은 ‘미확인 · 증거 부족’으로 표시한다. AUTH-001은 기존 표시를 유지한다.

사용 가능한 결과에는 기존 7-B의 triage_score/priority, evidence_confidence, 완전성, 요청 묶음 수, 고유 이벤트 수, 증거 참조 수, 확인·미확인 경보 증거 수, stream 관측 상태, 점수 기여 코드/값, 불확실성, 범위와 correlation_revision을 전달한다. 위험도와 severity는 기존 상세 응답에서 별도로 표시한다. 독립 요청 수는 웹 증거로 확인된 **하한**이며 실제 전체 요청 수가 아니다. 여러 묶음 중 일부에만 스트림이 있으면 그 스트림을 확정 표시하지 않고 미확인으로 남길 수 있다.

화면은 원문 설명을 복사하지 않고 허용된 요인 코드의 고정 문구를 표시한다. HTML은 textContent만 사용한다. request_id는 출처 인증이 아니며 DetectionOnly는 차단 성공이 아니다. 403만으로 WAF 차단을 판단하지 않는다.

## 서버 설정과 읽기 전용 스냅샷

기존 7-A/B 검증에서 생성한 **닫힌** triage.sqlite 결과를 사용한다. 실시간 재계산이나 자동 갱신은 이번 범위가 아니다. 기존 TriageStore 생성자는 쓰기를 수반하므로 호출하지 않는다. 승인된 SHA-256의 파일 바이트를 메모리 SQLite로 읽고 query_only를 적용한다. 운영 SQLite와 ES에는 쓰지 않는다. SQLite deserialize가 가능한 Python/SQLite 빌드가 필요하다(기존 VM Python 3.12 지원).

Portal 서버 설정 `MALL_TRIAGE_SNAPSHOT_FILE` 또는 환경 변수 `SOC_MALL_TRIAGE_SNAPSHOT_FILE`에 다음 JSON 설정 파일의 **절대 경로**를 지정한다. 브라우저가 경로·조직·인덱스·revision을 선택할 수 없다.

```json
{
  "database": "/home/kopo/soc-mall-lab/portal-lab/analysis/triage.sqlite",
  "sha256": "승인된 닫힌 SQLite의 64자리 SHA-256",
  "scope": {
    "organization": "mall-isolated",
    "site": "soc-mall-lab",
    "host": "mall-host-isolated",
    "service": "security-mall",
    "normalized_indices": ["soc-normalized-mall-isolated-20261016-8a070063", "soc-normalized-mall-continuous-20261017-42062f13"],
    "app_indices": ["soc-host-raw-mall-isolated-20261016-8a070063", "soc-host-raw-mall-isolated-continuous-20261017-42062f13"],
    "edge_indices": ["soc-host-raw-mall-edge-isolated-continuous-20261017-42062f13"],
    "alert_indices": ["soc-mall-alerts-lab-live-20261016-f56deb49"],
    "window_seconds": 30,
    "max_events": 10000
  },
  "start": "2026-10-16T00:00:00Z",
  "end": "2026-10-17T10:54:54Z"
}
```

설정·DB 디렉터리 0700, 파일 0600, Portal 사용자 소유로 준비한다. Windows에서는 동일한 비공개 ACL을 적용한다. 심볼릭 링크/reparse point·하드링크·누락·큰 파일·해시 불일치를 거부하며, DB의 scope/정책/frame/publisher/revision을 대조한다. 기존 MALL_LAB_SCOPE의 실제 경보 인덱스와 정확히 일치해야 한다. 이 분석 설정이 기존 Portal 원본 조회 인덱스나 ES 키 권한을 확대하지 않는다. 합성 경보 인덱스를 목록에 추가하지 않는다.

새 revision을 표시하려면 발행자가 정상적으로 저장·종료한 새로운 스냅샷과 해시/범위 설정을 검토해 별도 승인된 Portal 배포 시 반영한다. 실행 중인 ledger를 단순 복사하거나 결과를 최신 실시간 분석이라고 표시하지 않는다. 여기서는 자동 발행 서비스나 새 저장소를 만들지 않았다.

## 접근 통제와 증거

기존 경보 조회의 조직 검사 후 서버가 만든 LogPrincipal로 분석 범위를 다시 검사한다. 현재 경보의 정확한 index/id·규칙·발생 시각·risk/severity·raw/normalized 참조·증거 해시가 스냅샷과 맞아야 한다. 경보의 증거는 기존 Operations.evidence의 조직·해시·원본 identity 검사로 다시 확인한다. 현재 증거가 없거나 바뀌면 분석 점수를 숨긴다. 요청당 증거 25개 초과는 분석 미확인으로 남기며 기존 증거 페이지는 유지한다.

분석 요약은 가명 계정, IP, 원문, 원본 참조 locator를 새로 전달하지 않는다. 원본 링크/열람은 기존 상세 증거 API와 보호 원문 API만 사용한다. 다른 조직은 경보 없음과 동일한 404이며 viewer의 보호 원문 열람은 계속 403이다.

## 검증과 실제 자료

로컬 관련 Python 고유 26건 통과, OS 전용 2건 skip, DOM 10건 통과다. Python에는 상세 API/실제 엔진 스냅샷, 조직/인덱스 파라미터 조작, 원문 권한, 현재 증거 변경, 위험도/severity 변경, scope/site/host/파일 바인딩, 설정 누락/손상 fallback, 비밀 미노출을 포함한다. POSIX 소유권/권한 부정 분기는 Windows에서 모의 metadata로도 검증했다. 실 Linux 파일 권한 및 Windows 심볼릭 링크 생성 검사는 이번 실행에서 미검증이다.

7-A/B 실제 검증 결과 디렉터리 `approved-20261017T105455Z-c289b4ba/results`의 완료된 SQLite 두 파일만 SSH로 로컬 비공개 state에 복사했다. 실제 triage 스냅샷 SHA-256은 `56d461524737f256d74056daad66bb1440fe490f9c2ff3dc4805088d2d79affb`다. 새 어댑터로 실제 저장된 ACCESS 경보 투영·증거 메타데이터를 읽어 20/low, confidence limited, 앱 관측/웹·WAF 미확인, 고유 이벤트 1개/증거 참조 2개를 확인했다. 동일 이벤트의 두 관측 참조를 공격 2건으로 계산하지 않는다. SQLite 해시는 불변이다.

이 검사는 **실제 데이터의 오프라인 재조회**이며 새 ES 검색·7-A/B 통합 재실행 또는 현재 VM Portal의 화면 검증이 아니다. API 테스트의 ES transport와 현재 증거 응답은 격리 대역이다. 실제 AUTH 경보와 현재 실행 Portal의 연결·브라우저 렌더링은 미검증이다.

로컬 근거: Git 제외 `state/security-mall-7c-20261017/actual-snapshot-readback.json`, `snapshot.example.local.json`, pytest 결과. 기존 VM 서비스·키·DB·원본/정규화/경보/사건 문서는 변경하지 않았다. 전체 테스트·배포·서비스 재시작·Git commit/push는 수행하지 않았다.

## 다음 시연 인수

별도 승인된 배포에서 최신 Portal 코드·공유 정적 파일, 검토된 비공개 스냅샷과 설정만 반영한다. 기존 Portal 읽기 키와 CA를 유지하고 추가 권한을 발급하지 않는다. 브라우저에서 기존 ACCESS 목록 1건 → 상세의 기존 risk 20/low와 severity low → 조사 점수 20/low·limited·앱 증거/웹·WAF 부족 → 기존 증거 링크를 확인한다. 결과 미설정 fallback, 타 조직 404, viewer 원문 403 및 AUTH-001 표시도 확인한다. 이 실제 인수 전까지 7-C는 부분 완료다.

## 2026-10-17 실제 반영 사전 확인 — 재시작 승인 대기

실행 Portal은 soc-mall-portal.service active/running, MainPID485310, 시작 UTC04:13:41, localhost18081/login HTTP200이다. 실행 code에는 7-C 어댑터와 correlation/triage 6모듈 및 edge 파서가 없고 기존 app/operations/공유JS도 로컬과 다르다. portal_wsgi.py는 명시적 settings 딕셔너리를 create_app에 넘기며 스냅샷 설정 전달이 없다. 단순 환경 변수 추가만으로 반영되지 않는다. Gunicorn은 reload 설정 없이 Python 코드를 시작 시 로드하므로 파일 교체와 Portal 재시작이 필요하다.

사용자가 요청한 서비스 영향·승인 경계에 따라 실행 파일 교체·WSGI 설정 수정·restart는 수행하지 않았다. 신규 staging `/home/kopo/soc-mall-lab/portal-lab/staging/portal-7c-92309a`에만 최소 코드11파일/스냅샷/설정과 manifest를 준비했다. 13 payload SHA256 일치, manifest SHA256 `54bdf19fcf3e8012acfac89b4155198db644a511c6de58f696b98802f078650f`, Python 문법·기존 venv 실제 import 성공, Linux0600/0700 보호 및 snapshot scope/frame/53개 항목 읽기 성공이다. 스냅샷 SHA는 기존 검증값과 동일하다. 실제 API·브라우저 성공을 뜻하지 않는다. 전체 테스트·ES 재검색·키 변경은 하지 않았다.

다음 승인 범위는 **실습 Portal 한 서비스의 파일 반영 및 1회 정상 재시작**이다. 기존 코드/portal_wsgi.py를 보호 백업하고 staging11파일만 반영하며, WSGI settings에 `MALL_TRIAGE_SNAPSHOT_FILE`로 staging의 snapshot.json 절대 경로를 추가해야 한다. 사용자/세션 비밀·SQLite·ES 읽기 키·CA·조직 정책은 유지한다. 관련 import/해시 확인 후 `systemctl --user restart soc-mall-portal.service`를 수행하고 기존 계정의 ACCESS 상세·원본 링크·타 조직 차단을 실제 브라우저로 확인한다. 예상 영향은 Portal 접속의 짧은 중단이며 다른 서비스와 ES 문서는 변경하지 않는다. 실패하면 Portal 코드/WSGI만 보호 백업으로 복원해 해당 서비스만 복구한다. 현재는 승인 전이라 이 절차를 실행하지 않았고 7-C는 부분 완료로 유지한다.

## 2026-10-17 승인된 최종 반영·실제 인수 결과

- 승인 staging 코드11파일과 보호된 snapshot 설정만 반영했다. 기존 코드/WSGI 복구본은 VM `portal-lab/backups/7c-20261017T112828Z`에 유지한다. WSGI settings에 snapshot 경로만 추가했고 config의 기존 사용자/정책/세션 비밀/ES 읽기 키/CA 파일은 불변이다. 새 키·권한 확대·DB 스키마·탐지/위험도 변경은 없다.
- systemd Portal 한 번 정상 restart(exit0), PID485310→892692, enabled/active/running, /login HTTP200이다. 비교한 다른 user unit PID·시작 시각·상태 및 snapshot SHA는 불변이다. 다른 서비스 재시작·쇼핑몰 배포·ES 문서 변경·로그 재수집은 하지 않았다. 롤백 불필요다.
- 실제 Edge/Playwright에서 기존 mall-analyst 로그인→경보 목록 ACCESS1/AUTH0→상세의 조사20/low·limited·고유이벤트1/증거참조2·앱 관측/웹·WAF 미확인·기존severitylow/risk20low·고정 snapshot 표시를 확인하고 스크린샷을 검토했다. 현재 경보 증거 normalized_hash_verified 및 원본 메타데이터 링크 HTTP200도 확인했다.
- 실제 other-viewer 로그인에서 사건 조사 화면404/빈 경보 영역, 타 조직 경보와 없는 경보의 동일404 응답, 타 조직 원본 메타데이터404, 보호 원문POST403, 조직 파라미터 조작400을 확인했다. 브라우저 pageerror0이며 합성 경보/임의 증거는 추가하지 않았다.
- 인수 스크립트가 기존 버튼명을 ‘조회’로 잘못 지정해 증거 단계에서 한 번 timeout했다. 제품 코드는 변경하지 않았으며 ‘확인’으로 고친 뒤 이미 성공한 목록/점수 검사를 반복하지 않고 증거·권한 단계만 재개해 완료했다. Portal 추가 재시작은 없다. 기존 로컬/전체 테스트도 반복하지 않았다.
- 근거는 Git제외 로컬 `state/security-mall-7c-20261017/acceptance.json`, 최초 도구 실패기록 acceptance-first.json, portal-triage-detail.png·portal-triage-evidence.png·portal-foreign-denied.png이다. 브라우저 연결 도구 초기화 실패 후 이미 설치된 Edge/Playwright를 재사용했고 새 프로그램은 설치하지 않았다. 실제 브라우저 검증을 API 모의 검증으로 대체하지 않았다.
- 7-C 완료는 이 실제 ACCESS 조사 화면과 권한 인수 범위다. 분석은 UTC[2026-10-16T00:00:00Z,2026-10-17T10:54:54Z)의 고정 snapshot이며 최신 자동 분석이 아니다. 기존 전역 수집/처리 상태 일부 ‘미확인’은 최소 읽기3인덱스 범위대로 남겼고 권한을 확대하지 않았다. 실제 AUTH 경보·실시간 발행은 이 단계에서 추가 검증/개발하지 않았다.
- 시연 주소는 Windows SSH 터널의 http://127.0.0.1:18081/operations.html 이다. 기존 실습 계정으로 로그인하고 최근7일→ACCESS 상세를 연다. 터널 PID9540은 로컬 `tunnel.pid`에 기록했으며 실습 localhost로만 연결한다. 비밀번호와 API key는 문서/결과에 기록하지 않았다.

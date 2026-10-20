# 테스트 보강 — TEST-QUALITY-01

2026-10-21, codex/operational-readiness. 기존 규칙·데이터·키·조직/원본 계약을 유지한다.

## 범위

- CI는 prototype/tests/package-lock.json에 따라 npm ci --ignore-scripts로 linkedom을 설치한다. 새 제품 의존성은 없다. 기존 push/PR/manual 트리거와 기존 검사는 삭제/완화하지 않는다.
- Linux 전체 pytest 자동 수집에 새 파일이 포함된다. Windows는 명시 선택 목록에 새 대시보드/보고기 파일을 추가한다. 로컬 제한 검수는 전체 Actions 실행과 별도다.
- test_dashboard_quality.py: precision75/recall60을 포함한 독립 기대값, 각 분모0/0%/100%, 실패·취소·판정불가 제외, 가중치/승인예외 분모와 관측/만료 경계, 정상 CSRF의 viewer 거부와 관리자 성공/잘못된 CSRF/미인증의 상태 불변을 확인한다.
- test_dashboard_query_quality.py: 실제 LogReader query builder/project_list_hit/InsightReader에 모의 원격 응답만 연결한다. 503건을250/250/3으로 나누고 같은 시각·다른 인덱스 같은ID, 정확한 전체 참조/정렬/search_after/PIT 회전·종료를 대조한다. 부분 실패/범위 이탈/중복/정렬 오류/용량 초과는 성공/캐시로 남기지 않는다. 실제 AWS 출처와 cloud 인덱스 계약을 사용하며 supported 판정을 강제로 통과시키지 않는다.
- test_dashboard_device_quality.py: 매 검사에 새 원장/장치/임의 생성 키와 고정 시계를 사용한다. HTTPS 성공, 정확한 조직/장치 연결, duplicate 최초수신시각, 인증/회전/폐기/만료/일시정지, 프록시 신뢰·위조, 시각/순번/내용충돌 및 저장 실패 후 불변·회복을 확인한다. Flask HTTPS 모의 요청을 실제 TLS로 주장하지 않는다.
- test_device_heartbeat_tls.py: 새 RSA 시험 인증서의 loopback HTTPS 서버와 실제 urllib/SSL을 사용한다. 신뢰CA+localhost 성공, 다른CA/호스트 이름 실패와 앱 요청0건, 실패 뒤 순번 보존·재시도, 평문 키의 순번DB/CLI출력 비노출을 확인한다. 장치 서비스 조회만 합성으로 대체하고 기존 서비스는 읽거나 변경하지 않는다. openssl 부재 시 명시 skip이며 실제 TLS 완료로 세지 않는다. 시험 서버 종료·thread join·시험 개인키/인증서 제거를 수행한다.
- dashboard-insights-forms.test.cjs: linkedom에서 장치/정책/평가 폼의 요청 계약·중복 제출·동일 요청identity 재시도·실패 입력 보존·열린 폼 자동갱신 보존·일회성 키 닫기·브라우저 저장 금지를 확인한다. linkedom에는 native constraint validation이 없어 fixture가 required/min/max에 따른 브라우저 제출 gate를 모델링한다. 실제 브라우저의 native validation/레이아웃/E2E 완료를 뜻하지 않는다. 대시보드 위치 이동은 검사하지 않는다.

## 검수 계획과 결과

약50%: 계산/RBAC/조회와 직접 수정한 기존 viewer 검사만 실행한다. 최초37통과/1실패였다. 실패는 신규 시험의 날짜 정렬 기대값을 실제 date sort 계약에 맞춰 수정했다. 합성 AWS의 host index/필수schema도 cloud 인덱스/metadata 계약에 맞추고 강제 supported mock을 제거했다. 영향 조회13검사 최종 통과, 첫 영향 수정 중1통과/1실패 기록도 보존한다. 전체 반복은 하지 않았다.

작성100%: 후반 장치·로컬TLS·폼, 변경 fixture를 공유하는 전반 검사와 기존 직접 영향 검사, 변경 파일의 정적 진단만 수행한다. 실패 시 원인을 분류하고 영향 항목만 재실행한다. 실행 결과는 작업 목록과 Git 제외 state/test-quality에 기록한다.

실제 ES/클라우드/GeoIP·실장치 설치/보고·실습 쇼핑몰 공격·전체 화면/전체 테스트·재부팅·부하/HA·운영 배포는 제외한다. 이 코드의 작성/모의·로컬 통신 검사와 실제 제품 연결을 구분한다. main 병합·자동 커밋/푸시는 별도 요청 전까지 수행하지 않는다.

## 최종 결과 — 2026-10-21

- Python 전반38개/후반35개는 직접 영향 항목이 일부 겹친다. 중간 실패 수정과 영향 재검사를 포함한 고유63항목이 통과했다. 전체 pytest 재실행 수치가 아니다.
- 후반35항목은 실제 loopback TLS의 정상CA/호스트·다른CA·호스트 이름 오류와 CLI비노출4항목을 포함하며 skip0이다. 시험 인증서/개인키를 제거하고 시험 서버 thread를 종료했다.
- Node 최초14항목은11통과/중복 제출3실패였다. 장치 등록과 공통 정책·평가 submit handler가 disabled 버튼 상태를 검사하지 않아 연속 submit event가 두 요청으로 이어졌다. 두 handler에 저장 중 재진입 차단을 추가하고 해당3항목을 재확인해 통과했다. 계정 근거 평가의 정책/조직/KST·만료/항목 근거 전달1항목도 통과해 고유15항목을 확인했다. 테스트 기대값이나 서버 보안 조건을 완화하지 않았다.
- 변경 Python 정적 진단에서 imported fixture 이름과 테스트 인자 사이F811이 발생했다. 명시적 모듈 fixture 바인딩으로 수정 후 영향2파일 진단 통과. 나머지 변경 파일은 최초 진단에서 이슈가 없었다. 제품 JS2파일 구문 통과, 고정 npm ci 설치 통과.
- 기존 미커밋 검토 기록은 보존했다. 새 제품 패키지/운영 설정/기존 키/데이터/DB/큐/체크포인트는 변경하지 않았고 실제 서비스 배포·전체 suite·전체 브라우저·실장치·재부팅 검사는 하지 않았다. 변경폼의 실제 브라우저 동작과 GitHub Actions Linux/Windows 전체 결과는 별도다.
- 사용자의 최신 ‘깃에 테스트 코드 수정’ 요청에 따라 현재 작업 브랜치에 이번 변경을 커밋/푸시하는 범위로 반영한다. 초안의 자동 커밋/푸시 제외는 별도 요청 없는 자동 작업 금지로 유지한다. main 병합과 배포는 하지 않는다. 실제 원격 반영 결과는 Git refs/최종 보고로 확인한다.

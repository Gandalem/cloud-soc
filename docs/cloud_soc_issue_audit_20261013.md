# Cloud SOC 통합 장애 점검·운영 안정화 — 2026-10-13

AUDIT-01 / ISSUE-02 / ISSUE-12 / ISSUE-13. 문제 관리표를 **제품 코드 편집 전에 작성**했고, 초안과 진행 상태는 e301783에 보존했다. 아래는 최종 대조 결과다. 최초 날짜는 가장 이른 확인 가능한 참조일이며 실제 최초 발생일이 확정되지 않은 항목은 표시한다. 과거 다른 VM의 성공을 현재 지정 서버의 성공으로 대체하지 않는다.

분류: **1 해결 및 해당 회귀 통과**, **2 코드/부분 인수 완료·운영 잔여**, **3 미해결 결함**, **4 환경/승인/데이터 제한**. 각 항목의 범위가 다르므로 이 분류를 제품 완성률로 합산하지 않는다.

## A. 현재 시스템 상태

현재 중앙은192.168.32.60이다. 직접 LAN IP에 엄격한 CA·IP 검증을 적용해 무인증401/인증200·HTML과 API를 확인했다. 인증은 Basic/admin이며 실제 세션 다계정/조직 인수는 별도다. 사용자가 거부한 CA 신뢰 등록을 하지 않았고 일반 브라우저 인증서 경고는 남는다. 이번 직접 IAB 탐색은 ERR_CERT_AUTHORITY_INVALID로 중단됐으며 경고 우회/SSL 검증 비활성을 사용하지 않았다. **이번 실제 업무 인수는 HTTPS API, 화면 인수는 합성 루프백 브라우저**로 구분한다.

| 구분 | 확인한 실제 실행/소스 |
| --- | --- |
| PC 기능 브랜치 시작 | codex/dashboard-platform-20261013·79689156315220f26514e06bbd70cfbe39e74b18 |
| 포털 보완 소스 | e301783769b6c07144aa0ffa085f57bd0ef1caca, 개인 대시보드 후속517178d6b7597b32614a1a0ae7e8433d2712fc77 |
| 지정 서버 checkout |92d13c011468ca4f869afc70c63dd61fa3214e12·서버 Git 갱신 없음 |
| 현재 포털 | cloud-soc:audit-517178d6b759·sha256:04daf08f8eaa25d02725e9c52df68424216246b80c844b16075db617760770d2·시작2026-10-13T06:30:56.194398628Z |
| 정규화/탐지 | cloud-soc:early-3b9aff9·sha256:40ed90fb0c524c376cfb8bdda0a2908018f9475f414a8ebd783316f596646c90·컨테이너/시작 시각 유지 |
| 게이트웨이 | LAN 수정 Caddy 유지·sha256:de23def33b17fb5d1290b0f6c2add1d70780e52341896c00a4c8a2a2fe9d355e·이번 재시작 없음 |
| 활성 구성 | deploy/server/compose.yaml + state/early-release-000659f/early.override.json·후속 override SHA25603c75ce809b11b3b71a20313fd05d2d27d6de1cbb4cb0c4eb8234a74f63ac5aec |
| 시작/상태/규칙 | start/SSH 형식 floor=2026-10-13T02:35:47.839670+00:00·checkpoint.sqlite/runtime.sqlite/.early.sqlite 유지·AUTH-001 + early만 활성·900초 최종 유예 유지 |
| 주소 | 포털 LAN HTTPS192.168.32.60·기존 공개 URL 별도·에이전트 HTTPS192.168.32.60:9200 유지 |

이미지의 source label은 전체 Git tree 일치의 증명이 아니다. 이번 복사한 **7개 파일의 실제 이미지 내 SHA256**을 manifest와 대조했다(operations.py·reader_maintenance.py·runtime_audit.py·dashboard.js·shell.js·operations.js·dashboard-builder.js). 나머지는 기존 보호 이미지의 구성이다. CLI2개는 보호 release-ui 소스에 보존하고 실제 runtime CLI를 지정 서버에서 실행해6개 서비스·활성 구성 해시를 확인했다. 전체 main 이미지로 일괄 재배포했다고 기록하지 않는다.

05:39 UTC 읽기 관측에서 원본 host2,994,147/network2,880,839, 최근15분 수신6,020/7,065, 정규화141,884/처리216,541·탐지회차1,867·최종 경보1이었다. 06:21 UTC에는 최근15분 네트워크5,577건·표본100 중 종료 Flow14/필수필드9/정확 정규화 참조9를 확인했다. checkpoint와 성공 시각이 실제로 전진하므로 과거20만건 정체를 현재 장애로 재등록하지 않는다. 제외 누적과 초기 상태는 관측 회차에 따라 변하며 0/실패/평가 제외를 분리한다. 현재 초기 상태 observed, 최종 평가 제외 warning은 유지한다.

ES는 단일 노드 yellow다. **미할당 primary0/replica3**을 실제 cat API로 확인했다. repository[]/path.repo 미설정이며 ES snapshot/독립 복원은 미실행이다. 05:39 UTC soc-* primary store2,316,370,448 bytes, 06:21 UTC2,362,499,143 bytes, 초기 디스크 여유31,683,837,952 bytes였다. 이 짧은 구간의 증가를 장기 보존 용량이나 일일 성장률로 확정하지 않는다.

현재 개인 대시보드는 **2개/revision13**이다. 예전 검증 구성만 있다고 가정하지 않았고 사용자 구성 전체 응답을 적용 전후 대조했다. 비밀번호·개인키·키 값·원문·서버 DB·개인 Word/JSON은 공개 기록/Git에 넣지 않았다.

## B. 해결된 문제 이력과 현재 회귀 관리표

### 원인·기존 수정


| ID | 최초 참조 날짜 | 문제/최초 증상 | 확인된 원인 | 기존 수정/커밋 | 현재 코드 상태 |
| --- | --- | --- | --- | --- | --- |
| FIX-01 |2026-10-13|IP 주소의 빈200·본문0|Caddy 공개 Host만 라우팅|7968915·LAN origin/Host별 Origin|구현·기존789/CI 통과 |
| FIX-02 |2026-10-12|실제 SSH 실패 미정규화|journald/ISO 형식 누락|67dc3bf·linux_ssh_v2|지원 형식 구현 |
| FIX-03 |2026-10-12|실패9/10의 미러를18/20으로 집계|경로별 약1ms 시각차|67dc3bf·제한된5ms/서로 다른 origin|원본 유지·논리 관측 중복 제거 |
| FIX-04 |2026-10-13|정상 publickey 성공 누락|정확한 SHA256 suffix 미지원|3b9aff9·ED25519/RSA/ECDSA 성공만|지문 반환 없음 |
| FIX-05 |2026-10-13|화면 경보가15분 지연|최종900초 유예와 화면 표시 결합|18dabf7/000659f·영속 초기 통지|최종 유예/불변 경보 유지 |
| FIX-06 |2026-10-13|후보 image import 실패|기반 image의cryptography 누락|고정requirements/constraints 후보 보완·서버patch|보완 image 기록 있음 |
| FIX-07 |2026-10-13|Windows 키 인증 거부|현재 관리자 키 파일에 지정 키 없음|같은 승인 키 보호 복원·서버 설정 이력|새 키/정책 변경 없음 |
| FIX-08 |2026-10-12|24시간289버킷 차트 미표시|일반 메타데이터 배열256 상한|51187aa/37f9587·고정 숫자/시각 투영|일반 개인정보 상한 유지 |
| FIX-09 |2026-10-12|20만건 입력에서 완료 위치 정체|회차 읽기 예산 뒤 입력 재개 없음|ee471e6/51187aa·고정 구간 SQLite spool|부분 완료·전체 완료 구분 |
| FIX-10 |2026-10-12|없는 과거 분석 index에서503|명시 부재와 실제 조회 실패 혼동|ee471e6·정확한 index_not_found만no_index|권한/부분 실패 계속 오류 |
| FIX-11 |2026-10-12|과거bootstrap 재실행 뒤403/503|옛 역할 설정이 읽기 범위를 제거|최소 네 이력 read 복원·18dabf7 notice 추가|최신 setup와 실제 역할 대조 필요 |
| FIX-12 |2026-10-12|Basic 서버에서 세션 화면 혼동|실제 인증 모드와 UI 차이|ee471e6/51187aa·인증 모드 안내|Basic/세션 로컬 구현 |
| FIX-13 |2026-10-12|CI·backup·Restricted/fixture 실패|형식/OS 정책/도구 계약 차이|6287688/000659f/7968915 등|현재 시작 CI 성공 |
| FIX-14 |2026-10-12|bridge/실행버전 차이로 통신 혼동|Docker주소/Compose·Git·image drift|이전 VM bridge 복원·현재 보호override|과거 VM와현재 중앙 분리 |

최초 발생일을 별도로 확정하지 못한 FIX-06~14는 해당 날짜의 검증 보고서에서 확인되는 증상으로 분류했다. [SSH 이력](archive/validation/live_auth_validation_20261012.md), [차트 이력](archive/validation/chart_validation_20261012.md), [고객 복구](archive/validation/customer_readiness_20261012.md), [이전 보호 배포](archive/validation/protected_deployment_20261012.md), [현재 초기 통지](early_deployment_validation_20261013.md), [직접 LAN 수정](lan_portal_fix_20261013.md)을 시간순 대조했다.

### 현재 서버·재현·이번 회귀

| ID | 현재 지정 서버 적용/재현 | 이번 회귀·검증 | 미해결/인수 제한 | 우선순위·분류 |
| --- | --- | --- | --- | --- |
| FIX-01 | 직접IP 빈200 재현 안 됨·401/200 정상 | strict CA/IP·Origin 불일치403·LAN 회귀 | CA 경고는 ISSUE-10·현재 직접 브라우저 인수 제한 | 높음/1 |
| FIX-02 | 기존 실제9/10 근거와 고정 floor 유지 | SSHv2/정규화 전체 회귀·실제 근거10 재조회 | 지원형식 한정·범용 PAM 별도 | 높음/1 |
| FIX-03 | 원래 고유9/10/경보0/1 불변 | 중복/재개 회귀·원래 경보 해시 유지 | 모든 수집원 중복 제거의 보장은 아님 | 높음/1 |
| FIX-04 |3b9 worker 유지·Windows 정상 SSH 재접속 | 정상 suffix/경계/개인정보 회귀 | 지정 publickey 알고리즘/형식 한정 | 높음/1 |
| FIX-05 | 원래 통지1 confirmed·원래 경보1/근거10 유지 | 명시02:35~03:20 UTC 조회·재시작 후 동일 참조 | 기존25.894초 단일 실측·지속 SLO 별도 | 높음/1+ISSUE-07 |
| FIX-06 | 보호 base 기반 offline 후보 import 성공 | 네트워크 없는 두 후보 빌드·현재 코드 CI | 새 base 다운로드 재현 별도 | 중간/1+HIST-01 |
| FIX-07 | HP 엄격한 host key 정상 SSH | 두 수집 서비스 Running·정상4624 최근6 관측 |4625 최근7일0·실패/IP 인수 별도 | 높음/1+ISSUE-05 |
| FIX-08 | 홈/개인 구현 유지 | 차트 회귀·3폭/2테마 합성 화면 | 추가 실제 역할·기간 대조 별도 | 중간/1 |
| FIX-09 | 현재 checkpoint 실제 전진·spool 보존 | 부분 재개/대량 조회/체크포인트 전체 회귀 | 현재 큰 부하·VM 재부팅 인수 별도 | 높음/2 |
| FIX-10 | 복원 후 history200/no_index·진짜 인덱스 부재 | 이력 부재/403/부분 실패 회귀·실제 최소 권한 복원 | 없는 이력을 가짜 문서로 채우지 않음 | 중간/1 |
| FIX-11 | 처음 두 이력 권한 누락·503을 실제 재현 | 사용자 승인 exact2 read/view 추가·기존 grant 동일 | 향후 bootstrap 전체 역할 재작성·동시 변경은 운영 검토 필요 | 높음/2 |
| FIX-12 | 현재 Basic/admin 재인증 정상 | 세션/RBAC/CSRF/401·전역조회 guard 회귀 | 실제 일반계정/조직 인수 없음 | 중간/2 |
| FIX-13 | 기존 Windows/Ubuntu CI 성공 유지 | 새818 Python/144 UI·새 소스 CI |19skip·로컬 환경 의존성 제한을 D에 기록 | 중간/1 |
| FIX-14 | 현재6서비스 동일 네트워크·active override 식별 | runtime CLI 실제 실행·portal 외5개 ID/StartedAt 유지 | 과거VM bridge 성공과 분리·재부팅/DR 미검증 | 높음/2 |

### 이번에 실제 보완한 두 문제

재처리 이력503은 인덱스 부재와 별도로 현재 조회 역할의 두 권한이 빠져 생겼다. 정확한 index_not_found 분기는 이미 올바르므로 이를 느슨하게 바꾸지 않았다. 역할을 보호 백업하고 사용자 승인 후 cloud_soc_agent_monitor에 **soc-normalized-history-v1/soc-processing-history-v1의 read/view_index_metadata만 추가**했다. 기존 grant/다른 role fields를 대조했고 사용자·비밀번호·키·인덱스/문서는 변경하지 않았다. 결과200/no_index·rows0이다.

초기 통지 실패 카운터가 있어도 마지막 최종 회차 성공만으로 healthy가 되는 **격리 재현 결함**을 수정했다. 실제 현재 서버에서 같은 실패가 발생했다고 주장하지 않는다. 실패/재대조/미전달/미완료를 제한된 숫자로 투영하고 누락·오류는 미확인으로 표시한다. 최종 장애/정체/지연의 우선순위는 유지했다. 홈·전역 안내·고급 상태·개인 대시보드에 구체적 이유를 표시했다. 새 worker나 규칙을 활성화하지 않고 포털만 적용했다.

## C. 현재 미해결/제한 문제

| ID | 최초 참조·문제/원인·현재 코드 | 이번 실제/격리 결과 | 잔여·필수 조건 | 우선순위·분류 |
| --- | --- | --- | --- | --- |
| ISSUE-01 |2026-10-13·ES 전체복구 없음·백업준비 코드 | repo[]/path.repo 없음·SQLite8 개별 online backup/격리 restore 통과 | 독립 암호화 저장소·snapshot 설정·별도 복원 승인 | 높음/4 |
| ISSUE-02 |2026-10-13·실제 사건0에서 업무 미인수 | 실제 기존 경보→검증 사건→담당/메모/정상 판정/종결→Basic 재인증·포털 재시작 보존 완료 | 직접 browser CA 제한·실제 세션/다조직·전체 장애 복구 별도 | 최우선/1 해당 API 범위 |
| ISSUE-03 |2026-10-13·AWS 감사 수신0·기존 adapter/collector | AWS SSH·Amazon Linux2023·ap-northeast-3·수집 서비스/경로 없음 | 계정 CloudTrail/IAM 읽기와 수집 범위 승인·설치/과금 미실행 | 높음/4 |
| ISSUE-04 |2026-10-13·HTTP 정규화0·기존 HTTP adapter | DVWA 정상GET200·json-file·접근 log 채널/최근30줄의11개 메타 관측·중앙0 | 웹 수집 경로/최소 메타데이터 전송 구성 승인 | 높음/4 |
| ISSUE-05 |2026-10-13·Windows Security IP 결측·기존 adapter | SSH/서비스 정상·4625 최근7일0·정상4624 최근6 | 유효 IpAddress/LogonType 실제 실패 입력 필요·IP 추정 보강 금지 | 높음/4 |
| ISSUE-06 |2026-10-13·신규 opt-in 후보 비활성 | SSH/Windows/HTTP/AWS/Flow 정상·경계·중복 등 전체 격리 회귀·현재 Flow 필드9/참조9 | 후보 field gate/기준·정상 오탐/별도 state 승인 후 활성화 | 중간/2+4 |
| ISSUE-07 |2026-10-13·지속 SLO 미인수 | 기존 실제 단일25.894초 보존·합성1000×3회 인프로세스 측정 | 실제 전체경로 P50/P95·높은부하·장기 계측 별도 | 중간/4 |
| ISSUE-08 |2026-10-13·추가계정/조직 실제인수 없음·기존 RBAC | 전역 이력 admin200·분석가/조회자/타조직403/ES미조회·사건 권한 회귀 | 실제 계정 준비·조직 인수 별도·현재 admin만 | 중간/2+4 |
| ISSUE-09 |2026-10-13·설치/만료 수명주기 부분 | Windows 두 서비스/발견 task Ready·정책 유지·유효 Windows 관련키2개10/14 15:50 KST 만료 | 실제 collector와 키 연결 확인 후 보호 교체 승인·새설치/재부팅 별도 | 긴급 확인/2+4 |
| ISSUE-10 |2026-10-13·사설CA 미신뢰·사용자 신뢰 추가 거부 | CA/IP strict API 성공·CA2036-09-19 만료·브라우저 인증서 오류 | 신뢰 변경 금지 유지·직접 browser 검증 제약 | 중간/4 |
| ISSUE-11 |최초일 미확정·ngrok/Host/endpoint 혼동 | 기존 PUBLIC_URL/agent endpoint 분리 유지·LAN 직접 Origin403 회귀 | 공개 인증/터널 재구성 없이 공개 터널 현재 응답은 미인수 | 중간/4 |
| ISSUE-12 |2026-10-12·Git/image/config 차이 | read-only runtime CLI·strict allowlist·배포 파일7 해시/override/DB/identity 대조 | 전체 checkout/image 동일화·VM 재부팅/다른 서버 적용 별도 | 높음/2 |
| ISSUE-13 |2026-10-12·0/실패/지연 혼동 | early 실패 격리 재현 후 수정·포털 적용·current early observed/제외warning 유지 | 실제 초기 통지 장애 주입은 하지 않음·지속 관측 별도 | 중간/1 해당 보완 |
| ISSUE-14 |2026-10-13·전체 dashboard 인수 부족·format4 | 사용자2개/revision13 응답 동일·SQLite 격리복원·4화면×3폭×2테마 인수 | 모든 위젯/실제 일반역할·팀공유/복구 인수 별도 | 중간/2+4 |
| ISSUE-15 |2026-10-13·기능 main 미병합 | main b67eefa는 현재 기능의 조상·소스517178d 원격 일치 | 승인된 기능 브랜치 push만·main/PR/merge 미실행 | 중간/4 |

### 추가 과거 장애

| ID | 최초 참조·증상/원인 | 기존 보완/이번 회귀 | 현재 잔여·우선순위/분류 |
| --- | --- | --- | --- |
| HIST-01 |2026-10-12·Hub TLS 다운로드 실패 | 현재 보호 base 이용·네트워크 없는 후보 import 성공 | 새 base 확보/새 환경 재현 별도·중간/4 |
| HIST-02 |2026-10-12·Restricted 설치시험 차단 | Windows 실제 CurrentUser RemoteSigned·상위정책 Undefined·전역정책 미변경 | 설치/재부팅 SYSTEM 실인수 별도·생략을 통과로 해석하지 않음·중간/4 |
| HIST-03 |2026-10-12·ES yellow | 실제 primary 미할당0/replica3·정책 유지 | 단일 노드 HA/replica 복구 별도·높음/4 |
| HIST-04 |2026-10-12·상태/메뉴 혼동 | Basic/API 권한·home/개인/고급/사건 합성 화면 회귀 | 실제 추가역할 별도·중간/2 |
| HIST-05 |2026-10-12·미완료 SQLite 저널 | 원래 DB/WAL·spool 보존·8개 backup/격리복원·실제 사건 재시작 보존 | VM 전체 장애·동시 main/early snapshot은 이번에 하지 않음·높음/2 |
| HIST-06 |2026-10-12~13·파서 변경 후 옛 해석 위험 | 고정 start/floor·원래 경보 전체 해시 동일·근거10 같은 raw/normalized 참조 | 전체 재처리 금지 유지·원본의 당시 내용 해시는 소급 확정 불가·높음/2 |
| HIST-07 |2026-10-12~13·도구/fixture/OS 차이 | 아래 실패별 원인·보정·성공·skip 분리 | 도구 실행 실패를 제품/운영 성공으로 바꾸지 않음·중간/1 |

### 실제 사건 업무 인수

시험 사건 `d868e3a5291543adbacdb286e74bae00`은 사용자가 승인한 SSH 통제 시험이다. 기존 실제 AUTH-001 경보를 연결했고 근거10개의 정확한 원본 참조/정규화 해시를 재조회했다. 실제 사용자를 공격하거나 가짜 경보를 삽입하지 않았다.

1. 기존 경보와 조건10건/300초를 대조하고 검증 목적을 제목에 명시해 사건 생성.
2. admin 담당·investigating·근거 검토 메모 저장.
3. 사용자의 **정상 승인 시험 판정·종결** 선택을 기록해 verdict benign/status closed.
4. version5/history5/linked alert1·종결 목록·동일 create 요청 재시도(idempotency)·무인증401/Basic 재인증 대조.
5. 포털의 두 보호 갱신 후 **사건 전체 JSON·메모/이력·근거10개·사용자 대시보드 응답**을 동일 대조.

원래 경보의 SHA256은 `2ad12e5ededdacc807adecb9bc700c892aff08c9cee4eaa7c0e2dd527d1b23d8`로 유지됐다. 초기 통지1개는02:35~03:20 UTC 명시 조회에서 confirmed다. 기본 최근1시간의0건은 현재 필터 결과이며 소실이 아니다. 탐지 시점의 원본 본문 해시가 없는 과거 근거는 **원본 참조와 정규화 해시만 검증**하며 당시 원본 내용 불변성을 소급 확정하지 않는다. 시험 사건은 감사 기록으로 남기고 삭제하지 않는다.

### 보호·복구 준비와 미실행 조건

현재 보호 자료는 서버 state/audit-stability-20261013 아래에 있다. 최초8 SQLite는 개별 online backup/integrity/메모리 격리 restore가 통과했다. 서로 다른 DB의 동시 snapshot으로 과장하지 않는다. 그 뒤 새 사건을 포함해 portal DB5개·키/CA·활성 override·현재 이미지 archive를 각 적용 전에 새 디렉터리에 보호했다. 최종 보호 디렉터리는 **portal-before-ui-followup**이며 당시 e301 포털 이미지 archive59,200,512 bytes와 case1/history5를 포함한다. 최초 cases0 백업을 현재 포털의 rollback에 덮어쓰지 않는다.

포털 rollback은 다른 설정이 변하지 않았는지 먼저 대조한 뒤 **portal image만 cloud-soc:audit-e301783769b6**으로 바꾸고 동일 env/base/active override로 `up -d --no-deps --no-build portal`을 수행하는 범위다. DB/queue/WAL은 현재 값을 유지한다. 최초 LAN 기준은 cloud-soc:lan-131166bdfc08/e6620235…이며 두 단계의 보호 이미지/manifest를 남겼다. ES/Kibana/worker/gateway 또는 전체 Compose를 재기동하지 않는다. 이번 rollback 실행은 필요 없어 하지 않았다.

전체 ES 복구안은 **독립 암호화 저장소·접근권한·보존7일 일간/4주 주간**을 초안으로 검토하고, 저장 용량/증가율을 충분한 기간 측정한 뒤 확정한다. RPO24시간/RTO4시간은 제안 목표이며 측정 결과가 아니다. 파일시스템 repository는 mount/path.repo와 노드 재시작이 필요하므로 별도 승인 대상이다. 실제 snapshot 성공·실패 shard0·격리 동일 버전 restore·문서/매핑/근거 수·복구 시각을 확인해야 ISSUE-01을 완료할 수 있다. SQLite/Compose/이미지 보관이나 ES 볼륨 복사로 전체 ES 복구를 대체하지 않는다. [Elastic snapshot 지침](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore), [파일시스템 repository 설정](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/fs-repository-settings).

### AWS·웹·Windows·신규 후보 후속안

AWS13.208.175.237에서 ec2-user SSH·Amazon Linux2023·IMDSv2의 리전ap-northeast-3/계정 메타 존재만 확인했다. AWS 자격 증명 문서는 읽지 않았고 계정 CloudTrail/IAM API 상태는 미확인이다. DVWA는 sagikazarmark/dvwa·Docker json-file·Apache access/error regular 경로였고 마지막30개 container log 줄에서 접근 메타11개(GET9/POST2,2009/3022)를 관측했다. 정상 GET의 최종200만 확인했으며 공격 요청을 실행하지 않았다. 센서 서비스7개/기존 config 경로는 없고 중앙 AWS/HTTP 정규화는0이다. CloudTrail 자체가 없다고 결론내리지 않는다.

AWS 감사 후속은 기존 `src/cloud_soc/aws/cloudtrail.py`와 `deploy/aws/collector.example.json`/lookup-policy.example.json의 허용 계정·리전·조회 범위를 검토한다. 최초 경로는 승인된 reader의 **LookupEvents 관리 이벤트**이며 동일 eventID·checkpoint·create-only 전송을 인수한다. 90일 이벤트 이력은 리전별 관리 이벤트 범위이므로 EC2 SSH/웹 요청 및 모든 data event를 대신하지 못한다. collector/publisher 역할은 분리하고 원문 requestParameters·responseElements·인증 토큰을 출력하지 않는다. 지속 S3 trail/CloudWatch/data event/agent 설치나 IAM 변경은 필요·보존·비용 범위를 따로 승인받아 실행한다. [AWS 이벤트 이력](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html), [LookupEvents CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html).

웹 수집안은 기존 HTTP adapter에 맞춰 timestamp/source IP/method/허용 status/path 분류만 전송한다. query 문자열·cookie·Authorization·POST 본문은 수집하지 않고 중앙 TLS/호스트·전용 publisher key·중복 identity/정규화 참조를 대조한다. 기존 Apache/container log를 회전·삭제하거나 stdout FIFO를 무한 읽지 않는다. 중앙 수신0이므로 HTTP 후보의 실제 탐지 성공으로 표시하지 않는다.

Windows192.168.1.138 HP의 SSH·두 수집 서비스 Running·Cloud-SOC-Discovery Ready·CurrentUser RemoteSigned를 확인했고 정책/작업/키는 바꾸지 않았다. Security4625 최근7일 표본0이며 최근15분4624는6개였다. 기존4624의 IpAddress 결측에 다른 OpenSSH IP를 넣지 않는다. 다음 field gate는 원래4625의 IpAddress/TargetUserName/LogonType/host/org/time이며 RDP후보는 LogonType10을 요구한다. 승인된 존재하지 않는 시험 계정·정상/경계/실패 단계가 준비될 때만 실행한다.

유효한 Windows metrics host/network 이름의 키 두 개는 **2026-10-14T06:50:23Z(15:50 KST)**에 만료한다. 현재 실제 collector와의 연결은 확정하지 못했으므로 즉시 실제 설치 식별/보호 receipt와 대조하는 것이 필요하다. 교체가 필요하면 기존 패키지/endpoint/CA/org를 보존한 후보키와 rollback을 준비해 별도 승인 후 한 수집기씩 새 수신을 인수한다. old key 폐기/새 키 발급을 자동으로 하지 않았다.

새 cardinality/sequence/attack/metadata 후보는 계속 비활성이다. Flow9개 실제 field/provenance 충족은 portscan 발생이나 규칙 성공이 아니다. 각 후보는 threshold-1/threshold/정상·중복·다른 host/org·시간 경계·cooldown·재시작·누락 필드가 갖춰진 별도 state와 위험 승인에서만 활성화한다. 기존 AUTH/early state와 최종900초 유예를 재사용/초기화하지 않는다.

지속 SLO안은 source→receipt→normalized→early index→UI와 final frontier를 따로 계측하고, 공통 시각/ES refresh/수집·정규화·탐지·화면 주기와 backlog를 기록한다. 정상/높은 부하를 승인된 재생 데이터로 단계적으로 비교하고 P50/P95·실패·누락·중복을 보고한다. 이번 인프로세스 합성 benchmark나 기존 한 번의25.894초 화면 측정은 실제 장기 SLO/최대 부하 보증이 아니다.

## D. 이번 테스트 결과

| 범위 | 최종 결과 | 실제 범위/제한 |
| --- | --- | --- |
| 전체 Python | **818 passed/19 skipped/257 subtests passed·99.05초** | 기존 state/pr3-review-venv·새 Python 소스 e301 이후 불변 |
| 전체 UI | **144 passed/0 failed** | 개인 대시보드 후속517178d 포함 |
| Ruff/Bandit/diff | 통과·Bandit 중간/높음 발견0 | 기존 nosec 불필요 경고는 결과와 별도 |
| 새 읽기 도구 | runtime9+reader6 회귀 통과·runtime CLI 실제 실행 | credential/unknown argv/DLS-FLS/stale review 방어·계정/key 변경 없음 |
| API 권한 회귀 | reprocessing scope4+history19=23 passed | 진짜 세션 guard·admin만 전역 조회·타역할 ES 미조회 |
| 상태·관련 회귀 | early visibility10 포함 관련74 passed/3 subtests | 수정 전 신규9 실패/1 통과로 격리 재현·실제 장애 주입 안 함 |
| 실제 중앙 | strict TLS API·사건/메모/판정/목록/재인증·포털 두 갱신 보존·proof10/해시 | Basic/admin·공개 인증 전송 없음·타5서비스 불변 |
| 브라우저 | **4화면×1440/768/390×light/dark=24조합·JS 예외0·가로 overflow0** | 합성 session/login·실제 JS·early 실패 주입·고의 notices503 표시·직접 실제 browser는 CA 제약 |
| 합성 benchmark |1000 events/3회·중앙값 합계0.620963초/약1610 events/s | AWS StopLogging 인프로세스·network/ES/index/UI 제외·실제 처리량 아님 |
| SQLite | 최초8개 개별 backup/격리restore·매 portal 적용 전5개 추가 보호 | 동시 main/early snapshot/전체ES/외부DR 인수 아님 |
| 현재 source CI | e301783/517178d 모두 성공·E의 실제 run 참조 | Windows/Ubuntu 실제 runner·clean pinned dependency 단계 |

19 skips: Linux root/private-state5, Docker opt-in3, Windows POSIX 권한3, Caddy binary opt-in4, AWS SDK1/OCI SDK3이다. 생략을 성공으로 기록하지 않는다. 로컬 기존 검증 venv의 pip check는 부가 selenium/typing-extensions 버전 불일치로 실패했다. 이 환경을 덮어쓰거나 사용자 설치를 변경하지 않았으며 프로젝트의 clean pinned 환경은 원격 CI의 별도 설치/호환 단계로 확인한다.

실패/보정 이력: 최초 보호 helper의 HeadApiResponse JSON 직렬화는 bool 변환 후 기존 백업을 재사용했다. 사건 생성 응답을201로 잘못 기대한 도구는 API의200 계약에 맞추고 같은 idempotency key로 재사용해 중복 사건을 만들지 않았다. 전역 history 누출을 추정한 exploratory fixture는 실제 before_request403을 확인한 뒤 경계 회귀로 교정했고 권한 코드를 느슨하게 바꾸지 않았다. 권한 복원 후 ES의 기본 allow_restricted_indices:false를 exact dict와 비교한 검증 실패는 읽기 대조로 해소했으며 역할을 재작성하지 않았다. 중간 UI142/143의1 실패는 generic warning 문구 계약 변경을 반영하고 초기 통지 원인 회귀를 추가해144/144로 통과했다. 브라우저 대기 문구/개인 dashboard 경로의 오류는 현재 DOM을 대조하고 개인 화면의 구체적 원인 표시를 보완한 뒤24조합을 인수했다.

재개 직후 잘못 선택한 .venv/전역 Python은 pytest 또는 Flask/Werkzeug 누락으로 수집 실패했고 기존 검증용 venv를 확인해 전체 검사를 통과했다. AWS cmd.exe 인용 오류는 PowerShell stdin 전달로 바로잡아 같은 읽기 점검을 완료했다. 이들을 제품 장애나 최종 통과 수에 포함하지 않는다.

## E. Git 결과

- 기능 브랜치: codex/dashboard-platform-20261013.
- 소스/회귀/초안: e301783769b6c07144aa0ffa085f57bd0ef1caca·일반 push 완료·[CI 성공](https://github.com/Gandalem/cloud-soc/actions/runs/38355451048).
- 개인 대시보드 후속:517178d6b7597b32614a1a0ae7e8433d2712fc77·일반 push 완료·[후속 Windows/Ubuntu CI 성공](https://github.com/Gandalem/cloud-soc/actions/runs/38356790377).
- main b67eefa5f5b1af72bb76dc59e2181727ccc6c0ef는 소스517178d의 조상이며 당시9커밋 차이였다. 현재 branch origin SHA는 일치했다. 실제 merge/PR/main/force push는 하지 않았다.
- 최종 보고/runbook/tracker 정리는 별도 문서 커밋으로 같은 브랜치에 보존한다. 실제 적용 이미지의 소스는517178d이며 이후 문서 커밋과 구분한다.
- 개인 Word2개/JSON의 시작 해시를 대조했고 공개 stage에서 제외했다. 비밀/state/output/원문/서버 DB/인증 자료를 stage하지 않았다.

## F. 다음 작업 우선순위

1. **Windows 키 만료의 실제 설치 연결 확인**:10/14 15:50 KST 전에 해당 키를 쓰는 collector인지 확인하고 보호 교체가 필요하면 후보/rollback과 승인 범위를 확정한다. 새 만료 관측으로 일반 후속보다 우선하는 읽기 점검이며 기존 P0~P7 완료 수는 바꾸지 않는다.
2. **ISSUE-01 독립 백업/복구**: 저장소·권한·측정 RPO/RTO를 정하고 승인된 snapshot/격리 복원으로 ES까지 인수한다. 현재 same-VM 보호를 DR 완료로 부르지 않는다.
3. **ISSUE-05/03/04 실제 필드·수집 경로**: Windows4625/IP·AWS 계정/리전/관리 이벤트 reader·DVWA 최소 접근 메타 전송을 승인된 범위에서 순서대로 인수한다.
4. **ISSUE-06/07/08/09/14**: 후보별 정상/반례와 별도 state·지속 SLO·실제 다계정/조직·설치/재부팅/모든 widget을 인수한다.
5. **ISSUE-15 병합 검토**: 기능/실제 실행/보호 자료가 준비된 뒤 사용자의 별도 main/PR 승인에서 진행한다.

기존11/24 완료 기준·P2-02 보류·날짜별 이력은 유지했다. 이 작업의 실제 API 사건 인수와 부분 보호 적용을 전체 Cloud SOC 운영 완성으로 표시하지 않는다.

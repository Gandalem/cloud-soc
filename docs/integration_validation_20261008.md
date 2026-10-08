# main / JEONGRIM 기능 통합 검증 — 2026-10-08

## 기존 JEONGRIM-SEO 병합 후속

사용자가 통합 커밋 `935f9b2e3e3bb3bc3913f6507252ed88504be459`를 직접 생성하고, 기존 `JEONGRIM-SEO`의 `091a19484b07e3335460164e00d6952771cd52d9`에서 `--no-ff --no-commit` 병합을 실행했다. 원격 정림 HEAD는 최초 비교 기준과 같았다. 아래 INT-01의 '커밋 없음'과 '로컬 미커밋'은 그때의 검증 이력이며 이후 사용자 커밋을 취소하거나 부정하는 의미가 아니다.

후속 병합에서는 18개 충돌을 검토했다. 보안·세션·History·UI·수집기 시험의 충돌은 이미 양쪽 기능을 합쳐 검증한 통합 커밋의 내용을 유지했다. `app.py`/`privacy.py`는 조직 접근제어·보호 원본 감사·마스킹·세션 권한을 보존했고, 자동 병합된 `Dockerfile`도 통합 검증본과 동일하다. 단일 미통합 main/정림 파일로 덮어쓰거나 `--ours`/`--theirs` 일괄 선택을 하지 않았다.

`.env.example`와 `.gitignore`의 같은 안내/제외 패턴 중복만 제거했다. README는 main 설치·보안 안내와 기존 정림 포트폴리오 안내를 함께 보존하고 과거 측정/CI 기록을 현재 결과와 구분했다. 작업 목록은 양쪽 이력을 모두 남겼다. 기존 정림의 포트폴리오 이미지·과거 patch·설치 보조 도구는 삭제하지 않았다. 현재 실행 경로·설정·의존성·테스트(`src`, `tests`, `prototype`, `deploy`, `rules`, `.github`, requirements/constraints/pyproject, Compose)는 통합 커밋과 동일하다. 기존 설치 보조 도구는 이번 검증 중 실행하지 않았다.

충돌 해결 후 전체 pytest는 471 통과/7 skip/168 subtest 통과, 화면 Node는 94 통과, 수집기 Node는 100 통과/1 Linux 전용 skip/실패 0, Ruff 및 전체 staged whitespace 검사는 통과했다. 새 증거는 `../../jeongrim-merge-pytest.log`, `../../jeongrim-merge-pytest.xml`, `../../jeongrim-merge-ui.log`, `../../jeongrim-merge-ruff.log`, `../../jeongrim-merge-agents.log`에 보존한다. staged 실행 경로와 통합 커밋의 차이는 0이고, unmerged 항목도 0이다. 병합 부모·tree·공개 증거 해시는 `../../jeongrim-merge-evidence.json`, 병합 변경은 `../../jeongrim-merge-changes.patch`에 기록한다. 이번 후속에서는 Docker/TLS ES/Edge를 새로 실행하지 않았고, 같은 실행 코드에 대한 INT-01의 실제 실행 증거를 참조한다. 원격 CI·운영 배포·원격 main 변경은 수행하지 않았다. 병합 커밋과 push는 사용자가 수행한다.

## 범위와 브랜치 상태

- 대상: `integration/main-jeongrim-features-20261008`의 로컬 작업 트리.
- 최초 원격 비교는 main과 동일(`ahead=0`, `behind=0`, 변경 파일 0)이었다. 실제 통합은 없었다.
- 기준 main/통합 HEAD: `d670fb385fa3dfe4ca271ffad4be4439a156ca57`.
- 정림 기준: `091a19484b07e3335460164e00d6952771cd52d9`, 공통 조상 `cb329e4dd092a8278b638d742a3fdd40f920957a`.
- main과 정림은 12 ahead / 5 behind로 분기되어 있었다. 공통 조상을 이용한 3방향 내용 통합 후 인증·마스킹 충돌을 직접 해결했다.
- main 직접 수정, 새 커밋, push, 운영 배포는 수행하지 않았다. 따라서 원격 통합 브랜치는 아직 main과 동일하며, 아래 검증은 로컬 미커밋 변경에 대한 결과다.

## 기능별 통합

| 기능 | 반영 및 보존 내용 |
| --- | --- |
| Detection / Pipeline | 임계값·시퀀스·클라우드 규칙, 안정적인 경보 ID/create-only 저장, 증거 중복 제거, 증분 상태/체크포인트/이력 outbox, 설명 가능한 위험도, 처리 CLI 및 관측 지표 |
| Linux Parser | 기존 SSH와 명시적 시간대 처리 유지; sudo/PAM, systemd, 컨테이너 런타임, 커널·데스크톱·네트워크 서비스, access 로그의 선별 정규화; 미지원/잘못된 입력의 별도 처리 기록 |
| History | 탐지 실행/제외 이력의 규칙·시간·종류 필터와 seek paging; 재처리 메타데이터 이력 및 상태/검색/페이지 API; 화면의 필터·페이지·정확한 원본 참조 |
| Security | main 조직 제한 reader, 계정/범위별 커서, 보호 필드 원본 조회·고정 사유·감사 성공 후 반환, 감사 실패 차단, URI/비밀 옵션/숨김 문자 마스킹 보존; 정림 세션 로그인·CSRF·역할 권한과 구조화 마스킹 추가 |
| CI / UI | pytest/Ruff/Node/이미지 빌드 구성, 통합 브랜치 push 대상, Node 런타임 설정, Windows 수집기 시험 순차 실행; 로그인·실행/재처리 이력·위험도/근거 화면 연결 |

`app.py`는 main의 Basic 인증 및 조직별 보호 조회를 유지한다. 세션 계정도 같은 로그 정책을 따른다. 정책이 있는 비관리자는 전역 이력/경보/사건으로 우회할 수 없고, 조직 정책이 없는 비관리자 세션에 전체 ES 로그 권한을 부여하지 않는다. 세션 역할과 로그 정책 역할이 충돌하면 시작을 거부한다. Basic 미인증 요청의 기존 401 응답을 보존했다.

`privacy.py`는 main의 일반 URI·명령 옵션·제어/숨김 문자 필터와 정림의 추가 민감 키·비파괴 재귀 마스킹을 합쳤다. `Dockerfile`은 main의 UID 1000, 공개 파일 권한 정규화, 민감 요청 정보를 배제한 Gunicorn 로그를 유지하며 고정 의존성과 규칙 파일을 추가했다.

포트폴리오 이미지/과거 평가 결과, 이미 생성된 patch 아카이브, 자기 수정형 설치 보조 도구, VS Code 개인 설정은 기능 통합 대상으로 복사하지 않았다. main README 및 기존 작업 완료 이력은 보존했다.

## 실제 실행 결과

| 검증 | 결과 | 근거 |
| --- | --- | --- |
| pytest 전체 / Windows Python 3.12 | 471 통과, 7 건너뜀, 168 subtest 통과 | `../../pytest-final.log`, `../../pytest-final.xml` |
| Ruff `src tests tools` 및 diff whitespace | 통과 | `../../ruff-final.log`, 최종 `git diff --check` exit 0 |
| 화면 Node | 94/94 통과 | `../../node-ui-final.log` |
| 수집기 Node 전체 | 100 통과, 1 건너뜀, 실패 0 | `../../node-agents-final.log` |
| 수집기 PowerShell 전체 문법 | 통과 | `../../powershell-parse-final.log` |
| 실제 Docker 이미지 빌드 | 통과; UID 1000, network none/read-only import 및 6개 규칙 프로필 로드 통과 | `../../docker-build.log`, `../../docker-image.txt`, `../../docker-runtime.log` |
| 실제 TLS Elasticsearch 9.5.2 / HTTP API | 26개 검사 통과 | `../../live-complete.json`, `../../live-complete.log` |
| 실제 Edge UI / API | 통과, JavaScript 예외 0, API 실패 0 | `../../browser-evidence.json`, `../../browser-complete.log` |
| Bandit medium/high | 통과; 기존 nosec 주석 경고만 있음 | `../../bandit.log` |
| pip dependency audit | 알려진 취약점 없음 | `../../pip-audit-final.log` |
| 오프라인 규칙 프로필 | AUTH, AWS, OCI, sequence 6개 유효 | `../../offline-rules.log` |

pytest의 7 skip은 Linux root 파일시스템 전용 5개, 기존 선택적 Docker/ES 현황 검증 1개, POSIX 설정 파일 권한 검증 1개다. 선택적 기존 ES 시험의 skip을 통과로 세지 않았다. 별도로 아래의 실제 TLS ES 저장·권한·HTTP/브라우저 연동 시험을 수행했다. GitHub Actions 원격 실행, Ubuntu 전용 coverage 및 Compose config 검사는 이번 로컬 결과로 통과를 주장하지 않는다.

수집기 Node의 1 skip은 Linux flock 기반 갱신 시험이다. Git Bash에서 가짜 flock으로 성공시키지 않고 Linux 전용으로 구분했다. 로컬 Node는 24.19.0이고 CI 설정은 22이므로 CI 런타임 자체의 통과를 주장하지 않는다. 최종 이미지 ID는 `sha256:0fcb72fa1737f6c0d4d0b588c90ae7a699680bf6c30f7e864a162458dc5528dd`이며 사용자 설정은 `1000:1000`이다.

## 실제 저장·보안·이력 증거

임시 Docker 데몬과 폐기 가능한 전용 ES 클러스터에서 합성 자료만 사용했다. Windows/WSL 로컬 경로로 연결했고 CA 및 호스트/IP 검증을 유지했다. 운영 서버, AWS/OCI 실제 API, 기존 에이전트·키·큐·실제 로그에 접속하지 않았다.

- raw 16건: auth.log SSH 10건, syslog 파일의 systemd 1건, sudo/컨테이너 런타임 운영 로그 2건, 잘못된 시간대 1건, 잘못된/미지원 형식 1건, 타 조직 1건.
- 실제 정규화 저장 14건, invalid 1 / unsupported 1은 원본 참조와 고정 사유(`ssh_time_invalid`, `adapter_not_supported`)를 별도 처리 기록에 보존했다. 민감 본문은 정규화/격리 기록에 포함하지 않았다.
- 같은 자료 재처리 후 정규화 문서 수는 14건으로 유지했다. 탐지 첫 실행 created=1, 재실행 existing=1, 실제 경보 문서 1건 유지. 위험도 65/high이며 설명 요소의 합과 일치했다.
- 실제 normalizer API key의 원본 쓰기/경보 쓰기/정규화 덮어쓰기 3개 동작, detector API key의 경보 덮어쓰기/원본 쓰기 2개 동작은 403으로 거부되었다.
- 조직 제한 로그 조회는 자기 조직 15건만 반환했다. 타 조직 보호 원본 조회 404, viewer 보호 원본 조회 403, investigator 허용 조회 200 및 본문 canary 비노출. 감사 DB 3행을 실제 조회했다.
- 감사 테이블을 검증 중 일시 이용 불가능하게 했을 때 503이며 source 반환이 없었고, 이후 테이블을 복구했다. 세션 CSRF 없이 원본 조회도 403이었다.
- 실제 증분 처리의 evaluated/committed 이력을 저장하고 AUTH-001 필터·limit=1·다음 seek를 HTTP로 대조했다. 조직 제한 계정의 전역 이력 접근은 403이었다.
- 재처리 화면 시험용 메타데이터 57건을 실제 ES에 저장했다. 서버 partial 검색 53건을 50/3 페이지로 중복·누락 없이 대조했고, 실제 Edge는 전체 50/7·partial 50/3·빈 검색·검색 초기화·정확한 원본 상세를 확인했다. 이 57건은 페이지 검증용 복사본이며 실제 과거 로그 57건을 운영 재처리했다는 뜻이 아니다.
- desktop 및 390px 모바일 화면 증거: `../../ui-detection-history.png`, `../../ui-reprocessing-mobile.png`.

## 발견한 실패와 보완

1. 작업 환경의 sandbox 실행기가 볼륨 열거에서 실패했다. 승인된 로컬 실행으로 검사·검증을 수행했다. 동기화된 `sources/`는 수정하지 않았다.
2. 최초 Python 의존성 설치 시 아직 패치를 적용하기 전이라 constraints 파일이 없었다. 통합 후 고정 의존성 설치 및 pip check를 다시 수행했다.
3. 최초 pytest는 Windows 스크립트 정책 때문에 2건 실패했다. 시험 자식 프로세스에서만 RemoteSigned를 사용했고 저장된 실행 정책을 변경하지 않았다.
4. 전체 pytest에서 시험 로그가 사용자 프로필의 금지 경로 아래에 있던 3건과, 병합 인증의 401/403 순서 회귀 1건을 발견했다. 시험 경로를 시스템 임시 경로로 바꾸고 Basic 인증 순서를 복구한 뒤 전체 471개를 재검증했다. CI가 새로 발견한 기존 불필요 import도 제거했다.
5. Docker 명령이 없어 최초 빌드 시도는 실행 환경 오류였다. 공식 static Docker를 임시 WSL 디렉터리에 기동해 실제 빌드/실행을 수행했다. 시스템 Docker 서비스는 설치하지 않았다.
6. ES는 Windows 마운트의 777 password 파일 권한으로 첫 기동에 실패했다. 임시 Linux 디렉터리에 권한을 제한한 인증 자료를 두었다. Windows→WSL loopback 연결 실패는 전용 로컬 WSL 주소와 해당 IP SAN을 사용해 해결했다.
7. 실제 검증 도구의 지연 허용값 0 및 미래 합성 실행 시각 때문에 두 시도가 실패했다. 유효한 60초와 최근 조회 범위에 들어가는 합성 시각으로 보완했다. 초기 실패 JSON/log를 그대로 보존했다.
8. 실제 Edge에서 검색 후 상세 클릭이 동작하지 않았다. input 이후 blur/change가 같은 필터로 표를 재생성해 클릭 대상을 제거한 것이 원인이었다. 같은 필터면 재생성하지 않도록 수정하고 회귀 1개 추가·전체 화면 94개·실제 브라우저를 다시 검증했다.
9. 수집기 병렬 시험의 공유 설치 mutex 충돌, 사용자 프로필 금지 경로, 네이티브 합성 시험 경로 및 junction 정리 권한 실패를 발견했다. 시험 순차 실행·허용된 합성 경로·검증된 junction의 비재귀 정리를 보완했다. 이후 PowerShell Remove-Item의 심볼릭 링크 판별이 Windows Temp 접근 권한 때문에 실패했다. 절대 경로·부모·이름 검사를 유지하고 junction을 먼저 제거한 뒤 .NET Directory.Delete로 합성 폴더만 정리했다. 단독 시험과 전체 100개를 다시 통과했다. 이전 `node-agents-final-verified.log`의 99 통과/1 실패/1 skip을 최종 성공 기록으로 오인하지 않는다.
10. 검증 venv의 기본 pip 24.0이 dependency audit에서 검출되었다. 제품 CI와 동일한 pip 26.2.1로 맞춘 뒤 알려진 취약점 없음으로 재검증했다. 취약점을 ignore하거나 검사 대상을 제외하지 않았다.
11. 최종 재빌드 첫 호출은 WSL 기본 사용자에게 임시 Docker 소켓 권한이 없어 실패했다. 데몬을 시작한 임시 root 실행으로 재호출해 최종 빌드와 비관리자 이미지 실행을 통과했다. 소켓을 공개하거나 시스템 사용자의 Docker 권한을 늘리지 않았다.
12. 추적 중인 파일만 검사한 초기 diff 검사는 통과했으나, 미추적 추가 파일까지 포함한 전체 패치 검사에서 Python 3개 파일의 끝 빈 줄을 발견했다. 정리 후 전체 pytest 471개, Ruff, 이미지 빌드/실행을 다시 검증하고 전체 패치 whitespace 검사도 통과했다. `../../docker-final-confirmation.log`에 마지막 빌드 및 임시 데몬 종료를 함께 기록했다.

## 재현과 제한

로컬 기본 검증: `python -m pytest -q`, `python -m ruff check src tests tools`, `node --test prototype/tests/*.test.cjs`, `node --test --test-concurrency=1 deploy/agents/tests/*.test.cjs`, `docker build -f deploy/server/Dockerfile -t cloud-soc:integration-check .`.

실제 저장 검증은 `tools/validate_integration.py`의 CA/password/output 인자를 사용한다. 검증 전용 클러스터 이름을 확인하며 `--reset`은 그 클러스터에서만 시험 인덱스를 초기화한다. `--serve-seconds`로 임시 화면 서버를 유지한 뒤 Playwright가 있는 환경에서 `node tools/validate_ui.cjs <증거 폴더>`를 실행한다. 비밀번호·키·정책 파일은 시험 산출물 폴더의 비공개 자료이며 Git 변경에 포함하지 않는다.

이번 결과는 기능 통합의 로컬 회귀와 합성 자료의 실제 저장/HTTP/브라우저 검증이다. 운영 배포, 실제 Filebeat/Packetbeat 송신, 과거 운영 자료 재처리, 무손실 보장, ES DLS/외부 변조 방지 감사, 대규모 성능, 원격 CI 실행 및 main 반영을 완료한 것으로 해석하지 않는다.

## 전달 및 정리

전체 로컬 변경은 `../../integration-changes.patch`로 전달하고, 파일별 SHA-256 및 공개 시험 증거 해시는 `../../validation-evidence.json`에 기록한다. 실제 Git index에는 stage하지 않았고 커밋·push하지 않았다. 마지막 원격 확인에서도 main과 원격 integration은 최초 기준 HEAD와 같았다.

검증 도구의 임시 API key 3개를 무효화하고 HTTP 서버를 종료했다. 검증 전용 ES 컨테이너와 해당 임시 Docker 데몬만 종료했으며, 설치된 서비스는 변경하지 않았다. 정리 결과는 `../../cleanup.log`에 보존했다. 화면 증거·로그·시험용 합성 상태는 동기화 참조 디렉터리 밖의 작업 공간에 남겨 두었다.

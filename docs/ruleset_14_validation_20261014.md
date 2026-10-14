# 전체 14개 탐지 룰 검증 — 2026-10-14

14개 룰을 기존 엔진에 등록해 전체 격리 실행, 정확한 근거, 재시작 복구와 포털 연동을 검증했다. 중앙 `192.168.32.60`의 운영 룰은 기존 AUTH-001과 그 초기 통지를 유지한다. 이번 새 소스는 운영 배포하지 않았으며 데이터·상태 DB·체크포인트·경보·서버 권한을 변경하지 않았다. 아래 실환경 관측과 합성 인수를 구분한다.

## 룰별 결과

전 룰 **구현 완료·로컬 인수 통과·격리 활성화**다. 각 룰에 정상/조건 충족/직전 임계값/시간 경계/중복/누락·조직 분리/쿨다운 또는 단일 이벤트 독립성/새 Python 프로세스 복구/저장 실패 재시도/근거 해시·참조/Flask API/사건 판정·재시작/저장 대시보드 검사가 있다. 조건과 메타데이터가 같은 정상 관리 활동은 오탐 후보로 명시하며 공격 성공으로 판정하지 않는다.

실제 로그 열은 **이번 지정 중앙의 최근 30일**(조회 2026-10-14 10:42 KST, 소스별 정규화 표본 최대 100개) 관측이다. Windows 수집 자체가 실패 시나리오의 필수 정보 확보를 뜻하지 않는다. AWS 호스트의 웹 로그를 CloudTrail로 분류하지 않는다.

| Rule ID | 구현·로컬 | 실제 로그 수집 | 실제 서버 탐지 검증 | 운영 활성화·사유 | 초기 통지·대시보드 연동 | 남은 문제 |
| --- | --- | --- | --- | --- | --- | --- |
| AUTH-001 | 완료·통과 | SSH 256건; 기존 실제 실패 근거 10개 | 이전 실제 9/10 인수 유지; 이번 10개 정확 근거 재평가의 경보 ID 동일 | 활성 유지 | 초기→확정 회귀 통과; 실제 기존 경보·격리 화면 확인 | 지속 SLO·새 코드 운영 갱신은 별도 |
| AUTH-SEQ-001 | 완료·통과 | SSH 성공/실패 소스 있음 | 실제 실패 5회→성공 전체 조건 미시험 | 미활성; 정상·경계·오탐 실환경 인수 전 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 정상 재시도와 침해 구분 |
| AUTH-SPRAY-001 | 완료·통과 | SSH 소스 있음 | 실제 계정 4개·실패 10회 미시험 | 미활성; 실제 다계정 인수 전 | 초기 대상 아님; 같은 입력의 AUTH-001 초기 회귀 및 최종 격리 통과 | NAT·관리 자동화 오탐 |
| ATTACK-01 | 완료·통과 | SSH 256건·sudo 51건 | 실제 전체 공격 순서 미시험 | 미활성; 실제 연쇄 인수 전 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 동일 SSH 세션·권한 상승 성공 미확정 |
| ATTACK-02 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 정상 인벤토리 기준선 |
| ATTACK-03 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 변경 승인·다른 Trail 영향 |
| AWS-IAM-001 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 승인된 관리자 변경과 구분 |
| AWS-AUDIT-001 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 실제 감사 수집 영향 |
| AWS-NETWORK-001 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 실제 라우팅·노출 별도 확인 |
| OCI-IAM-001 | 완료·통과 | OCI 감사 0건 | 실환경 미검증 | 미활성; 감사 수집 없음 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 정책 내용·권한 영향 |
| WIN-AUTH-001 | 완료·통과 | Windows 인증 89건; 표본 중 평가 불가 5건 | 실제 실패 10회 전체 조건 미시험 | YAML 비활성; 필수 source IP/logon type 인수 미완료 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 4625·출발지·실제 로그온 유형; RDP 추정 금지 |
| WEB-404-001 | 완료·통과 | 기존 실제 웹 5건; 404 조건 일치 0건 | 실제 404 20회 미시험 | YAML 비활성; 실제 경계·크롤러 오탐 인수 전 | 초기 대상 아님; DVWA/통합 사이트 어댑터·최종 격리 통과 | 정상 크롤러·잘못된 링크; 취약점 종류 미판정 |
| NET-PORT-001 | 완료·통과 | 네트워크 220,094건; 표본 종료 Flow 조건 일치 11건·평가 불가 1건 | 실제 15종 포트 전체 조건 미시험 | YAML 비활성; 종료 Flow·정상/경계 인수 전 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 종료 시각은 연결 시도 시각이 아님 |
| AWS-CONSOLE-001 | 완료·통과 | CloudTrail 0건 | 실환경 미검증 | YAML 비활성; 콘솔 감사/실행 주체 미확보 | 초기 대상 아님; 최종/사건/대시보드 격리 통과 | 명시 principal/ARN·MFA/잠금 오탐 |

‘조건 일치 입력’은 개별 이벤트의 적격 여부이며 경보나 공격 성공 건수가 아니다. 소스 존재·서비스 실행만으로 위험 시나리오를 인수하지 않는다. 미수집·미검증은 공격 부재와 다르다.

## 보완한 구현

- 고정 14개 카탈로그와 명시 `--isolated-all`을 추가했다. 파일의 비활성 후보를 private copy에서만 켜며 기본 AUTH와 네 후보의 YAML 비활성을 유지한다. CLI의 실제 쓰기는 명시 loopback HTTPS ES와 기본 상태 파일과 다른 경로가 필요하다. CA 검증은 필수다. 프로필 충돌·잘못된/중복 ID·비활성 후보의 일반 선택은 연결 전에 거부한다.
- `--rules AUTH-SEQ-001` 같은 개별 선택은 활성 정의 중 검토된 룰만 선택한다. 항상 기존 AUTH-001을 첫 룰로 유지해 초기 통지가 다른 룰에 적용되지 않는다. 이 옵션 자체가 운영 인수나 승인 기록을 대신하지 않는다.
- 기존 엔진을 재사용했다. 같은 raw 참조의 재전송/정규화 버전과 AWS event ID를 중복 집계하지 않는다. SSH 실패→성공·sudo 상관 탐지에서도 journald/ISO 파일 미러를 한 번 센다. ATTACK-01에 실제 Ubuntu `linux_ssh_v2`를 연결하고 WEB-404에 DVWA `web_access_metadata_v1`과 통합 사이트 `web_access_agent_v1`를 연결했다.
- 빈/마스킹 그룹·잘못된 IP·bool 임계값·시간/쿨다운을 거부한다. 시간 창 끝은 포함하며 순서 탐지의 선행 시각은 엄격히 이전이어야 한다. 새 프로필/룰 정의는 기존 상태 identity와 맞지 않으면 거부한다. AUTH 정의·기존 정상 입력의 경보 ID·기본 상태 identity는 유지한다.
- 실행 기록에 해당 소스 관측 수와 `unverified / not_evaluable / evaluated`를 저장한다. 경보 0건을 안전으로 표시하지 않는다. 포털은 허용된 상태/사유만 투영하며 입력 없는 접힌 이력에도 ‘미검증’을 표시한다. 단일 실행의 평가 완료가 전체 실환경 검증을 의미하지 않는다. 새 assessment는 비색인 object이며 기존 dynamic:false 이력 `_source`와 호환한다.
- 최종 경보의 위험도·시각·사유·스냅샷·raw/normalized 정확 참조·해시, 조직 권한과 보호 상세를 유지한다. 초기 통지는 AUTH-001에만 해당한다. 다른 룰의 초기 통지 확장은 이번에 만들지 않았다.

## 재현과 검증

선언된 `requirements-dev.txt`/`constraints.txt`만 설치한 Git 제외 venv에서 전체 Python **1,042 passed / 15 skipped / 257 subtests passed**(144.84초), UI **147 passed**, Ruff 통과, Bandit 중간/높음 0, pip check 통과다. 소스 실행에는 `PYTHONPATH=src`가 필요하다. 전체 룰 격리 검사는 `tests/test_ruleset_complete.py`·`tests/test_ruleset_integration.py`이며 Windows Actions에도 추가했다.

추가 의존성 취약점 검사는 새 venv의 bootstrap pip 24.3.1만 지적했다. 기존 CI와 같은 pip 26.2.1로 맞춘 뒤 pip-audit ‘No known vulnerabilities found’·pip check 통과다. 마지막 스키마/정규화 상태 경로 보호·CLI 관련150 Python/7subtests도 통과했으며 전체 수에 중복 합산하지 않는다.

```powershell
$env:PYTHONPATH='src'
python -m cloud_soc.detection --isolated-all
python -m pytest -q tests/test_ruleset_complete.py tests/test_ruleset_integration.py
python -m pytest -q
node --test prototype/tests/*.test.cjs
python -m ruff check src tests tools
python -m bandit -r src -ll -q
```

합성 ES IO + 실제 정규화 어댑터/엔진/SQLite/새 Python 인터프리터/Flask API로 전체 룰을 동시에 켜고 14종 경보를 생성했다. 경보 저장 장애 시 체크포인트 유지·재시도·기존 create-only 문서 불변과 모든 근거의 normalized hash 검증을 인수했다. 각각의 경보에서 사건 생성→메모/정상 승인 시험 판정·종결→앱 재생성 후 보존 및 개인 대시보드 구성을 확인했다. 실제 ES 클러스터 장애 주입/모든 위험 룰의 실서버 공격 시나리오는 별도다.

`tests/preview_ruleset.py`는 localhost 전용 합성 브라우저 재현기이며 운영/배포 진입점이 아니다. Playwright CLI로 1440/768/390px × light/dark × 대시보드/이력 **12조합**, 14종 경보 제목·정확한 UI 상태·JS/HTTP 오류 0·document 가로 넘침 0을 확인했다. 화면은 `output/playwright/ruleset-14-20261014/`에 Git 제외 보관한다.

초기 검증에서 과거 SSH 시험이 동일 raw ID를 10회 반복하면서 ‘서로 다른 시도’로 간주했던 잘못된 fixture를 발견했다. 서로 다른 raw ID 10개는 탐지하고 같은 참조 재전송은 탐지 횟수를 늘리지 않는 시험으로 보완했다. 기존 도구 venv의 무관한 Selenium 의존성 충돌은 프로젝트 의존성을 변경하지 않고 깨끗한 venv로 구분했다. 브라우저 합성 응답의 템플릿 형식/미지원 로그 위젯과 ID 대신 제목을 표시하는 UI·접힌 이력의 검사 기준도 실제 계약에 맞춰 보정했다.

## 운영 활성화와 남은 범위

현재 운영에서 새 13개 룰을 켜지 않았다. 이번 실제 확인은 기존 메타데이터 조회·AUTH 근거 로컬 재평가다. 운영 DB 복사·초기화·체크포인트 되감기·경보 삭제·새 공격/설치/키/권한 변경을 하지 않았다. API/원문/개인키/비밀번호·운영 DB·개인 Word/JSON은 커밋에서 제외한다.

각 룰을 활성화하기 전에 해당 실제 소스의 필수 scope·시각·고유 식별자·정규화 참조를 확인하고 승인된 시험 환경에서 정상·조건 직전/충족·오탐·재시작을 인수해야 한다. 변경 전 상태/이미지를 보호하고 기존 상태 identity를 임의로 수정하지 않는다. 새로운 선택은 새 명시 상태 경로/시작 범위가 필요하며 기존 DB를 지우거나 과거 start로 무조건 재처리하는 방법을 쓰지 않는다. 지원 필드가 없는 룰은 계속 비활성/미검증으로 둔다.

SQLi/XSS/명령 주입/경로 탐색은 이번 14개에 포함되지 않으며 HTTP404만으로 이를 주장하지 않는다. 실제 공격 귀속·지속 SLO·장기 보존·ES 독립 복구·추가 실계정 운영 인수는 남아 있다.

## Git

변경26파일: `.github/workflows/ci.yaml`; `docs/{README.md,work_tracker.md,ruleset_14_validation_20261014.md}`; `prototype/{detection-history.js,tests/detection-history.test.cjs}`; `rules/{attacks.yml,metadata_patterns.yml}`; `src/cloud_soc/detection/{__main__.py,behavior.py,engine.py,incremental.py,profiles.py,registry.py,rule_loader.py,sequence.py,telemetry.py,worker.py}`; `src/cloud_soc/{portal/detection_history.py,processing/setup.py,runtime_audit.py}`; `tests/{preview_ruleset.py,ruleset_fixtures.py,test_linux_ssh_live_formats.py,test_ruleset_complete.py,test_ruleset_integration.py}`.

요청한 `codex/dashboard-platform-20261013`을 기존33db896에서 d49a4af까지 fast-forward해 최근 설치기/폼 수정·이력을 보존한 뒤 구현 **a1125fec0f3b14fa7b5633487df928878b0d523b**를 일반 push했다. main은 eec0717를 유지했다. force push·PR 생성/자동 병합은 하지 않았다.

[GitHub Actions45](https://github.com/Gandalem/cloud-soc/actions/runs/38498674935)의 **Windows2025·Ubuntu24.04 모두 success**를 공식 API로 확인했다. Ubuntu전체1,041 passed/18skip/255subtests, statement coverage90.1%, UI147, pip-audit·이미지빌드·게이트웨이4passed/18subtests도 통과했다. 로컬Windows의1,042/15skip/257subtests와 OS별 조건 차이를 구분하며 수치를 합산하지 않는다. 마지막 완료/CI 기록은 이 두 문서만 별도 commit/push([skip ci])한다. 검증된 구현 소스는 변경하지 않는다.

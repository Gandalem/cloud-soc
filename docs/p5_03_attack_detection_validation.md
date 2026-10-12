# P5-03 공격 탐지 검증 기록

2026-10-12 / 브랜치 `pack` / 미커밋 로컬 변경.

## 결과와 한계

5개 시나리오 명세와 구현 가능한 3개 규칙의 로컬·격리 Elasticsearch 검증을 완료했다.
Ubuntu/Windows 기존 수집기의 실제 중앙 수신도 읽기 전용으로 확인했다.
**P5-03 전체는 미완료**다. 신규 규칙의 운영 배포·실제 공격 시나리오·AWS 실제 수신·
운영 임계값 승인은 남았으며 웹 2개는 필수 관측 데이터 부족으로 실행 규칙을 만들지 않았다.
기본 탐지는 AUTH-001 그대로다. 새 규칙은 `--include-attacks`를 명시해야 선택된다.
이번에 운영 서비스/Compose/기존 SQLite/기존 ES 자료를 변경하거나 원격 Git에 올리지 않았다.

| 규칙 | 조건/예상 경보 | 검증 수준 |
| --- | --- | --- |
| ATTACK-01 | 같은 조직·호스트·계정·IP의 SSH 실패 5건/300초→성공→600초 이내 root(uid=0) 대상 PAM sudo 세션 / SSH 인증 공격 이후 권한 관련 활동 의심 | 공개 로그 형식 기반 합성·보호 필터·정규화·탐지·SQLite 검증. 동일 SSH 세션/권한 상승 성공은 미확정 |
| ATTACK-02 | 조직·계정·principal ID·ARN의 명시 API 20건/300초 AND API 종류 4개 / AWS 비정상 API 열거 및 정찰 의심 | 실제 projection/normalize 경유 합성 검증. 실제 계정 유입·userAgent·정상 활동 기준선 미검증/미지원 |
| ATTACK-03 | 같은 조직·계정·principal ID·ARN의 고권한 정책 연결 성공→900초 이내 Trail 중지/삭제 성공 / AWS 권한 변경 이후 감사 기능 비활성화 의심 | 실제 projection/normalize 경유 합성 검증. 실제 유효 권한·모든 감사 제거·정확한 자격 증명 세션 미확정 |
| ATTACK-04 | 웹 SQLi 신호+요청 참조 필요 | 명세만 완료. 400/500이나 접속 횟수로 가짜 SQLi 경보를 만들지 않음 |
| ATTACK-05 | 웹 신호→서비스·안정 프로세스/요청 연결 필요 | 명세만 완료. 프로세스·PID·시간 근접만으로 실행 공격을 추정하지 않음 |

정확한 필드·출처·그룹·창·제외·판정 한계는 [시나리오 명세](p5_03_attack_scenarios.md)에 있다.

## 자료와 실행 환경

- Windows, Python 3.13.2, Node 22.20.0. 프로젝트 CI의 Python 3.12 Ubuntu/Windows 실행은
  미실행이며 CI 설정에 신규 시험/프로필 검증만 추가했다.
- 기존 격리 시험 환경 `state/pr3-review-venv`를 재사용했다. `.venv`에는 pytest가 없어
  최초 전체 unittest 실행의 pytest 의존 모듈 3개가 import 실패했다. 시험 환경을 바꾼 뒤
  최종 pytest 전체가 통과했다. 설치/전역 Python/PowerShell 정책/프로젝트 의존성 변경 없음.
- `tests/fixtures/cloudtrail_management.json`의 합성 Management 이벤트를 시간·ID·API별로
  변형해 기존 CloudTrail project_event와 normalize를 실제 호출한다. 실 AWS 계정 데이터가 아니다.
- SSH는 지원 RFC3164 공개 형식, sudo는 Linux-PAM 공개 소스의 session-open 형식에 맞춘
  합성 문자열이다. `host.id`는 시험 입력이 제공하고 이름/IP로 생성하지 않는다.
- Node는 **변경하지 않은** `deploy/agents/privacy.js`를 실행해 SSH/PAM 메시지가 보존되고
  `PWD=`가 있는 명령 로그와 canary/인자가 마스킹됨을 검사한다. 개인정보 정책 완화 없음.
- 최초 로컬 시험의 ES는 Mock이며 실제 normalizer/engine/alert/API/SQLite 코드를 실행한다.
  실제 보관 문서의 존재·최소 ES 권한·라이브 근거 조회·현장 탐지율 증명이 아니다.

## 실제 명령과 결과

다른 개발 PC에는 `requirements-dev.txt`와 `constraints.txt`에 맞는 시험 환경을 별도로 준비한다.
아래 `$Python`은 이번 PC의 이미 준비된 환경이다.

```powershell
$env:PYTHONPATH = 'src;tests'
$Python = '.\state\pr3-review-venv\Scripts\python.exe'
& $Python -m pytest -q -rs
& $Python -m ruff check src tests tools
& $Python -m bandit -r src -ll -q
& $Python -m cloud_soc.detection --include-cloud --include-sequence --include-attacks
node --test prototype/tests/*.test.cjs
node --test --test-concurrency=1 deploy/agents/tests/*.test.cjs
node --test deploy/agents/tests/privacy.test.cjs
git diff --check
```

| 검사 | 실제 결과 |
| --- | --- |
| 최종 전체 Python (PAM 어댑터 포함) | 591 passed, 14 skipped, 242 subtests passed, 48.00초 |
| 웹 UI 전체 (최종 PAM 표시 포함) | 101 passed, 0 failed |
| 기존 에이전트 직렬 전체 (새 PAM 시험 추가 전, 제품 에이전트 코드는 불변) | 101 passed, 1 skipped, 0 failed, 약 249초 |
| 새 PAM 보존 시험을 포함한 privacy 파일 재검증 | 7 passed, 0 failed |
| Ruff / Bandit 중간·높음 | 통과. Bandit의 기존 nosec 관련 경고는 존재하며 검사 실패는 아님 |
| 프로필 오프라인 검사 | 기본 1개, 모든 선택 옵션 9개 유효, 연결/쓰기 없음 |
| diff 검사 | 통과, 일부 기존 파일의 CRLF 변환 안내만 있음 |
| 최초 로컬 단계의 브라우저·Docker·실제 ES·AWS | 미실행. 아래 후속 검증에서 브라우저·격리 ES 및 기존 VM 수신을 별도로 확인 |

Python 생략 14개: Linux root 파일시스템 5, POSIX 권한 2, opt-in Docker ES 3,
선택 boto3 SDK 계약 1, 선택 OCI SDK 계약 3. OCI 실제 환경이 없어 추가 연결을 시도하지 않았다.
에이전트 전체의 1개 생략은 Linux 건강 보고 파일시스템 시험이다.

## 2026-10-12 후속 검증

### 기존 VM의 중앙 수신

기존 CA·호스트 검증과 출발지 제한 SSH 키로 접속했다. 운영 컨테이너의 monitor 읽기
권한으로 최근 15분 문서 수와 마지막 수신 시각만 조회했다. 원문·인증정보는 출력하지 않았다.

2026-10-12 10:20:21 KST 표본:

| 대상 | 호스트 로그 | 네트워크 문서 | 건강 보고 | 마지막 네트워크 수신 (KST) |
| --- | ---: | ---: | ---: | --- |
| Ubuntu VM | 288 | 7,360 | 13 | 10:20:14 |
| Windows VM | 195 | 2,329 | 15 | 10:20:16 |

두 VM의 Filebeat·Packetbeat가 실행 중이고, 건강 보고의 두 수집기 통계 상태는 observed다.
위 숫자는 조회 구간의 저장 문서 수다. 공격 횟수·패킷 수·전체 무손실 수집 증명이 아니다.
Windows host.name은 소문자로 수신되어 대소문자를 맞춘 정확 일치 조건으로 재조회했다.
초기 대문자 이름의 0건을 오프라인이나 수집 장애로 판정하지 않았다.

Windows Packetbeat의 최근 파일에서 연결 거절/재연결 오류를 확인했다. 마지막 오류 표본은
09:41:14 KST이며 이후 중앙 수신은 확인됐다. Filebeat scanner 경고는 10:27:07 KST에도
있어 원인/소스 영향 확인이 남는다. 오류가 사라졌거나 모든 로그가 수신된다고 주장하지 않는다.
수집기·설정·키·큐·예약작업·정책은 변경하지 않았다.

중앙의 soc-normalized-v1와 soc-pipeline-status는 존재하고 security-alerts는 NotFoundError다.
인덱스 존재만으로 처리기가 실행된다고 판단하지 않는다. 새 탐지 프로필의 운영 실행은 미검증이다.

### 격리된 실제 Elasticsearch

Ubuntu의 기존 캐시 ES 9.5.2 이미지와 portal 이미지 ID를 재사용했다. 새 내부 전용 Docker
네트워크와 시험 컨테이너를 만들고 포트·운영 볼륨을 공유하지 않았다. ES의 HTTP는 이 격리망
안에서만 사용하며 기존 서버 TLS 설정은 바꾸지 않았다. 원본은 공개 형식의 합성 자료 29건이다.

- 실제 normalizer bulk·매핑·create-only 처리: 정규화 29건, 재실행 증가 없음.
- 신규 ATTACK-01/02/03과 기존 AUTH-SEQ-001/AWS-IAM-001/AWS-AUDIT-001 경보 총 6건.
- 별도 Python 프로세스의 SQLite 재시작, 새 상태 재처리, snapshot 재실행에서 신규 중복 0건.
- 실제 ES 쓰기 권한 거절 때 체크포인트 미확정, 정상 권한 재시도 후 기존 경보 6건 재사용.
- normalizer/detector/monitor의 금지 작업과 다른 조직의 경보 조회를 차단.
- 실제 근거 참조·정규화 해시 일치, 시험 문서 변조 시 mismatch, 시험 원본 삭제 시 없음/만료 표시.

시험 컨테이너·네트워크·임시 파일을 제거했고 기존 4개 운영 컨테이너의 ID/시작 시각/
실행 상태/재시작 횟수는 불변이었다. 합성 자료의 실제 ES 검증이며 운영 공격 탐지 증명이 아니다.

재현 도구: tools/verify_p5_disposable.py, tests/p5_03_live_checks.py.
도구는 root·명시적 --run·공개 아카이브 SHA-256·여유 자원을 검사한다.
시험 클라이언트는 고정 격리 주소와 무작위 시험 클러스터 이름을 확인하기 전 쓰지 않는다.
경로 이탈·링크/FIFO 아카이브와 실행 동의/클러스터 식별 누락은 로컬 보호 시험으로 거부했다.
실제 운영 서버를 시험 대상으로 지정할 수 있도록 변경해서는 안 된다.

### 화면과 최종 회귀

실제 엔진·경보·상세 변환 코드의 합성 UI를 별도 루프백 서버에서 렌더링했다.
운영 자료가 아니라는 배너를 표시하고 실수신/운영 배포와 구분했다.
SSH 단계 5/1/1, AWS 20호출/4종, IAM→감사 1/1과 원본 없음/만료 안내를 확인했다.
데스크톱 1440px 및 모바일 390px에서 확인했고 브라우저 오류/경고는 0건이다.

사용자의 UX 요청에 따라 경보 제목·관측 건수·탐지 이유를 먼저 표시하고 근거 목록과
규칙 버전/임계값은 접었다. 반복 안내를 줄이되 공격 성공 미확정·시험 기준·연결 한계는 유지한다.
긴 버전 문자열 줄바꿈을 추가했으며 모바일 페이지 폭 390px, 창 내부 clientWidth/
scrollWidth 356/356px로 가로 넘침이 없다. 기존 근거 페이지 탐색도 보존했다.

최종 Python: **602 passed / 14 skipped / 242 subtests passed (48.50초)**.
UI: **102 passed**. 새 PAM 시험을 포함한 에이전트 직렬 전체:
**102 passed / 1 skipped / 0 failed (242.26초)**. Ruff와 Bandit 중간/높음 검사 통과.
조건부 생략 항목은 위 목록과 같다. 별도 실제 ES 검증은 이 opt-in 시험들의 생략을 없앤 것이 아니다.

이번 SSH 공개 키 항목만 제거한 뒤 양쪽 VM의 해당 키 인증 거절을 확인했다.
다른 authorized_keys 내용·Windows ACL·기존 CA/키 파일은 보존했다.
커밋·푸시·운영 배포는 하지 않았다.

새 API 다양성 엔진에서 5,000건의 합성 정규화 이벤트를 평가해 경보 1건/0.599초를
관측했다. 자료 생성 시간·ES I/O·증분 저장은 제외하며 성능 SLA나 운영 처리량은 아니다.

## 검증한 반증·실패·복원

`tests/test_attack_detection.py`, `tests/test_linux_operational.py`,
`prototype/tests/operations.test.cjs`, `deploy/agents/tests/privacy.test.cjs`:

- 정상 소량 조회/단일 API 반복/단독 sudo/성공 없는 인증 실패/비-root 대상은 신규 경보 없음.
- 4/5/6 SSH 실패, 19/20/21 호출, API 3/4종, 300/301·600/601·900/901초 경계.
- 역순 입력 정렬, 실제 순서가 반대/동시각일 때 미연결, 선행 성공으로 실패 집합 초기화.
- 같은 IP의 다른 조직/호스트/계정, 같은 계정 이름의 다른 principal/ARN은 혼합 금지.
- 동일 AWS 이벤트 ID의 다른 문서 참조/재전송은 호출량 증가 없음. 별도 후속 감사 이벤트는
  독립 경보이며 동일 근거 재처리는 같은 결정적 ID다.
- principal/ARN/IP/정확한 event ID 누락·잘못된 자료형은 unknown/제외.
  actor/UID 없는 PAM 메시지는 정상 해석 가능하더라도 새 후속 규칙에 사용하지 않는다.
- 재시작·JSON runtime 복원·배치 경계를 넘는 3개 규칙, bounded 지연 정렬,
  frontier 이후 도착 제외 이력, 오래된 그룹 만료, active state 상한 실패.
- 경보 쓰기·상태 쓰기·근거 누락 실패 시 SQLite 체크포인트 유지 및 같은 ID 재시도.
  규칙/옵션이 바뀌면 기존 상태 거부, 자동 초기화 없음.
- 정상 승인 활동도 위험 변경 Single 경보는 유지. falsepositives 텍스트는 필터가 아니다.
  exact 조직/계정/주체+최대 하루의 event-time 예외는 실제 제외 및 감사/계측 기록을 생성한다.
- 상세 API가 실제 관측량/API 다양성/단계별 근거 위치/판정 한계를 반환하고 UI는 안전한
  텍스트로 표시한다. 기존 조직 접근·원문 보호·근거 누락/만료/해시 회귀도 전체 시험에 포함됐다.

초기 통합에서 실제 정규화에는 최상위 `event.id`가 없음을 발견해
`cloud_soc.detail.fields.event_id`로 수정했다. SSH 시험의 기준 날짜·허용 지연 범위를
바로잡았으며, 최초 일반 sudo 기반 양성 사례는 에이전트 개인정보 필터까지 연결되지 않아
충분하지 않았다. 보호 정책을 바꾸지 않고 명령 본문이 없는 PAM 세션 어댑터로 대체했고
최종 전체 및 개인정보 시험을 다시 통과했다. 이 과정의 초기 실패를 운영 성공으로 표현하지 않는다.

## 경보 예시와 해석

아래는 합성 규칙 평가의 근거 설명이며 실제 공격/운영 ES 경보가 아니다.

```text
ATTACK-01: ssh_failures=5 -> ssh_success=1 -> sudo_root_metadata=1
           evidence offsets: [0..4] / [5] / [6]
           type=attack_correlation, attack_success=not_established
           same SSH session NOT established; sudo command execution NOT established

ATTACK-02: observed_count=20, distinct_count=4
           DescribeInstances / ListUsers / ListBuckets / ListFunctions
           type=attack_indicator, attack_success=not_established
           userAgent/normal activity baseline NOT evaluated

ATTACK-03: high_privilege_policy_attachment=1 -> trail_stop_or_delete=1
           evidence offsets: [0] / [1]
           type=attack_correlation, attack_success=not_established
           effective privilege / all audit impairment NOT established
```

고유 원본·정규화 index/ID, event_hash, rule snapshot/version은 기존 provenance에 있다.
새 assessment는 이미 non-indexed인 provenance object 안에 추가하므로 새 동적 매핑을
강제하거나 기존 문서를 갱신하지 않는다. 규칙이 겹쳐 생긴 3개 경보를 3번의 실제 공격으로
합산해서는 안 되며 공격량 중심 첫 화면 집계는 후속 P5-05 범위다.

## 변경 파일과 기존 영향

| 영역 | 파일 |
| --- | --- |
| 새 엔진·규칙 | `src/cloud_soc/detection/behavior.py`, `rules/attacks.yml` |
| 선택·검증·영속 연결 | `detection/{registry,engine,rule_loader,telemetry,worker,incremental,__main__}.py` |
| PAM metadata 어댑터 | `parsers/linux_operational.py`, `processing/contract.py` |
| 경보 근거·조회 | `pipeline/alerts.py`, `portal/operations.py` |
| 상세 표시·회귀 | `prototype/operations.js`, `prototype/operations.css`, `prototype/tests/operations.test.cjs` |
| Python·개인정보 시험 | `tests/test_attack_detection.py`, `tests/test_linux_operational.py`, `deploy/agents/tests/privacy.test.cjs` |
| CI·문서 | `.github/workflows/ci.yaml`, 두 P5-03 문서, `docs/{cloud_detection,detection_coverage,work_tracker}.md` |
| 후속 격리 검증·화면 fixture | `tools/verify_p5_disposable.py`, `tests/{p5_03_live_checks,preview_p5_attacks,test_p5_disposable_guards}.py` |

개인 Word/검증 JSON과 기존 미커밋 작업 기록은 보존했다. README·설치기·TLS/인증/RBAC·
개인정보 정책·기존 규칙·운영 데이터/키/큐/SQLite는 변경하지 않았다.
기존 정규화 어댑터의 버전/ID는 유지하고 새 PAM 형식만 별도 버전/ID로 처리한다.

## 실제 환경에서 남은 인수

1. Ubuntu에서 같은 호스트의 SSH/PAM 형식·host.id·계정·시간대·개인정보 필터 이후 데이터가
   실제 원본→정규화로 들어오는지 확인한다. 익명/비표준 PAM은 추정하지 않는다.
2. AWS 계정/리전/수집 권한을 별도 승인받고 API별 실제 Management 기록 여부·principal/ARN/
   고유 이벤트 ID가 수신되는지 확인한다. 승인되지 않은 자원 변경/공격 실행은 하지 않는다.
3. 정상 관리자/인벤토리 자료로 초기 임계값·창·예외를 검토·승인한다. 승인 기간이 없어졌을 때
   자동화 작업을 계속 제외하지 않는지 확인한다. 실제 공격 성공률/오탐률은 아직 산출하지 않는다.
4. 상태 보호 백업·새 프로필 전환 시작점·재처리 중복 영향을 결정한 뒤 별도 요청으로 배포한다.
   격리 합성 검증을 운영 완료로 대신하지 않고, 배포 후 실제 ES 저장/재시작/장애/근거 조회와
   배포 화면을 인수한다.
5. 웹 공격은 민감 내용 추가 수집 없이 검증된 독립 신호와 요청→프로세스 관계를 확보한 후
   별도 승인한다. 지금은 비활성 명세로 남긴다.

이 인수와 운영 기준 승인 전 P5-03 전체 체크하지 않는다.

# 공통 런타임 v2 안정화 검토 기록 — 2026-10-15

기준은 `9d97ee2f2090992697eeaaaf1ceef1986a121268`, 작업 브랜치는 `codex/runtime-v2-upgrade-hardening`이다. 원래 작업 폴더의 수정된 작업 기록·Word·JSON을 보존하기 위해 별도 worktree를 사용했다. 원격 main은 읽기 조회했다. 로컬 검증 보고 후 사용자가 커밋·일반 push를 승인해 별도 기능 브랜치로 게시하며 새 CI를 확인한다. PR 생성과 운영 배포는 이번 승인 범위 밖이다. 학교에서는 기존 호환성 소스의 해시와 과거 실패 영수증만 읽었고 집 서버에는 접근하지 않았다.

## 원인과 변경

| 문제 | 원인 | 이번 처리 |
|---|---|---|
| 등록 OFF 재시작 | 정리 프로그램 종료와 필수 서비스 계약 충돌 | 기존 학교 수정 재사용: 자격증명/ES/등록 저장소를 열기 전 60초 대기, ON sweep/retry 유지 |
| bootstrap 복귀 실패 | 구형 depends_on을 일반 up으로 실행 | 필요한 이전 서비스만 no-deps/no-build/pull-never, 관측 이미지 ID를 고정한 보호 Compose로 복귀 |
| 구형 stop의 미정의 서비스 | 컨테이너 존재와 활성 서비스 정의 혼동 | 정의·실행·중지·잔존 구분, 활성 정의의 실행 중 앱만 stop, 정의 밖 실행은 사전 거부 |
| 부분 신규 워커 재시도 | 중지된 wrapper 명령을 구형 명령으로 파싱, DB 자기 복사 | 검증된 실패 계약으로 시작점 인수, 신규 컨테이너만 있고 DB가 없는 경우도 보존한 계획으로 재시도 |
| 키 생성 직후 중단 | ES 성공과 로컬 secret 저장 사이의 비원자적 경계 | 의도/저장/공개 journal, 같은 키와 소유권 단계 재사용, 응답 유실은 재발급 없이 명시적 대조 요구 |
| 과도한 백업 | 운영 DB 외 원본/미활성 사본을 재귀적으로 다시 복제 | 현재 운영 DB 목록만 사용, WAL 포함 온라인 백업/복원, 같은 내용의 온라인·중지 후 사본만 명시적 hard link |
| ES 쓰기 차단 위험 | 고정 여유값에 중간 복제·로그·실제 watermark 누락 | 파일시스템별 단계 최대량, 실제 ES 설정/장치, 온라인 백업 후 남은 예산 재측정 |
| 정상 대시보드 변경 오인 | 쓰기 중인 전후 revision을 불변 데이터처럼 비교 | 쓰기 완전 중지 후 기준 확보, 포털 재개 전 검사, 손실/검증 불가는 영구 실패 근거를 남겨 자동 재시도 차단 |
| 알림 정상 revision 변경 오인 | 워커 재개 후 초기 통지를 불변 해시로 비교 | 마이그레이션 후 모든 writer가 멈춘 시점에 경보/통지 보존 검사 |
| 별도 릴리스의 재적용 거부 | Compose 경로가 state의 상위 폴더 안에 있다고 가정 | 실제 레이블·보호 영수증·렌더링과 실행 signature로 입증, 전역 옵션만 허용해 실행 명령 삽입 거부 |
| 실제 Compose 기본 명령 오인 | 렌더링의 null을 이미지 기본값 상속으로 처리하지 않음 | null/생략과 명시적 빈 목록을 구분하고 실제 이미지의 CMD/ENTRYPOINT와 대조 |
| 변경 없는 계획의 stale 오인 | Docker inspect가 Mounts 배열을 매번 다른 순서로 반환 | 실제 Docker에서 재현 후 순서만 정규화. 경로/RW/이미지 등 실제 변경의 거부는 유지 |
| 컨테이너 소실 후 신규 설치 오인 | 컨테이너가 없으면 fresh로 판정 | 관리 영수증과 기존 DB를 우선 확인, 증거 없는 bootstrap 거부 |

학교 수정본의 OFF 대기, readiness, 최소 복귀, retry 계약, 선택적 DB 인수와 포털 검사 순서를 재사용했다. 추가된 부분은 장치별 자원/backup 모듈, 고정된 이전 실행 구성, 전체 실패 단계 journal, 전원 중단 내구성, 발급 경계 처리, 관리형 무변경 재적용과 분리된 소스 경로 지원이다. 운영 룰 revision·메모리 정책·900초·권한 제한을 낮춰 통과시키지 않았다.

## 변경 파일 — 총19개

| 파일 | 핵심 변경 |
|---|---|
| `src/cloud_soc/deployment/host.py` | 실제 상태 관측·자원 재측정·선택 백업·단계 journal·쓰기 중지 보존·apply/recover/무변경 재적용 |
| `src/cloud_soc/deployment/execution.py` | Compose 버전/정의/레이블/기본 명령/환경/mount 대조, 이전 이미지 고정 구성 |
| `src/cloud_soc/deployment/resources.py` | native 장치·mount·실제 ES watermark·단계 최대량·외부 백업·신규 readback |
| `src/cloud_soc/deployment/backups.py` | 운영 DB 목록·WAL 크기·검증/복원/해시 manifest·동일 사본의 명시적 공유 |
| `src/cloud_soc/deployment/migrations.py` | fsync 내구성, 키 발급/공개 경계·소유권 재시도, 기존 키/이력 재사용 |
| `src/cloud_soc/deployment/preflight.py` | 읽기 전용 ES 디스크 관측 경로 |
| `src/cloud_soc/deployment/contract.py` | 미활성 신규 상태 인수, 실제 공간/온라인 복원 메모리 판정 |
| `deploy/server/manage.py` | 빌드 전/외부 백업/수신 예약 CLI·구조화된 자원 거부·엄격 readiness |
| `deploy/server/enrollment-maintenance.py` | 등록 OFF 무작업 대기 |
| `tests/test_deployment_parity.py` | 재시도·상태 인수 회귀와 불명확 bootstrap 대조 시험 |
| `tests/test_school_runtime_compat.py` | 학교 수정 재사용 회귀·OFF/ON·최소 복귀·정상 저장 기준 |
| `tests/test_upgrade_safety.py` | 장치/watermark/WAL/실제 프로세스 종료/발급/동시 저장/Compose 상속·순서/초기화 거부 |
| `tests/test_upgrade_lifecycle.py` | 실제 SQLite+합성 외부 IO 장애 행렬·실패/복귀 재실패·반복 적용 |
| `tests/linux_upgrade_lifecycle.py` | 실제 Docker 세 유형 기동·구형 no-deps 복귀·OFF·중복/재기동 검사 |
| `tests/linux_runtime_smoke.py` | 별도 새 실제 전체 스택·정상 로그·Basic/TLS/API·무변경 재적용 |
| `.github/workflows/ci.yaml` | Ubuntu/Windows 신규 회귀 및 실제 Linux Compose 생명주기 단계 |
| `docs/runtime_deployment.md` | 공식 예산·백업·복귀·발급 경계·인수 절차 |
| `docs/runtime_upgrade_hardening.md` | 본 변경/시험/잔여 위험/학교 재배포 기록 |
| `docs/work_tracker.md` | RUNTIME-V2-HARDEN-20261015 범위·로컬 인수·원격 CI 승인 대기 |

## 사전 검사와 보호

전체 앱 한도 6656MiB+필수 여유 512MiB를 유지한다. 온라인 복원 시험이 기존 서비스와 동시에 사용하는 메모리도 별도로 검사한다. 장치별 보고에는 SQLite 본체/WAL, ES 실제 data mount, 기존 이미지의 비압축 크기(공유 레이어 합산 금지), 기존 업그레이드 할당량, 신규 사본/인수/빌드 상한과 수신 로그 예약을 기록한다. 기존 데이터는 이미 사용 중인 공간으로 반영하며 추가 사용량에 중복 합산하지 않는다.

ES low/high/flood-stage와 max_headroom을 defaults/node/persistent/transient 우선순위로 읽는다. 설정을 끄거나 높이지 않는다. low 기준에 닿는 단계가 있으면 부족 장치·단계·바이트와 용량 확장/별도 백업 장치 등의 대안을 보고하고 중지 전에 거부한다. 빌드 전 계획은 적용 불가능한 별도 예산이며, 기본 4GiB 빌드 상한과 1GiB 로그 예약은 실제 부하에 맞춰 높여야 한다.

신규 ES가 아직 없을 때는 고정 이미지 기본 watermark를 추정치로 명시하고, 첫 bootstrap 전에 실제 클러스터 설정을 재조회해 다시 거부할 수 있다. 기존 클러스터에 추정값을 적용하지 않는다. native ext2/3/4·XFS 장치의 mount identity를 기록하고 Btrfs/ZFS·NFS/CIFS·overlay/tmpfs는 st_dev만으로 독립 공간을 입증할 수 없어 자동 적용을 거부한다.

현재 워커·AUTH early·포털·알림 DB의 온라인 백업을 만들며 원본 WAL을 강제 checkpoint/truncate하지 않는다. 사본의 integrity 및 memory restore와 SHA256을 기록한다. 불변 사본을 공유할 때는 두 독립 백업이라고 표시하지 않는다. 이전 실패 사본·원본·이미지·ES 볼륨은 자동 삭제하지 않는다. 외부 백업은 별도 실제 장치와 root 보호 경로를 확인하며, 독립 물리 DR을 입증한 것으로 해석하지 않는다.

복귀는 실행 구성 복귀다. 운영 DB를 과거로 덮어쓰지 않고 호환 가능한 마이그레이션과 이미 발급한 키를 남긴다. 실패/복귀 재실패/pending/단계 영수증을 보존하며 완전한 readiness·signature·중복 검증 후에만 pending을 지운다. API 발급 결과가 불명확하거나 bootstrap running 상태에서 중단됐다면 운영자의 명시적 결과 대조가 필요하다.

## 시험과 인수 범위

최종 수치와 이미지/소스 증명은 아래 결과 표에 기록한다. 기존 조건부 시험은 삭제/skip/xfail로 바꾸지 않았다. 일반 사용자 단위 시험의 소유권 대역과 별도 root 컨테이너의 실제 chown 검증을 유지한다.

| 검사 | 범위 및 결과 |
|---|---|
| Python Ubuntu / Windows | Ubuntu **1,390 passed / 기존 조건부12 / 하위255**, Windows **1,386 passed / 기존 조건부16 / 하위257**. 게이트웨이 실제 Caddy **4 passed / 하위18** 별도 실행 |
| Ruff / Bandit / pip check / pip audit | 통과. 기존 Bandit nosec 설명 경고는 있으나 중·고위험 발견 없음. CI와 동일 pip26.2.1에서 알려진 의존성 취약점 없음 |
| UI / 설치 / Windows 에이전트 | UI **153** 및 설치 **57/기존 조건부1**가 양 OS에서 통과. Windows 에이전트 원래 일괄 실행108통과/1시간초과/기존조건부1 후 동일 실패 시험을 제한시간 변경 없이 재실행해 통과(약115초), 고유109사례 통과. 해당 시간초과 위험은 원격 CI에서 재확인 필요 |
| Compose config | 개발·운영·공통 세 구성의 실제 렌더링 검증 |
| 실제 UID/GID·권한 | root 컨테이너의 실제 chown, UID1000 허용/1001 거부, 0600/0700 및 실패 보존 19검사 |
| 실제 Compose 세 유형 | **최종 이미지로 순차 재실행 통과**. 관리형·구형 bootstrap 의존성·신규 구조, 12서비스/7워커 생명주기·OFF·최소 복귀·반복 기동 |
| 실제 전체 런타임 | **통과**. 새 격리 ES9.5.2/Kibana/포털/6처리+Slack1, TLS/Basic/API10·Kibana HTTP200·정상 합성 로그1→정확 raw 참조 정규화1·동일 구성 무재생성 재적용. OFF 정리 재시작0/OOM·재시작 증가0 |
| GitHub Actions | Ubuntu/Windows에 새 회귀와 Linux 실제 생명주기 단계 추가. 로컬 검증 후 push 승인됨. 새 원격 실행 결과는 후속 기록으로 구분 |

최종 후보 이미지: `sha256:baeaaaccf739128cf8cebada9a7444d89a3d1076797e797b822068c45c3e2444`.
공개 파일 **243개** 실제 이미지 내부 SHA256 대조 및 룰 revision7개 검증 완료.
소스 manifest SHA256: `574f336e4fd3f88fb6e26965e07836e33d265d556e1109290079dc197e7e3e22`.
이는 새 Git 커밋 SHA가 아니며 기준 main9d97ee2에 작업 브랜치 수정이 더해진 후보의 바이트 증명이다.

이미지와 실제 Docker 시험 환경은 로컬 WSL Ubuntu-24.04의 독립 Docker 엔진이다. 학교/집 또는 Docker Desktop에 배포한 것이 아니다. 운영 데이터가 포함되지 않은 검증 요약은 Git 제외 `D:/cloud-soc/state/runtime-hardening-validation-20261015/`에 보관한다. 시험 상태·실패 근거·볼륨·이미지는 승인 없는 삭제를 하지 않았다.

로컬 Linux 준비 중 Node18의 기존 RegExp v 미지원과 PowerShell 부재를 확인해 CI와 같은 Node22와 공식 PowerShell을 시험 전용 경로에 준비했다. 제품/시험을 삭제·완화하지 않았다. 실제 전체 스택 시험의 첫 입력 형식 및 검색 제외 필드 조회는 시험 코드를 정상 journald 메타데이터와 결정적 ID 직접 조회로 바로잡았다. 실제로 발견한 분리 경로/null 명령/mount 순서 문제는 제품 코드와 회귀에 반영했다. 두 Docker 통합 시험의 병렬 실행은 전역 중복 워커 보호에 걸렸고, 동일 최종 이미지로 순차 재실행해 통과했다. 이를 제품 탐지 실패로 간주하지 않는다.

장애 행렬은 온라인/중지 후 백업 실패, 온라인 중 자원 악화, 마이그레이션 후 실패, 서비스 시작·Kibana/포털 readiness 실패, 실제 행 손실/ES 근거 검증 실패, 강제 종료, 복귀 재실패와 재시도를 포함한다. 키 발급 경계는 별도 Python 프로세스의 실제 os._exit로 원격 성공 직후와 로컬 fsync 직후를 시험한다. 동시 WAL 트랜잭션은 커밋 전 온라인 사본과 커밋 후 중지 기준을 구분한다.

생명주기 시험의 ES/워커 대역은 실제 탐지 인수가 아니다. 별도 실제 전체 스택 시험의 정상 합성 로그도 학교/집의 실제 수집기나 신규 공격 인수를 의미하지 않는다. 실제 공격과 Slack 메시지는 보내지 않는다. 운영 계정·CA·키·DB·ES·Webhook은 변경하지 않았다.

## 승인 후 학교 재배포 절차 — 이번에는 실행하지 않음

1. 승인된 커밋/검증 이미지가 정해지면 별도 릴리스 디렉터리에 준비한다. `/home/kopo/cloud-soc`의 사용자 수정은 덮어쓰지 않는다. 기존 학교의 Slack ON/Webhook과 Basic 인증을 유지한다.
2. 실제 학교 IP와 현재 영수증을 확인한다. pending이 있으면 검증된 이번 관리자의 recover를 사용하고 DB를 되감지 않는다. preservation-failed/불명확 발급/bootstrap 증거가 있으면 먼저 대조한다.
3. 실제 state 경로 `/home/kopo/cloud-soc/state/server` 및 활성 Compose 레이블을 재확인하고 아래 예산을 검토한다. 이 경로가 달라졌다면 실제 운영 경로로 바꾼다.

```bash
cd /opt/cloud-soc/releases/REVIEWED_SOURCE
sudo python3 deploy/server/manage.py plan --before-build --state /home/kopo/cloud-soc/state/server --build-budget-mib 4096 --ingress-reserve-mib 1024 --plan /home/kopo/cloud-soc/state/server/build-budget.json
sudo docker --host unix:///var/run/docker.sock build --pull=false -f deploy/server/Dockerfile -t cloud-soc-runtime:reviewed .
sudo python3 deploy/server/manage.py plan --state /home/kopo/cloud-soc/state/server --image cloud-soc-runtime:reviewed --plan /home/kopo/cloud-soc/state/server/runtime-plan.json
sudo python3 deploy/server/manage.py apply --plan /home/kopo/cloud-soc/state/server/runtime-plan.json
sudo python3 deploy/server/manage.py verify --state /home/kopo/cloud-soc/state/server --portal-origin https://192.168.32.60 --wait-seconds 300
```

4. 외부 백업이 필요하면 검증된 별도 root 보호 장치를 plan의 `--backup-root`로 지정한다. 예산 거부 시 삭제/임계값 완화로 우회하지 않는다. 적용 후 실제 수신/정확 원본 참조, priority와 적체, 기존 키·상태, Kibana healthy/HTTP200, OOM·재시작을 확인한다. 실제 신규 탐지가 없으면 해당 인수는 미검증이다.
5. 장애 시 공식 recover로 이전 실행만 복귀한다. 새로운 컨테이너가 남았다고 임의로 bootstrap/down-v/volume 삭제/키 재발급을 하지 않는다. 기존 실패 영수증과 백업을 유지한다.

## 잔여 위험 및 PR 범위

전체 ES snapshot과 독립 DR, 전원 장치 자체의 장애 시험, 학교/집의 새 운영 배포와 공격 인수는 이번 범위 밖이다. 다중 ES 노드/data path는 모호한 저장 장치 매핑을 자동 승인하지 않는다. 로그·빌드 예약은 운영자가 지정한 유한한 상한이며 예산을 넘는 유입을 영구 보장하지 않는다. 새 원격 CI는 승인된 기능 브랜치 push로 실행한다. PR과 운영 배포는 별도 승인 대상이다.

새 apply부터 고정된 이전 Compose를 기록한다. 그 영수증이 없는 과거 journal은 저장된 관측 정보에 의존하는 호환 경로이며, 당시 Compose 파일/태그가 수동 변경된 상태까지 독립 복원 보장을 인수한 것은 아니다. 학교 재배포 전에 기존 pending과 복귀 근거를 먼저 대조하고, 차이가 있으면 강제 진행하지 않는다.

실제 전체 스택의 기존 경보 보존 수는 신규 빈 환경이므로0건이다. 기존 경보·사건·대시보드·Slack ON/발송 이력 보존은 별도의 실제 SQLite/합성 ES 및 root 권한/실패 복귀 시험에서 검증했다. 새 실제 공격 경보, 기존 운영 데이터가 쌓인 실서버의 장기 부하·10분 이상 운용 인수 및 Session 방식 전체 컨테이너 전환을 완료했다고 표시하지 않는다. 합성 Session/RBAC/조직 격리 회귀와 기존 secret mount 보존을 유지했다.

PR에는 배포 관리자/contract/migration/preflight, backups/resources/execution, OFF 정리, 공식 절차/본 기록/작업 추적, 장애·세 유형·실제 권한/전체 스택 시험과 CI 단계만 포함한다. 운영 상태·시험 비밀정보·DB·인증서·이미지·개인 문서는 포함하지 않는다.

# 포털 DB 백업과 격리 복원

P2-02 중 **사건/메모·패키지/키 발급 이력의 유실 방지**를 위한 로컬 도구입니다. Python 3.10 이상 표준 라이브러리만 사용하며 네트워크 접속, 비밀번호 입력, Docker 제어, 운영 데이터 덮어쓰기를 하지 않습니다.

## 포함 범위와 한계

2026-10-13 지정 중앙192.168.32.60에서 기존 포털 DB의 실제 온라인 backup·격리 restore, 이후 탐지 main/early를 잠시 정지한 일관 쌍 백업 및 실제 개인 설정 재시작 보존을 추가 인수했다. 원래 패키지16/발급 이력26·사건 관련 행과 키/CA는 보존했다. [현재 보호 자료·실제 결과](early_deployment_validation_20261013.md). ES snapshot·외부 독립 복구는 완료되지 않았으며 아래 형식별 개발 이력은 유지한다.

2026-10-13 다중 대시보드 확장: `dashboard_collections`가 포함된 `dashboards.sqlite`는 format 4로 기존 개인 설정과 다중 화면·기본 지정·즐겨찾기·독립 위젯 설정·컬렉션 revision을 함께 백업한다. 기존 format 1/2/3의 검증/격리 복원을 유지하며, 원본 행을 이행하거나 삭제하지 않는다. 새 테이블이 있는 DB에는 이번 버전의 백업 도구를 사용한다. 계정별 구성·기본 지정의 합성 백업/격리 복원과 현재/이전 감사 복원을 시험했고 운영 백업·복구는 별도다.

2026-10-12 대시보드 배포 보완: `dashboards.sqlite`가 있으면 format 3 백업에 계정별 이름·위젯·순서/너비·기간·테마·revision을 포함한다. format 1/2의 파일 목록·검증·격리 복원 호환은 유지한다. 로그인 세션 DB와 로그인 계정 설정/해시는 별도 보호 대상이며 비밀번호를 백업 출력에 포함하지 않는다. 구형 도구는 개인 설정 DB를 포함하지 않으므로 새 코드의 도구를 사용한다. 관련 백업/설정/권한 로컬 시험 37건을 통과했고 실제 배포 전 백업/복원·배포 후 개인 설정 복원은 별도로 기록한다.

2026-10-04 P2-01 후속 코드: `log-access.sqlite`의 보호된 원문 접근 감사도 백업한다. 감사 DB가 존재하면 manifest format 2로 최대 세 DB를 포함한다. 기존 format 1 백업의 verify/격리 restore는 유지한다. 새 포털은 원문 기능 차단 상태에서도 감사 DB를 만들므로 배포 버전과 맞는 백업 도구를 사용한다. 정책 파일·조회 계정 해시는 별도 보호 백업 대상이다. format 2 합성 감사 DB 백업/복원은 로컬 검증했으며 VM의 실제 감사 백업·배포·운영 복구 완료는 아니다([조회 정책](log_access_policy.md)).

2026-10-04 실제 후속 검증: 위 문단의 로컬 단계 이후 지정 VMware에서 초기 format 1 및 새 감사 포함 format 2의 online/stopped/final backup·verify·새 경로 restore·verify를 통과했다. 실제 감사 34개 행의 모든 컬럼·순번과 기존 패키지 10/키 이력 18/등록 15·사건 테이블을 대조했다([보고서](archive/validation/p2_source_access_validation_20261004.md)). 복원은 격리 경로에만 했으며 운영 DB 교체·ES 스냅샷·외부 백업·보존 기간 승인은 별도다.

| 대상 | 포함 여부 |
| --- | --- |
| `packages.sqlite3` | 설치 묶음 BLOB·설정·해시·발급한 키 ID 이력 포함, 필수 |
| `cases.sqlite` | 사건·경보 연결 메타데이터·메모·판정·변경 이력·중복 요청 기록 포함 |
| `log-access.sqlite` | 존재하면 원문 접근 감사 순번·계정·역할·사유·문서 참조 해시·결과·정책 버전 포함 |
| `dashboards.sqlite` | 존재하면 기존 개인 설정과 다중 대시보드·기본/즐겨찾기·위젯 설정·revision 포함 |
| P6 이전 설치의 사건 DB 없음 | `missing: ["cases.sqlite"]`로 명시, 사건 백업 완료가 아님 |
| ES 문서·인덱스·실제 API 키 유효 상태 | 미포함, ES 스냅샷과 별도 검증 필요 |
| CA/개인키·비밀번호·Kibana 설정·Compose 환경 | 미포함, 별도 보호 백업 필요 |
| 처리기/AWS/OCI 체크포인트·에이전트 registry/큐 | 미포함, 각각의 복구 정책 필요 |

파일 복사 대신 [SQLite 온라인 백업 API](https://www.sqlite.org/backup.html)를 사용합니다. DB별 일관된 시점을 보장하며 WAL의 커밋된 기록도 포함합니다. 전체 DB 또는 ES와의 동일 시점 분산 스냅샷은 아닙니다. 정확히 같은 운영 중지 시점이 필요하면 포털 쓰기를 중지한 뒤 실행하세요.

SHA-256, SQLite `integrity_check`/`foreign_key_check`, 지원 스키마, 테이블별 건수를 검사합니다. 해시는 우발적 손상 감지용이며 공격자가 파일과 manifest를 함께 바꾸는 것을 막는 전자서명이 아닙니다. 신뢰한 관리자 소유의 로컬 경로만 사용하세요. 검사 도중 관리자 외 사용자가 경로를 교체할 수 있는 디렉터리나 네트워크 공유는 지원하지 않습니다.

백업에는 조사 정보·서버 주소·조직과 키 ID 등 민감 메타데이터가 있습니다. **암호화 파일이 아닙니다.** POSIX에서는 새 디렉터리 700, 파일 600으로 만들며, Windows에서는 보호된 NTFS 상위 폴더 ACL을 관리자가 준비해야 합니다. 전송/원격 보관에는 승인된 암호화 저장소를 사용하고 Git에 추가하지 마세요.

## 1. 백업

검토한 코드가 Ubuntu 서버에 전달된 뒤 `~/cloud-soc`에서 실행합니다. 실제 `SOC_STATE_DIR`을 다르게 설정했다면 `--source`를 수정하세요. 기존 서버에 설치기를 다시 실행할 필요는 없습니다. 아래는 별도 서비스 변경 없이 호스트의 Python으로 실행합니다.

```bash
cd ~/cloud-soc
sudo install -d -m 700 state/portal-backups
BACKUP="state/portal-backups/$(date -u +%Y%m%dT%H%M%SZ)"
sudo python3 deploy/server/portal-backup.py backup \
  --source state/server/portal --destination "$BACKUP"
sudo python3 deploy/server/portal-backup.py verify --source "$BACKUP"
```

각 명령의 성공 출력 `status: ok`와 종료 코드 0을 확인하세요. `missing`도 확인해 기대한 DB가 모두 포함되었는지 검사합니다. 패키지 DB가 없으면 잘못된 경로일 수 있어 중단합니다. 대상 디렉터리는 **존재하지 않아야 하며**, 부모 디렉터리는 먼저 준비합니다. 같은 초에 재실행하면 기존 경로를 거부하므로 새로운 백업 이름을 사용하세요.

기본 제한은 DB당 1GiB, 작업 60초입니다. `--timeout-seconds 120`처럼 최대 600초까지 지정할 수 있습니다. 용량 제한을 넘으면 자동 생략하지 않고 실패합니다. 실행 중 쓰기 경합, 공간 부족, 손상, 지원하지 않는 스키마도 실패로 처리합니다. 제한 시간은 SQLite 진행 콜백으로 검사하며 OS 파일 I/O의 하드 실시간 중단 보장은 아닙니다.

성공 판정용 `manifest.json`은 마지막에 발행됩니다. 오류 시 부분 출력은 조사용으로 보존하고 자동 삭제·재사용하지 않습니다. **실패했던 경로는 완료된 백업으로 사용하지 마세요.** 원인 확인 후 새 경로에 다시 실행하고 `verify`를 통과시킵니다. 오류 출력은 DB 내용/메모/상위 예외를 포함하지 않습니다.

## 2. 격리 복원 시험

검증된 백업을 현재 서비스 폴더가 아닌 새 경로에 복원합니다. 위 셸의 `BACKUP` 변수가 없다면 검증할 백업 디렉터리를 다시 지정하세요.

```bash
sudo install -d -m 700 state/portal-restore-drills
RESTORE="state/portal-restore-drills/$(date -u +%Y%m%dT%H%M%SZ)"
sudo python3 deploy/server/portal-backup.py restore \
  --source "$BACKUP" --destination "$RESTORE"
sudo python3 deploy/server/portal-backup.py verify --source "$RESTORE"
```

복원 전·후 해시/무결성/건수를 검사하며, 기존 경로·원본 하위 경로·심볼릭 링크/junction/reparse point·하드링크·예상하지 않은 추가 파일은 거부합니다. 복원된 파일은 실행 계정 소유입니다. `sudo`로 실행하면 root 소유이며 이 상태를 UID 1000 포털에 바로 연결하지 않습니다.

`production_restored: false`는 정상입니다. 이 도구는 복구 준비까지만 수행하며 서비스 중지/재시작, 운영 폴더 교체, 소유권 변경, 계정/키 복원을 자동 실행하지 않습니다. 운영 전환은 장애 시점과 기존 DB 보존, 해당 코드 버전, 앱 사용자 UID/GID, ES/CA 일치, 승인된 중단 시간을 확인한 뒤 별도 절차로 수행해야 합니다.

운영 복구 검증에서는 건수만 아니라 실제 사건 제목·최근 메모·연결 경보·설치 묶음 해시를 대조하세요. 포털에서 새 기록을 쓰면 manifest의 원래 해시는 더 이상 맞지 않습니다. 원본 백업은 변경하지 말고 별도 복원 사본으로 앱을 검증하세요. 같은 서버 디스크의 백업만으로 서버/디스크 전체 장애에 대비했다고 간주하지 않습니다.

## 검증 범위와 다음 순서

`tests/test_portal_backup.py`는 합성 DB를 백업한 후 복원본의 실제 Flask API에서 사건·이력·담당·목록을 조회하고 설치 묶음 바이트와 키 ID, 요청 중복 방지를 대조합니다. WAL 커밋/미커밋, 경합, 손상, manifest 변조, 복원 중 변경, 용량/시간 제한, 실패 종료 코드도 시험합니다. Linux 권한/실제 symlink 검증은 `tests/portal_backup_posix_checks.py`입니다.

이는 실제 AWS 백업/복구 완료가 아닙니다. 현재 남은 우선순위는 P0 배포·수신 확인, P2 큐/전송 오류 계측 및 운영 ES 백업·보존 승인입니다. 백업 예약/자동 삭제/외부 저장소 연결은 추가하지 않았습니다.

2026-10-12 후속 실제 배포: 개인 대시보드 DB가 생성된 지정 VMware에서 format 3 backup/verify/격리 restore와 최종 관리자 revision 2 구성 대조를 완료했다. 기존 format 1/2 이력과 독립 저장소 보류는 유지하며 운영 DB 교체는 하지 않았다. [배포 결과](archive/validation/dashboard_deployment_20261012.md)

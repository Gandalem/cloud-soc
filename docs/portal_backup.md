# 포털 DB 백업과 격리 복원

P2-02 중 **사건/메모·패키지/키 발급 이력의 유실 방지**를 위한 로컬 도구입니다. Python 3.10 이상 표준 라이브러리만 사용하며 네트워크 접속, 비밀번호 입력, Docker 제어, 운영 데이터 덮어쓰기를 하지 않습니다.

## 포함 범위와 한계

| 대상 | 포함 여부 |
| --- | --- |
| `packages.sqlite3` | 설치 묶음 BLOB·설정·해시·발급한 키 ID 이력 포함, 필수 |
| `cases.sqlite` | 사건·경보 연결 메타데이터·메모·판정·변경 이력·중복 요청 기록 포함 |
| P6 이전 설치의 사건 DB 없음 | `missing: ["cases.sqlite"]`로 명시, 사건 백업 완료가 아님 |
| ES 문서·인덱스·실제 API 키 유효 상태 | 미포함, ES 스냅샷과 별도 검증 필요 |
| CA/개인키·비밀번호·Kibana 설정·Compose 환경 | 미포함, 별도 보호 백업 필요 |
| 처리기/AWS/OCI 체크포인트·에이전트 registry/큐 | 미포함, 각각의 복구 정책 필요 |

파일 복사 대신 [SQLite 온라인 백업 API](https://www.sqlite.org/backup.html)를 사용합니다. DB별 일관된 시점을 보장하며 WAL의 커밋된 기록도 포함합니다. 두 DB 전체 또는 ES와의 동일 시점 분산 스냅샷은 아닙니다. 정확히 같은 운영 중지 시점이 필요하면 포털 쓰기를 중지한 뒤 실행하세요.

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

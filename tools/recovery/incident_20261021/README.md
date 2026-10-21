# 2026-10-21 복구 도구 소스 이력

이 디렉터리는 해당 VM 장애 조사 중 저장소 밖에서 작성한 소스 21개를 보관한다.
자동 실행되는 제품 기능이나 범용 복구 패키지가 아니다. 호스트별 절대 경로,
백업 이름, 해시, 고정 이미지와 실행 순서가 들어 있으며 다른 환경에서 그대로 실행하면 안 된다.
소스 이동 후 원래 `outputs/` 경로를 참조하는 코드도 보존되어 있다.

## 현재 선택

사용자는 부분 추출 결과를 운영에 반영하지 않고 **10월 16일 Elasticsearch 스냅샷 기준 복원**을 선택했다.
`export-raw-salvage.py`, `RawSalvage.java`, `compare-local-recovery.py`는 조사 이력이다.
그 결과를 재수집·재색인하거나 운영 인덱스로 전환하는 실행은 승인된 현재 경로가 아니다.
`restore-snapshot-sidecopy.py`도 별도 이름의 시험 복원 도구이며 운영 전환 도구가 아니다.

## 소스 분류와 변경 효과

| 용도 | 소스 | 효과/한계 |
|---|---|---|
| 앞선 코드의 배포 준비 | `deploy-vm.sh`, `deploy-ssh-vm.sh` | 고정된 과거 tree/image를 검사하고 보호 배포 manager를 호출한다. 현재 스냅샷 복원에 실행하지 않는다. |
| 배포 인증/사전 진단 | `resume-vm-deploy.py`, `diagnose-vm.py`, `check-deployment-sqlite.py` | resume은 인증 검증 후 로컬 secret 복사본을 바꾸고 배포를 재개할 수 있다. 다른 두 도구와 효과를 혼동하지 않는다. |
| Linux 입력 시간대 | `apply-file-timezone.py`, `check-ssh-intake.py` | apply는 Filebeat 입력과 서비스를 변경할 수 있다. check는 수집/정규화 진단이다. |
| containerd 오프라인 조사 | `inspect-containerd-pages.py`, `check-containerd-candidates.py`, `containerd-inventory.go` | 보존 사본의 bbolt 페이지/후보와 항목 수를 조사한다. 빈 metadata를 정상 운영 복구로 간주하지 않는다. |
| Docker 네트워크 복구 | `prepare-network-recovery.py`, `recover-network-daemon.py` | prepare는 비공개 계획을 생성한다. recover의 현재 허용 인수는 `--disable-restart-only`뿐이며 설정 백업 후 자동 재시작을 해제하고 반환한다. 뒤에 남은 네트워크 기동 코드는 이 버전에서 실행되지 않는다. |
| ES 샤드/스냅샷 조사 | `inspect-shard-recovery.py`, `restore-snapshot-sidecopy.py` | 진단 및 별도 이름의 복원. 기존 운영 인덱스 교체는 수행하지 않는다. |
| 원본/로컬 로그 조사 | `inspect-raw-recovery.py`, `inspect-local-log-recovery.py`, `check-raw-segments-copy.py`, `inspect-translog-salvage.py` | 원문을 채팅에 출력하지 않고 메타데이터를 조사한다. 사본 검사는 별도 container/파일을 생성한다. |
| 사본 추출/비교 이력 | `RawSalvage.java`, `export-raw-salvage.py`, `compare-local-recovery.py` | 정상 세그먼트와 읽을 수 있는 translog를 비공개 파일로 추출한다. 전량 복구를 증명하지 못했으며 운영에 적재하지 않았다. |

`inspect-raw-recovery.py`의 초기 도움말 호출은 Lucene이 `-help`를 경로로 해석했다.
원래 실행 컨테이너 안에 도움말용 경로/lock이 생겼을 수 있으며 이 도구의 모든 실행이
컨테이너 파일시스템까지 완전히 무변경이었다고 주장하지 않는다. 실제 원본 샤드 수정과는 구분한다.
샤드 검사/추출은 현재 Elasticsearch 이미지의 Lucene 내부 API를 사용했으며 다른 버전의 지원을 보장하지 않는다.

## 확인된 결과

- 사용자 실행 결과로 containerd 복구 후보 검사와 12개 항목 조회, Docker 재기동과 기존 데이터 볼륨 연결을 확인했다.
- ES 스냅샷의 업무 인덱스 5개를 별도 이름으로 복원하고 primary 5/5 활성화와 문서 수를 확인했다.
- 정상 세그먼트 215,564건과 translog 추가 7,745건을 추출했지만 19,633개 순번은 여전히 비어 있다.
- 원본/journal 비교의 메시지 일치는 문서 ID 일치가 아니다. unmatched 기록은 손실분 복구 건수가 아니다.
- 운영 스냅샷 전환, Kibana 재구성, 데이터 완전성/최신 로그/Slack 실경보의 복구 완료는 확인하지 않았다.

## Git에서 제외한 자료

원문 로그, NDJSON 추출본, SQLite/bbolt DB, 인증서/개인키, 비밀번호/API 키,
호스트 생성 Compose/env/site 파일, 실행 영수증/진단 JSON, bbolt/Go/Java 실행 파일,
컴파일 캐시와 VM 스냅샷은 포함하지 않는다. `/var/tmp`의 실제 보존본도 Git으로 복사하지 않는다.

선택한 운영 복원의 범위와 남은 작업은 `docs/recovery_snapshot_20261016.md`를 참조한다.

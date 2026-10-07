# P2-02 백업 준비와 추가 용량 비교

## 지금 사용할 수 있는 것

**현재 보류:** 2026-10-07 사용자 요청으로 독립 저장소 준비 후 재개합니다.
아래 로컬 구현·검증 결과와 설계 기준은 보존하지만 추가 측정/운영 연결·활성화는 진행하지 않습니다.

2026-10-07 사용자 선택에 따라 **Windows/Linux 균형형 보존 + 매일 03:00 KST 백업 + 14일 백업 보관**을
개발 기준으로 삼았습니다. 저장소는 아직 없으므로 이번 기능은 검토안 생성과 읽기 전용 점검입니다.
OCI는 보류합니다. 중앙 서버·에이전트·포털 UI를 변경하거나 자동 삭제를 시작하지 않습니다.

| 기능 | 현재 동작 |
| --- | --- |
| 백업 준비 | NAS/공유 파일시스템 또는 S3 설정안과 SLM 정책안 생성 |
| 추가 저장량 비교 | 두 표본을 소스별로 비교해 원본 30일·네트워크/상태 14일 순증가 추정 |
| 다음 표본 시각 | 첫 표본으로부터 최소 24시간 뒤의 UTC/KST 시각 안내 |
| 백업 상태 | 지정 저장소/정책의 최근 10개 스냅샷으로 실패·누락·24시간 초과 판정 |
| 알림 | 주의/판단 불가 JSON과 종료 코드 제공. 이메일/문자/대시보드 전달은 아직 없음 |
| 실제 자동 백업/만료/복원 | 미활성화. 도구에 적용·삭제·복원 명령 없음 |

원본 로그의 보존 기간과 백업 보관 기간은 다릅니다. 원본에서 지워진 로그가 이전 백업에 남을 수 있습니다.
스냅샷은 최소 성공본 1개를 보존하도록 제안하므로 장기 백업 실패 시 **14일을 넘는 마지막 성공본**이
남을 수 있습니다. 이를 숨기거나 "정확히 14일 뒤 모든 사본 삭제"로 표시하지 않습니다.

## 준비안 확인

프로젝트 루트에서 프로젝트 의존성이 설치된 Python 3.10 이상을 사용합니다.
저장소가 없을 때도 실행할 수 있고 네트워크에 접속하지 않습니다.

```bash
.venv/bin/python deploy/server/backup-readiness.py plan
```

결과의 `activation_ready=false`는 정상입니다. 저장소/권한/비용/암호화 검증·운영 백업·격리 복원·
포털/비밀 파일 백업·알림 연결·자동 만료 적용 승인이 남았다는 뜻입니다.

독립 장비가 준비되면 아래 형태의 설정 파일을 비공개 관리자 작업 폴더에 준비하고
`plan --storage-config <설정파일>`로 검토안을 생성합니다. 예시는 실제 목적지가 아닙니다.

공유 파일시스템 예시:

```json
{"type": "fs", "location": "/mnt/independent-backups/cloud-soc"}
```

S3 예시:

```json
{"type": "s3", "bucket": "example-cloud-soc-backups", "base_path": "cloud-soc/p2"}
```

공유 경로는 **ES 컨테이너에서 보이는 경로**입니다. NAS 마운트/권한/독립 장비 여부와 `path.repo`,
컨테이너 볼륨 준비는 별도이며 이 도구가 수행하지 않습니다. S3는 버킷 접근 차단·암호화·최소 IAM 권한·
접근 경로/비용을 확인해야 합니다. AWS 키는 이 JSON이나 명령 인자/Git에 넣지 않습니다.
S3 저장소안은 `server_side_encryption=true`이며 자격 증명/임의 endpoint를 받지 않습니다.
버킷의 S3 객체를 별도 수명 정책으로 임의 삭제하면 스냅샷을 손상시킬 수 있으므로 저장소 정리는 ES로 관리합니다.

SLM 제안은 UTC `0 0 18 * * ?`, 즉 한국시간 다음 날 03:00입니다. ES 노드 시계도 맞아야 합니다.
호스트/네트워크/상태 수집 인덱스만 포함하고 partial snapshot·누락 무시·global state/feature state는 제외합니다.
정규화/탐지·Kibana·템플릿/파이프라인·ES 계정/정책은 이 수집 데이터 백업만으로 복구되지 않습니다.
팀원 기능 통합 후 별도 백업 범위/권한을 검토합니다. 새 정책 생성 자체가 스케줄을 활성화할 수 있으므로
출력한 JSON을 운영 ES에 바로 전송하지 마세요.

## 추가 용량 표본

기존 계측은 [저장량 안내](p2_capacity_backup.md)의 `capacity-report.py measure`를 사용합니다.
두 개의 schema 2 보고서가 필요하며 기존 표본을 덮어쓰지 않습니다.

```bash
.venv/bin/python deploy/server/backup-readiness.py next-sample \
  --report state/storage-reports/sample-01.json

.venv/bin/python deploy/server/backup-readiness.py capacity \
  --previous state/storage-reports/sample-01.json \
  --current state/storage-reports/sample-02.json
```

학교 VM 첫 표본은 2026-10-07 **12:45:23 KST**에 측정했습니다. 최소 간격의 다음 표본은
2026-10-08 12:45:23 KST 이후이며, 이 시각을 안내하는 것과 실제 측정/예약은 별개입니다.
가능하면 3~7일간 같은 범위로 주간/야간을 비교합니다. 24시간 미만, 소스 미관측,
클러스터 교체/인덱스 삭제·재생성/카운터 초기화/개별 인덱스 감소는 정상 추정으로 표시하지 않습니다.

AWS/OCI 표본은 이 소스별 추정에서 제외합니다. 경보/사건 90일과 조사 증거 보류의 저장량은 아직 미측정입니다.
출력은 **순증가 추정**이며 replica/translog/병합 여유/백업·다른 서비스·숨은 삭제/병합 영향은 따로 계산합니다.
전체 저장량이나 24시간 수신 건수를 하루 저장량 증가로 취급하지 않습니다.

## 백업 상태 읽기

아직 저장소가 없으므로 아래는 저장소·정책 활성화 후의 연결 방법입니다.
TLS를 검증하며 기존 수집 키 대신 `backup-health-reader-role.json`의 `monitor_snapshot` 조회 키를 사용합니다.
원문 `read`/키 발급/인덱스 삭제/스냅샷 생성·삭제/SLM 변경 권한을 요구하지 않습니다.
다만 ES의 `monitor_snapshot`은 다른 저장소 메타데이터도 조회 가능하므로 신뢰한 관리자만 보유합니다.
키 파일은 Linux 소유자 전용 `600`, Windows 관리자/SYSTEM 제한 ACL로 보호합니다.

```bash
.venv/bin/python deploy/server/backup-readiness.py health \
  --repository cloud-soc-p2-backup \
  --inventory state/storage-reports/sample-at-backup.json \
  --endpoint https://<중앙주소>:9200 --ca-file /secure/ca.crt \
  --api-key-file /secure/backup-health-reader.key
```

예상 인덱스 목록은 스냅샷 시점과 맞는 보고서를 사용합니다. 이후 새 일별 인덱스가 포함된 목록을 넣으면
그 이전 스냅샷에 없는 인덱스를 누락으로 판단할 수 있습니다. 현재 프로필/정책이 생성한 스냅샷만 최근 10개 조회합니다.

- `metadata_ok`: SUCCESS·완전 shard·예상 인덱스 포함·보수적 복구 시점이 24시간 이내. 복원 성공은 아님.
- `attention`: 최근 성공 없음/새 실패/예상 인덱스 누락/24시간 초과/진행 중 4시간 초과/예상 외 범위.
- `unknown`: 연결·권한·저장소 조회·응답 검증 실패. 정상으로 바꾸지 않으며 주의가 필요함.

복구 시점의 나이는 스냅샷 완료가 아니라 시작 시각 기준으로 보수적으로 계산합니다.
`restore_verified=false`, `notification_sent=false`를 유지합니다. SLM 활성 상태·만료 실행·저장소 암호화/독립성·
전체 무손실·포털/비밀 파일 백업은 이 조회로 검증하지 않습니다.
종료 코드는 `0` 출력 생성/메타데이터 정상, `2` 주의·판단 불가·용량 불완전, `1` 입력/TLS 준비 등 실행 실패입니다.
향후 운영 감시에는 1/2 모두 실패 알림에 연결하고, 감시 작업 자체가 실행되지 않는 경우도 별도로 확인합니다.

## 포털과 설정은 따로

기존 `portal-backup.py backup/verify/restore`는 보호된 SQLite 백업/검증/새 경로 복원 도구로 유지합니다.
온라인 DB 파일을 단순 복사하지 않고 이 도구를 사용해야 WAL의 커밋 자료가 포함됩니다.
출력은 아직 암호화되지 않았으므로 외부 저장소 전송 전 별도 암호화가 필요합니다.
CA/서버 개인키·비밀 파일은 DB와 다른 최소 권한/암호화 경로로 보관하고 복구 담당자를 지정합니다.
이번에 자동 암호화/업로드/예약/키 복구 절차까지 구현한 것은 아닙니다.

## 검증과 다음 단계

일반 로컬 회귀:

```bash
python -m unittest discover -s tests -p 'test_backup_readiness_p2*.py' -v
```

실제 격리 ES 시험은 로컬 Docker와 사전 준비된 ES 9.5.2 이미지가 있을 때만
`SOC_TEST_P2_BACKUP_ES=1`로 명시 실행합니다. 원격 Docker context는 거부하고 자동 image pull은 하지 않습니다.
임시 loopback ES·합성 3개 인덱스에만 SLM 등록/수동 실행, 실제 `metadata.policy`·최소 조회 권한·
원문/삭제/SLM 쓰기 거부·새 이름 복원/내용 대조를 검증한 뒤 소유 컨테이너를 정리합니다.

현재 로컬 Docker 엔진이 내려가 있어 이 시험은 미실행입니다. 기존 2026-10-07 Ubuntu 격리 ES 복원 성공은
이 새 SLM/상태 도구의 실제 검증으로 대신하지 않습니다.
다음은 **독립 목적지 준비 → 권한/암호화/접근 검증 → 추가 표본 → 실제 백업/격리 복원 →
포털·설정 보호 백업/알림 연결 → 별도 승인 후 스케줄·백업 만료 활성화**입니다.
원본 로그 자동 삭제는 사건 증거 보호·경계/기산점·복구 검증 후 별도로 승인합니다.

근거: [SLM 생성과 보관](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/create-snapshots),
[스냅샷 필터/크기 제한](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-snapshot-get),
[공유 저장소](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/shared-file-system-repository),
[S3 설정](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/s3-repository-settings).

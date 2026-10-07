# P2-02 저장량·보존·백업 준비

## 현재 상태

`park-p2-02`는 최신 main을 기반으로 독립 계측과 검증만 추가합니다.
탐지·인증·UI·CI·Dockerfile·Compose를 변경하지 않습니다. 운영 로그 자동 삭제,
ILM 적용, 저장소 등록, 기존 인덱스로의 복원 기능은 제공하지 않습니다.
이 문서의 숫자는 검토값이며 법적 보존 기간을 대신하지 않습니다.

권장 순서는 **실제 24시간 표본 → 용량/비용 검토 → 백업·격리 복원 → 기준 승인**입니다.
실제 서버 표본·보존 기간·디스크 기준·운영 백업 저장소는 승인/실증 전까지 미완료입니다.

2026-10-07 학교 Ubuntu VM에서 실제 24시간 수신 구간의 첫 용량 표본을 측정했고,
운영과 분리된 임시 ES 9.5.2의 최소 권한·ILM·스냅샷/복원을 검증했습니다.
[검증 결과](p2_capacity_validation_20261007.md)를 참고하세요. 첫 표본과 실제 복원 시험은
보존 기준 승인이나 운영 백업 구성 완료를 의미하지 않습니다.

## 무엇을 측정하나요?

- 호스트·네트워크·상태·AWS/OCI 수집 인덱스의 현재 검색 가능한 문서 수와 저장량.
- 지정 구간의 `event.ingested` 문서 수와 수신 시각 없는 문서 수.
- 노드별 가용 디스크와 검토용 경고/위험 상태(기본 75%/85%).
- 두 표본의 primary 저장량 순증가 추정. 전송 바이트나 전체 로그 무손실 지표는 아닙니다.

정규화/탐지/이력 인덱스와 다른 서비스는 대상이 아닙니다. 팀원 통합 후 별도 용량에 합산해야 합니다.
검색 refresh 전 문서는 집계에 보이지 않을 수 있으며 조회 전체가 원자적 스냅샷은 아닙니다.
500개 인덱스·100개 노드·60초 예산을 넘거나 권한/샤드/시간 초과가 있으면 정상 보고를 만들지 않습니다.
기존 저장량 도구의 schema 1 파일과 새 schema 2 파일은 비교하지 않습니다.

## 서버에서 읽기 전용으로 실행

중앙 이미지 재빌드 없이 저장소 루트에서 Python 3.10 이상과 프로젝트 Elasticsearch 의존성으로 실행합니다.
CA와 별도 **읽기 전용 API 키 파일**이 필요합니다. 기존 수집 키는 조회 권한이 없어 사용할 수 없습니다.
`deploy/server/capacity-reader-role.json`은 운영자가 검토할 권한 명세이며 자동 계정 생성은 하지 않습니다.
cluster `monitor`/`monitor_snapshot`, 지정 수집 인덱스의 `read`/`monitor`만 요청합니다.
키·삭제·스냅샷 생성/복원 권한은 없지만 인덱스 `read`는 원문 읽기도 허용하므로 신뢰한 운영자만 보유합니다.
이 도구가 원문을 출력하지 않는 것과 ES 필드 접근 통제는 다릅니다.

Linux 키 파일은 소유자 전용 `600`, Windows는 관리자/SYSTEM만 읽을 수 있는 ACL로 준비합니다.
키 값은 명령 인자·Git·보고서·채팅에 넣지 않습니다. 인증서 검증을 끄는 옵션은 없습니다.
관리자 작업 폴더에서 보고서를 비공개 보관하고 기존 보고서를 덮어쓰지 마세요.

```bash
cd ~/cloud-soc
umask 077
mkdir -p state/storage-reports
# Python/CA/키 파일 경로와 HTTPS 주소는 실제 승인된 값으로 교체
.venv/bin/python deploy/server/capacity-report.py measure \
  --endpoint https://<중앙주소>:9200 --ca-file /secure/ca.crt \
  --api-key-file /secure/capacity-reader.key --hours 24 \
  > state/storage-reports/sample-01.json
```

최소 1시간, 권장 대표적인 24시간 뒤 다른 파일명으로 재측정합니다. 야간·주간 표본을 추가하세요.
시간이 겹치는 수신 구간 건수를 더하면 중복 집계됩니다. 비교 명령은 네트워크에 접속하지 않습니다.

```bash
.venv/bin/python deploy/server/capacity-report.py compare \
  --previous state/storage-reports/sample-01.json \
  --current state/storage-reports/sample-02.json --proposed-days 30
```

종료 코드 `0`은 보고 생성, `2`는 스냅샷 주의/순증가 추정 불가, `1`은 실행 실패입니다.
빈 파일·실패 출력을 정상 표본으로 취급하지 않습니다. `30일`은 예시일 뿐 확정/자동 삭제가 아닙니다.
클러스터 교체·인덱스 삭제/재생성·카운터 감소·개별 인덱스 순감소는 추정 불가입니다.
새 인덱스의 과거 데이터, 양의 순증가에 숨은 병합/삭제, replica/translog/백업/병합 여유는 따로 고려합니다.

## 스냅샷 확인과 복원은 다릅니다

이미 등록된 저장소의 **정확한 스냅샷 이름**과 예상 인덱스 이름을 지정합니다.
와일드카드·전체 저장소 조회·새 저장소 등록은 하지 않습니다. 본문/오류 이유는 출력하지 않습니다.

```bash
.venv/bin/python deploy/server/capacity-report.py snapshot \
  --endpoint https://<중앙주소>:9200 --ca-file /secure/ca.crt \
  --api-key-file /secure/capacity-reader.key \
  --repository <저장소명> --snapshot <스냅샷명> \
  --expected-index <정확한-수집-인덱스명> --max-age-hours 48
```

`metadata_ok`는 SUCCESS·완료 shard·예상 인덱스 포함·신선도 대조입니다.
저장소 무결성/다운로드 가능성/복원 성공은 증명하지 않으며 `restore_verified=false`입니다.
48시간은 검토용 오래됨 기준이며 승인된 RPO가 아닙니다.

실제 백업은 같은 VM 디스크와 별도 디스크/외부 저장소를 구분하세요. 같은 디스크의 파일은 VM 소실 대비가 아닙니다.
암호화·권한·복구 주체·백업 비용·보존·RPO/RTO를 먼저 승인한 뒤 운영자가 저장소를 구성합니다.
복원은 별도 클러스터/새 이름에서 수행하고 원본 인덱스를 덮어쓰지 않습니다.
운영 복원에는 문서 수뿐 아니라 승인된 참조·대표 문서·필요 매핑/설정·조회 동작도 대조해야 합니다.
ES 스냅샷은 포털 SQLite·CA/비밀 파일·에이전트 키/큐 백업을 대신하지 않습니다.

## 독립 시험

일반 회귀: `python -m unittest discover -s tests -p 'test_capacity_p2*.py' -v`.
실제 Docker 시험은 별도 명시 활성화한 `test_capacity_p2_live.py`만 실행합니다.
`SOC_TEST_P2_CAPACITY_ES=1`, Windows에서 필요 시 `SOC_TEST_P2_DOCKER_CONTEXT=desktop-linux`을 지정합니다.
미리 준비된 ES 9.5.2 이미지와 로컬 Docker 소켓이 필요하며 자동 pull/운영 접속은 하지 않습니다.
임시 loopback 컨테이너·합성 자격 증명/문서·전용 임시 저장소만 사용합니다.
읽기 전용 역할의 실제 조회/삭제·복원 거부 → 합성 오래된 인덱스 ILM 삭제/최근 인덱스 유지 →
스냅샷을 새 이름으로 복원 → 동일 합성 1건 내용 대조 → 소유 컨테이너 정리를 검증합니다.
이 시험은 운영 저장소/모든 데이터/모든 장애의 복구 보장이 아닙니다.

## 승인 항목

| 항목 | 이번 상태 | 확정할 내용 |
| --- | --- | --- |
| 보존 | 미확정 | 소스별 기간, 예외/사건 보존, 삭제 승인자 |
| 디스크 | 검토값 75%/85% | 임계값, 대응 책임자, 여유 공간/용량 증설 |
| 백업 | 미구성 | VM과 독립된 목적지, 암호화, 접근, 주기/보존/비용 |
| 복원 | 운영 미검증 | 격리 대상, 검증 범위, RPO/RTO, 복원 담당자 |

보존은 조사 보조 기록의 7일/16MiB/2,000건과 별개입니다. 승인 전 삭제 정책을 배포하지 않습니다.

근거: [Count API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-count),
[조회/통계 권한](https://www.elastic.co/docs/reference/elasticsearch/security-privileges),
[스냅샷 조회](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-snapshot-get),
[스냅샷·복원](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore).

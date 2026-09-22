# P5 정규화와 실제 관제 현황

로컬 구현 안내입니다. 이 문서를 작성하면서 AWS/OCI 운영 서버에 배포하거나 실제 로그를 수집하지 않았습니다. **신규 처리기는 정규화 전용이며 탐지 규칙을 실행하지 않습니다.** 기존 `cloud_soc.main`은 AUTH-001을 실행하는 별도 개발 경로이므로 신규 처리기 대신 실행하지 마세요.

## 지원 범위

| 입력 | 동작 |
| --- | --- |
| `soc-host-raw-*` | 지원 Windows Security/Sysmon 메타데이터, 제한된 RFC3164 SSH 로그 정규화 |
| `soc-network-*` | Packetbeat 흐름·DNS·TLS 메타데이터; 프로세스/파일 유출 추정 없음 |
| `soc-cloud-aws-*` / `soc-cloud-oci-*` | 기존 수집기의 CloudTrail/OCI Audit 선별 메타데이터 |
| 미지원 / 필수 조직·발생 시각 누락 | 원본은 그대로 두고 `soc-processing-v1`에 참조와 고정 사유 기록 |

- SSH 연도는 원본 기준 시각으로 추론합니다. `event.timezone`의 UTC 또는 숫자 오프셋이 반드시 필요합니다. 센서 시간대를 확인하고 설정해야 하며 임의 UTC 보정은 하지 않습니다.
- Linux Audit의 여러 레코드 결합, sudo/PAM·계정 변경, 일반 앱 로그 파서는 아직 미연결입니다.
- 새 정규화 결과는 `soc-normalized-v1`에 저장하여 기존 `normalized-events` 기반 탐지기에 자동 유입되지 않습니다. 메시지·명령 인자·파일 본문·원본 PCAP을 결과에 복사하지 않습니다.
- `raw-logs-*`는 기존 처리 경로를 유지합니다. 과거 `security-alerts`의 정확한 참조 조회는 지원하지만, 없는 참조를 재구성하지 않습니다.

## 기존 중앙 서버 업데이트

변경 코드가 서버에 전달된 뒤 `~/cloud-soc`에서 실행합니다. 저장소에 커밋·푸시되지 않은 로컬 변경은 `git pull`만으로 서버에 전달되지 않습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml build bootstrap portal
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml run --rm --no-deps bootstrap
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --no-deps portal
```

bootstrap은 신규 결과/상태 인덱스 3개와 `cloud_soc_normalizer` 역할을 준비하고 관리자 포털 조회 계정에 해당 인덱스·기존 경보/근거의 **읽기 권한**을 추가합니다. 기존 문서·규칙·에이전트·키·보존 정책은 수정하지 않습니다. 매핑 충돌은 자동 덮어쓰지 않습니다. `down -v`나 기존 `state` 삭제가 필요하지 않습니다.

업데이트 후 포털 `/` 또는 `/index.html`이 실제 관제 현황입니다. `/agents.html`은 설치 파일 관리, `/workbench.html`은 여전히 데모입니다. 처리기를 실행하지 않았다면 ‘실행 기록 없음’이 정상적인 표시입니다.

## 선택적 정규화 처리기

이 단계는 실제 로그의 추가 저장과 읽기 권한을 사용합니다. 대상·시작 시각·디스크 여유를 확인하고 명시적으로 실행하세요. 기본 중앙 설치는 이 서비스를 자동 기동하지 않습니다.

1. ES 관리자 권한의 Kibana Dev Tools에서 다음과 같이 만료되는 **전용 API 키**를 생성합니다. 관리자/에이전트 수집 키를 재사용하지 않습니다.

```http
POST /_security/api_key
{
  "name": "cloud-soc-normalizer",
  "expiration": "30d",
  "role_descriptors": {
    "normalizer": {
      "cluster": [],
      "indices": [
        {"names": ["soc-host-raw-*", "soc-network-*", "soc-cloud-aws-*", "soc-cloud-oci-*"], "privileges": ["read", "view_index_metadata"]},
        {"names": ["soc-normalized-v1", "soc-processing-v1"], "privileges": ["create_doc"]},
        {"names": ["soc-pipeline-status"], "privileges": ["index"]}
      ]
    }
  }
}
```

2. 응답의 `encoded` 값은 채팅·Git·셸 명령 인자에 넣지 말고 서버의 보호 파일에 저장합니다. 아래는 Ubuntu Bash에서 입력을 숨기는 예시입니다. 기존 키 파일이 있으면 먼저 중지 및 교체 절차를 결정하고 이 초기 생성 블록은 실행하지 마세요.

```bash
(
  set -e
  sudo test ! -e state/server/secrets/normalizer.key
  sudo install -d -o 1000 -g 1000 -m 700 state/server/processing
  sudo install -o 1000 -g 1000 -m 600 /dev/null state/server/secrets/normalizer.key
  read -r -s -p 'Normalizer encoded API key: ' NORMALIZER_KEY; printf '\n'
  test -n "$NORMALIZER_KEY"
  printf '%s' "$NORMALIZER_KEY" | sudo tee state/server/secrets/normalizer.key >/dev/null
  unset NORMALIZER_KEY
)
```

실패하여 빈 키 파일이 남으면 실행을 중단하고 파일 상태를 확인하세요. 유효기간 만료 전 새 제한 키로 교체하고 이전 키를 폐기해야 합니다.

3. `sudoedit state/server/compose.env`로 `SOC_PROCESSING_START=2026-09-22T00:00:00Z` 같은 **승인된 최초 수신 시각**을 추가합니다. 예시 시각을 그대로 쓰지 말고 처리할 범위를 정하세요. 기존 SQLite 상태가 있는 동안 이 값은 변경할 수 없습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml config --quiet
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml build normalizer
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml up -d --no-deps normalizer
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml -f deploy/server/processing.compose.yaml logs --tail 50 normalizer
```

`bootstrap`을 먼저 성공시킨 뒤 실행합니다. `--no-deps`는 ES/기존 서비스를 재기동하지 않습니다. 중지는 같은 Compose 파일 조합에 `stop normalizer`를 사용합니다. SQLite 상태와 정규화 결과를 삭제하지 않으면 재실행은 체크포인트를 이어갑니다. 가이드의 서비스 기동 자체는 로컬에서 실제 중앙 배포로 검증한 것이 아닙니다.

## 처리 보장과 한계

- 서버 `event.ingested`로 5분씩 진행하고 15분을 겹쳐 재조회합니다. 조회 종료는 현재보다 30초 이전입니다. 과거에 발생했어도 새로 수신된 문서는 처리 대상입니다.
- PIT + `search_after`를 사용하고 페이지당 200건, 한 구간 1,000페이지로 제한합니다. 시간 초과·부분 샤드 실패·권한 오류·쓰기 실패에는 체크포인트를 넘기지 않습니다. 한도를 넘는 구간은 관리자가 처리 용량/분할을 개선해야 하며 자동 건너뛰지 않습니다.
- 원본 인덱스/ID/정규화 버전의 결정적 ID와 create-only 쓰기로 재시작 중복을 방지합니다. 원본이 append-only라는 전제이며 동일 ID를 수정한 문서의 재정규화는 지원하지 않습니다. 결과 인덱스만 복원/삭제하면 체크포인트도 함께 검토해야 합니다.
- ES 쓰기와 SQLite 커밋은 분산 트랜잭션이 아닙니다. 중간 종료는 같은 구간을 재실행하며 처리 기록은 정규화 저장 후 생성합니다. 상태 전송 실패 시 대시보드의 과거 성공 값은 5분 후 지연 상태로 표시됩니다.
- 수신 시각이 없는 과거 문서, 시작 시각 이전 문서, 15분을 넘는 검색 가시성 지연은 자동 복구를 보장하지 않습니다. 과거 자료 재처리는 별도 상태 파일·범위 검토가 필요합니다. 여러 인스턴스를 서로 다른 상태 파일로 동시에 실행하지 마세요.
- `soc-pipeline-status`는 현재 처리기 상태이며 heartbeat/탐지 정상 판정이 아닙니다. `counts`는 이번 재조회에서 관측한 수(재처리 포함), 메인 지표는 중복 제거된 처리 결과 문서 수입니다.
- 새 결과 인덱스의 자동 삭제 정책은 적용하지 않았습니다. 운영 보존·용량·스냅샷 정책은 P2 승인 항목입니다.

## 관제 조회 해석

- 동일한 시작/종료 구간에서 수신/처리 결과/품질 보고는 수신 시각, 경보는 경보 시각 기준입니다. 별도 ES 조회이므로 동시 유입 중 원자적 단일 스냅샷은 아닙니다.
- 성공 0건·인덱스 없음·조회 실패·처리기 실행 기록 없음/지연을 구분하며 샘플 숫자로 대체하지 않습니다.
- 수집 품질은 보고 건수 및 별도 품질 페이지로 연결합니다. 정상 호스트 비율·큐/전송 오류를 이 숫자로 추정하지 않습니다.
- 경보 목록은 최신 50건, 상세는 최대 100개 근거를 개별 조회합니다. 페이지 탐색·규칙별 필터는 후속 과제입니다.
- `경보 → 정규화 문서 → 원본 문서` 참조가 일치할 때만 근거를 표시합니다. 없어진 문서는 누락/만료, 다른 참조는 불일치로 표시합니다. 주변 로그 자동 검색이나 근거 내용 해시 재검증은 하지 않습니다.
- 새 규칙·탐지 서비스·사건 수·담당자·조사 판정 저장은 활성화하지 않았습니다. 규칙별 지원 소스·조건·임계값·버전·기대 결과 승인(P5-03)이 다음 의사결정입니다.

설계 근거: [Elasticsearch 권한](https://www.elastic.co/docs/reference/elasticsearch/security-privileges), [PIT 조회](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-open-point-in-time). 최소 키는 결과 덮어쓰기와 `security-alerts` 쓰기를 허용하지 않습니다.

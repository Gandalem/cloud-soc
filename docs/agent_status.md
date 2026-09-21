# 에이전트 접속 현황

중앙 포털의 **에이전트 → 에이전트 접속 현황** 또는 `https://<공인-IP-또는-도메인>/agent-status.html`에서 확인합니다. 포털 관리자 로그인이 필요합니다. 이 페이지는 샘플이 아니라 Elasticsearch의 실제 수신 데이터를 조회합니다. 기존 Mission Control·조사·로그 탐색 데모의 데이터 연동을 변경하는 기능은 아닙니다.

## 상태의 의미

에이전트를 재설치하지 않고 Filebeat·Packetbeat가 보낸 데이터의 **중앙 서버 수신 시각**으로 활동을 판단합니다. 서비스 실행 여부를 확인하는 heartbeat나 에이전트 등록 기능은 아직 없습니다.

| 표시 | 판정 기준 |
| --- | --- |
| 최근 수신 | 마지막 수신 후 5분 이내 |
| 수신 지연 | 5분 초과, 15분 이내 |
| 장기 미수신 | 15분 초과 |
| 판단 불가 | 수신 시각이 없는 기존 문서, 또는 서버 시각보다 1분 넘게 미래인 수신 시각 |

**장기 미수신은 오프라인을 뜻하지 않습니다.** 새 로그·통신이 없거나 큐 적체, 네트워크·인증 오류, 키 만료, 서비스 중지 등 여러 원인이 가능합니다. 연결 여부를 확정하려면 후속 heartbeat 구현이 필요합니다. 최근 수신 역시 호스트 전체나 두 수집기 모두의 정상 동작을 보장하지 않습니다.

- 수집기별로 호스트명·IP·OS·조직·종류·버전·ID, 마지막 서버 수신 시각, 해당 문서의 원본 이벤트 시각, 조회 범위 문서 수를 표시합니다. 시각은 브라우저의 로컬 시간대입니다.
- `organization.id + agent.id + agent.type`으로 구분합니다. 같은 PC의 Filebeat와 Packetbeat는 별도 행입니다. 재설치로 ID가 바뀌면 별도 행이 생길 수 있습니다. 호스트명·IP·조직·ID는 에이전트가 제공한 메타데이터이며 인증된 자산 식별이나 조직별 접근 격리를 보장하지 않습니다.
- 최근 30일 수신 데이터만 조회합니다. 수신 시각이 없는 기존 문서는 원본 이벤트 시각이 최근 30일인 경우만 보이며 상태는 항상 판단 불가입니다. 오래 조용한 수집기는 목록에서 사라질 수 있어 전체 설치 자산 목록으로 사용하지 않습니다.
- 한 페이지 최대 50개이며 다음/이전 페이지를 지원합니다. 카드 숫자·검색·상태 필터는 **현재 페이지 기준**입니다. 실시간 갱신 목록이므로 페이지를 넘기는 사이 데이터가 달라질 수 있습니다.
- 30초 자동 새로고침과 수동 새로고침을 지원합니다. 숨겨진 탭에서는 주기 조회를 멈춥니다. API 장애 시 이전 정상 표시는 지우고 조회 실패를 표시합니다. 마지막 성공 시각은 별도로 남습니다.
- `agent.id`가 없는 문서는 수집기 행에서 제외하고 건수를 경고합니다. 패키지 생성·다운로드·키 발급만으로 행이 생기지 않습니다. 패키지와 설치 호스트를 연결하는 등록 토큰은 아직 없습니다.

## 기존 중앙 서버 업데이트

새 설치는 설치기가 조회 계정과 수신 시각 기록을 함께 준비합니다. **이미 설치한 AWS Ubuntu 서버**는 아래 순서로 업데이트해야 합니다. 에이전트·인증서·기존 데이터는 지우지 않습니다. `install-ubuntu.sh`, `prepare.py`, `down -v`를 다시 실행하지 마세요.

먼저 이 변경이 포함된 코드를 중앙 서버의 `~/cloud-soc`에 반영합니다. 아직 Git에 커밋·푸시되지 않은 로컬 변경은 서버의 `git pull`만으로 받을 수 없습니다. 서버에 직접 수정한 파일이 있다면 병합 여부를 먼저 검토하세요.

1. SSH에서 아래 명령으로 **조회 계정용 비밀 파일만** 추가합니다. 기존 상태가 기본 경로가 아니라면 `--state /실제/상태/경로`를 지정하세요. 파일 내용은 출력하거나 공유하지 않습니다.

```bash
cd ~/cloud-soc
sudo python3 deploy/server/prepare-monitor.py
```

`state/server`와 `secrets`가 root 소유·0700인 정상 기존 상태만 허용합니다. 새 `monitor_password`는 UID 1000:GID 0·0400으로 만듭니다. 정상 파일이 이미 있으면 재사용하고, 잘못된 권한·불완전한 파일은 자동 덮어쓰지 않고 중단합니다. 기존 포털·Elasticsearch 비밀번호나 CA를 바꾸지 않습니다.

2. 새 이미지를 빌드하고 초기화 작업을 **성공한 경우에만** 포털을 갱신합니다. 수집기 전송은 유지되지만 포털 컨테이너 교체 중 짧은 웹 접속 중단이 있을 수 있습니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml build bootstrap portal &&
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml run --rm --no-deps bootstrap &&
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --no-deps portal
```

이 단계는 Elasticsearch가 실행 중이고 정상이어야 합니다. 초기화는 기존 비밀번호를 그대로 재사용하여 계정을 설정하고, 새 읽기 전용 계정·수신 파이프라인·중앙 템플릿을 준비합니다. 기존 대상 인덱스에는 `event.ingested` 날짜 매핑과 final pipeline 설정만 추가하며, 과거 문서를 재처리하거나 새 수신 시각으로 바꾸지 않습니다. 기존 사용자 정의 final pipeline이나 충돌하는 매핑이 있으면 자동 덮어쓰지 않고 중단하므로 관리자가 검토해야 합니다. 설정 작업은 원자적 트랜잭션이 아니므로 중간 실패 시 원인을 확인한 뒤 같은 명령을 재실행합니다.

3. 상태와 포털 로그를 확인하고 페이지를 새로고침합니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --since 5m --tail 80 portal
```

포털 주소 예: `https://13.208.166.199/agent-status.html`. 현재 서버의 공인 주소·인증서 신뢰 설정을 사용합니다. 이 업데이트에서 AWS 보안그룹·방화벽·포트·인증서 설정을 바꾸지 않습니다.

## 실제 수신 확인

1. 기존 PC에서 Filebeat 서비스가 실행 중인지 확인하고 승인된 테스트 로그를 발생시킵니다. 네트워크 수집은 Packetbeat 서비스와 지정 NIC에서 관측 가능한 통신이 별도로 필요합니다.
2. 페이지를 새로고침하여 자신의 `host.name`, `agent.id`, `agent.type`, 조직 값이 맞는지 확인합니다. 최초 도착 전에는 빈 목록이 정상일 수 있습니다.
3. Kibana에서 해당 인덱스의 최신 문서에 `event.ingested`가 새로 생겼는지 확인합니다. 지연 전송된 오래된 `@timestamp` 문서도 지금 도착했다면 최근 수신으로 표시되어야 합니다.
4. 계속 판단 불가라면 중앙 업데이트 이후 새 문서가 도착했는지 확인합니다. 수신 지연·장기 미수신일 때는 서비스 상태·전송 오류·API 키 만료·서버 연결을 확인하되 오프라인으로 단정하지 않습니다.

## 기술 계약 및 검증

- 관리자 전용 `GET /api/agents/status`는 `soc-host-raw-*`, `soc-network-*`만 조회합니다. `cursor` 외 쿼리 매개변수는 거부하며 페이지 크기·조회 기간을 클라이언트가 늘릴 수 없습니다. 원본 로그 본문이나 키를 응답에 넣지 않습니다.
- 별도 계정 `cloud_soc_agent_monitor`에는 대상 인덱스의 `read`, `view_index_metadata`만 부여합니다. 키 발급 계정·에이전트 쓰기 키에 읽기 권한을 추가하지 않습니다. 관리자는 모든 조직의 목록을 볼 수 있습니다.
- 중앙의 `cloud-soc-received-at-v1` final pipeline이 `event.ingested`를 `_ingest.timestamp`로 덮어써 클라이언트 시각과 분리합니다. 기존 개별 설치용 템플릿 파일은 변경하지 않고 중앙 bootstrap에서만 확장합니다. 따라서 이 기능은 중앙 서버 구성을 대상으로 합니다.
- 조회 제한 시간 초과·샤드 오류·권한 오류 시 HTTP 503으로 처리하며 부분 결과를 정상으로 표시하지 않습니다. API는 최대 50개 결과로 제한하지만 집계 비용은 전체 조회 범위에 비례할 수 있습니다. 대규모 운영에는 별도 상태 인덱스·캐시·heartbeat가 필요합니다.

오프라인 회귀 테스트:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
node --test prototype/tests/agent-status.test.cjs
```

선택적 실제 Elasticsearch 테스트는 Docker 로컬 데몬과 미리 받은 `docker.elastic.co/elasticsearch/elasticsearch:9.5.2` 이미지가 필요합니다. 루프백 임시 포트·합성 계정과 문서만 사용하며, HTTP 전송은 이 격리 테스트에만 사용합니다. 테스트 종료 시 자신이 만든 컨테이너·볼륨만 정리합니다. 원격 AWS·기존 SOC 컨테이너·실제 에이전트·패킷 캡처는 건드리지 않습니다.

```powershell
$env:SOC_TEST_AGENT_STATUS_ES = '1'
try {
    .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_agent_status_live.py -v
} finally {
    Remove-Item Env:SOC_TEST_AGENT_STATUS_ES
}
```

실제 ES 테스트는 서버 시각 덮어쓰기, 기존 문서 보존, 페이지 이동, 최소 권한 쓰기 키의 전송, 조회 계정의 쓰기·키 발급 차단을 검사합니다. 실제 AWS 배포와 Windows 서비스의 데이터 도착은 위 실제 수신 확인 절차로 별도 검증해야 합니다.

# 통합 로그 사용·검증 안내

2026-09-22: P1-02/03 코드 및 격리 시험 완료. **AWS 배포·실제 에이전트 수신 검증은 아직 별도**다. 작업별 상태는 [작업 목록](work_tracker.md), 필드 정의는 [조회 계약](log_query_contract.md)을 확인한다.

## 사용 방법

중앙 HTTPS 포털에 관리자로 접속한 뒤 **통합 로그**를 연다. 경로는 `/logs.html`이다. 기존 에이전트 설치 파일/접속 현황 메뉴에서도 접근할 수 있다.

1. 기본은 최근 1시간의 서버 수신 시각이다. 필요하면 최근 24시간/7일/30일 또는 직접 지정(KST)을 선택한다.
2. 호스트명 완전 일치, OS, 수집기, 단일 IPv4/IPv6 주소로 필터링하고 **조회**를 누른다. IP는 호스트·출발지·목적지 중 일치하는 문서를 찾는다.
3. 문서 ID를 눌러 제한된 메타데이터 상세를 확인한다. 인덱스+문서 ID로 원본 참조를 보존한다. 본문과 전체 원문은 이 화면에서 제공하지 않는다.
4. **다음**으로 동일 스냅샷의 다음 페이지를 조회한다. **이전**은 방문한 페이지의 메모리 캐시이며 최대 최근 20페이지다. 임의 페이지 번호 이동은 제공하지 않는다.
5. 새로 도착한 로그를 보려면 **새로고침**한다. 이전 조회 조건·페이지는 초기화되고 현재 폼의 조건으로 첫 페이지를 조회한다.

전체 로그 수/공격 수는 표시하지 않는다. 현재 페이지 문서 수만 보여준다. 로그 시각은 `@timestamp`이며 입력/파서에 따라 실제 행위 시각과 다를 수 있다. 수신 시각이 없는 과거 기록은 **로그 기준 시각**으로 조회한다. 미관측 값을 추측해 채우지 않으며 해석 상태는 아직 **미평가**다.

## 배포 전제

새 코드가 중앙 서버 체크아웃에 반영된 후 실행한다. 미커밋 로컬 변경은 서버의 `git pull`로 가져올 수 없다.

- 기존 서버의 조회 계정과 서버 수신 시각 설정은 [에이전트 현황 업데이트 절차](agent_status.md)를 먼저 완료한다. 이미 설정했다면 새 역할·비밀번호를 만들 필요가 없다.
- 추가 인덱스/역할/에이전트 재설치는 필요하지 않다. 포털 이미지 재빌드만 필요하다.
- 실제 ES에는 `soc-host-raw-*` 또는 `soc-network-*` 문서가 있어야 한다. 설치 패키지 생성만으로 문서가 생기지 않는다.

```bash
# 중앙 서버 ~/cloud-soc에서, 해당 코드 반영 및 기존 조회 계정 준비 후
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --build --no-deps portal
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps
```

기존 CA·비밀번호·데이터·볼륨을 삭제하거나 전체 초기 설치를 재실행하지 않는다. 포털만 바뀌며 탐지 규칙이나 처리 서비스는 이 변경에서 활성화하지 않는다. 브라우저 새로고침 후 **샘플 로그가 아니라 해당 서버에 실제 있는 문서**가 나오는지 확인한다.

## 실패 구분

| 상태 | 의미와 조치 |
| --- | --- |
| 정상 빈 목록 | 해당 시간/필터 문서가 없음. 시간 기준·호스트 완전 일치 여부 확인 |
| 400 | 미지원/중복 파라미터 또는 잘못된 커서. 첫 페이지 재조회 |
| 401/403 | 관리자 인증/접근 정책 실패. 인증·접속 주소 확인 |
| 404 | API가 없는 이전 서버 또는 삭제/만료 문서. 배포 상태·문서 참조 확인 |
| 410 | 스냅샷 만료. 새로고침. 마지막 요청 후 90초 또는 조회 시작 후 10분 제한 |
| 413 | 응답 한도 초과. 페이지 크기나 범위를 줄임. 조용히 일부만 표시하지 않음 |
| 503 | 조회 계정 미설정, ES 연결/권한, 시간/검색 필드 매핑, 부분 shard 실패 등. 보호된 서버 설정 확인 |

OS와 IP 필터는 서로 다른 기존 매핑에서도 동일한 의미를 유지하도록 서버에 고정된 runtime field 스크립트를 사용한다. 인덱스 매핑은 변경하지 않는다. runtime 쿼리는 추가 비용이 있고 `search.allow_expensive_queries=false`이면 실패할 수 있다. 이때 클러스터 제한을 자동 해제하지 않으며 503으로 표시한다. 대량 운영은 기간 축소와 P2 저장/성능 계획이 필요하다. [Elastic runtime field 안내](https://www.elastic.co/guide/en/elasticsearch/reference/current/runtime.html)

관리자 응답에 ES 오류 본문·자격증명은 포함하지 않는다. 커서는 서명되어 관리자·조회 조건·만료와 결합되며, 후속 요청에는 커서만 보낸다. 읽기 계정은 기존 두 수집 인덱스에만 접근한다. 전체 원문 조회를 켜는 우회 플래그는 없다.

## 로컬 검증

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test prototype/tests/*.test.cjs
```

격리 ES 시험은 Docker 엔진과 이미 내려받은 `docker.elastic.co/elasticsearch/elasticsearch:9.5.2` 이미지가 필요하다. 자동 이미지 다운로드 없이 127.0.0.1의 임시 포트로 컨테이너를 실행하고 종료 시 해당 컨테이너와 임시 볼륨만 정리한다. 운영 서버나 에이전트에는 연결하지 않는다.

```powershell
$env:SOC_TEST_AGENT_STATUS_ES = '1'
try {
  .\.venv\Scripts\python.exe -m unittest discover -s tests -p test_agent_status_live.py -v
} finally {
  Remove-Item Env:SOC_TEST_AGENT_STATUS_ES -ErrorAction SilentlyContinue
}
```

이 시험에 [실제 로그 쿼리 검사](../tests/log_query_live_checks.py)가 포함된다. 합성 호스트/네트워크 문서, OS·IP 필터, 동일 시각 61건의 연속 조회, 조회 도중 새 문서 추가, 별칭 거부, 매핑 충돌·커서 만료를 확인한다. 이는 실제 에이전트 수집 성공을 뜻하지 않는다.

UI만 확인할 때는 `.\.venv\Scripts\python.exe tests/preview_logs.py`를 실행하고 `http://127.0.0.1:8769/logs.html`을 연다. **합성 UI 전용이며 실제 API/인증 통합 시험이 아니다.** 호스트에 `no-such-host`를 넣으면 빈 목록, `unavailable`이면 합성 오류가 나온다. `Ctrl+C`로 종료한다. 이 서버를 외부 공개하거나 운영 배포에 사용하지 않는다.

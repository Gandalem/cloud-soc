# P2 수집 보호·품질 운영 가이드

이 문서는 **로컬 구현과 격리 검증**의 적용 범위를 설명합니다. AWS 배포, 실제 Windows/Ubuntu 서비스 전환, 보존 기간 승인이 완료되었다는 뜻이 아닙니다. 현재 포털은 단일 관리자용이며 조직별 권한 격리 제품이 아닙니다.

## 1. 민감정보 처리

| 지점 | 처리 | 제한 |
| --- | --- | --- |
| 소스 탐색 | 홈/전체 드라이브 금지, 알려진 개인키·인증서·환경변수·문서·비밀 파일 경로 제외 | 승인한 로그 폴더 안의 모든 텍스트가 안전하다는 보장은 없음 |
| Filebeat/Packetbeat | `privacy.js`가 전송·디스크 큐 진입 전에 민감 필드 제거/문자열 마스킹 | 새 설치 설정부터 적용. 기존 큐와 ES 문서는 다시 쓰지 않음 |
| 포털 목록/상세 | 허용한 메타데이터만 반환하고 의심 문자열은 다시 마스킹 | 전체 원문·본문·CSV 내보내기는 계속 제공하지 않음 |
| 오류 | 조회 실패 시 원문/상위 서버 예외 내용을 응답에 넣지 않음 | 운영자는 수집기 진단 로그도 보호해야 함 |

`password`, `secret`, `token`, 인증 헤더/쿠키, 명령 인자·명령줄, `event.original`, XML·본문 같은 필드는 제거합니다. Windows `include_xml`도 비활성화했습니다. 비밀번호 대입, Bearer/Basic, 자격증명이 붙은 URL, 쿼리/fragment가 있는 HTTP URL, 알려진 AWS 키/JWT/PEM 표식을 발견한 문자열은 **일부분이 아니라 전체를 `[REDACTED]`**로 바꿉니다. 배열에 민감 항목이 있으면 배열 전체를 가립니다. 일반 Linux 인증 실패 메시지와 이벤트 코드는 유지합니다.

P3에서 `privacy_policy=v2`로 보완했습니다. Windows 렌더링 `message`와 예약 작업 XML/스크립트 본문은 중복된 명령 인자 누출을 막기 위해 제거합니다. 네이티브 Linux 감사 인자 레코드(EXECVE/PROCTITLE/USER_CMD)는 전송하지 않고 SYSCALL/PATH를 유지합니다. 범위·미지원 포맷·기존 에이전트 적용 제한은 [P3 감사 가이드](host_security_audit.md)를 확인하세요.

문자열 8,192자 초과는 가리고, 깊이 12·노드 4,096 제한이나 처리 오류 시 이벤트를 버립니다. 스크립트 제한 시간 초과 이벤트도 후속 `drop_event`에서 버립니다. 안전한 실패를 우선하므로 이것은 손실 없는 수집 정책이 아닙니다. 정상 조사 정보가 가려지는 오탐도 가능합니다.

정규식은 완전한 DLP가 아닙니다. 이름 없는 비밀값, 인코딩된 값, 여러 줄로 쪼개진 키 본문, DNS 이름에 인코딩된 정보 등은 모두 식별할 수 없습니다. **민감 파일의 본문 수집이 아니라 접근 행위 감사가 필요한 경우 P3 감사 기능으로 처리**합니다. 소스별 검토 없이 개인 문서 경로를 수집 루트로 추가하지 마세요.

기존 `soc-host-raw-*`와 Kibana에는 과거 비마스킹 문서가 남아 있을 수 있습니다. 포털 차단은 Kibana/ES에서의 필드별 접근 제어가 아닙니다. Kibana 조회 계정은 신뢰한 운영자에게만 주고, 다중 사용자 도입 전 별도 역할·원문 접근 감사 설계가 필요합니다. 과거 문서 삭제/재처리는 승인 없이 수행하지 않습니다. 마스킹된 로그는 원본 파일과 동일한 법적 원본으로 취급하지 않습니다.

구현: [마스킹](../deploy/agents/privacy.js), [포털 표시 보호](../src/cloud_soc/portal/privacy.py). Beats 처리 API 근거: [Elastic Script Processor](https://www.elastic.co/docs/reference/beats/filebeat/processor-script).

## 2. 중앙 수집 품질 화면

접속 현황 화면에서 **수집 품질** 링크를 열거나 `https://<중앙주소>/collection-health.html`로 접속합니다. 포털 관리자 인증이 필요합니다.

- Filebeat가 로컬 `health.ndjson`을 파싱하여 TLS·기존 keystore 방식의 수집 키로 `soc-agent-health-*`에 전송합니다. 호스트 로그/네트워크 인덱스와 별개이므로 기존 로그 건수와 접속 현황을 부풀리지 않습니다.
- 호스트/조직, 선택·제외·탐색 오류 수, 생성/서버 수신 시각, 지연, 정책 버전, 소스별 상태를 표시합니다. 최신 30일, 페이지당 50개 수집기입니다.
- 소스 이름/경로는 로컬 `discovery-report.json`에만 남기고 중앙에는 SHA-256 ID와 상태를 보냅니다. Windows는 이름의 소문자 UTF-8, Linux는 경로의 원래 UTF-8을 해시합니다. 경로 사전 대입이 가능하므로 익명화 보장은 아닙니다.
- 소스별 목록은 첫 200개이며 나머지는 생략 수로 표시합니다. Linux는 파일 탐색 결과로 journald 접근 여부를 포함하지 않습니다. Windows는 채널과 파일·디렉터리를 포함합니다.
- `selected`는 입력 설정에 포함되었다는 뜻이지 실제 읽기·전송 성공이 아닙니다. 보고 수신도 해당 호스트의 모든 수집 기능이 정상이라는 의미가 아닙니다.
- 큐 사용량·전송 오류 계측은 아직 구현되지 않아 항상 **미측정**입니다. 보고가 없거나 오래되면 실제 오프라인으로 단정하지 않습니다. 생성 시각이 수신 시각보다 미래면 시계 경고를 표시합니다.
- 보고용 파일은 약 5MiB 단위로 1회 회전합니다. 장기 장애 시 오래된 미수신 보고는 유실될 수 있습니다. 보고 생성 실패 시 timer/예약 작업 오류와 로컬 수집기 로그를 확인하세요.

`agent.id`, 조직, 호스트명은 에이전트가 제출한 값입니다. 수집 키 인증은 호스트 신원 증명/조직 격리/서명된 상태 증명이 아닙니다. 보고 조작이 가능한 침해 호스트를 정상 판정하는 근거로 단독 사용하지 않습니다.

### 중앙 서버 반영 순서

1. 검토한 코드를 서버로 반영하고 [기존 중앙 서버 업데이트](agent_status.md#기존-중앙-서버-업데이트)를 실행합니다. bootstrap이 상태 인덱스 템플릿·서버 수신 시각·조회/발급 역할을 준비합니다. 저장 데이터·CA·기존 비밀번호는 삭제하지 않습니다.
2. **새 설치 패키지와 새 호스트 수집 키를 발급**합니다. 이미 SQLite에 저장된 ZIP/tar.gz와 기존 키는 자동 갱신되지 않습니다. 새 키에는 `soc-agent-health-*`의 쓰기 권한이 추가됩니다. 네트워크 키 권한은 확대하지 않습니다.
3. 승인된 테스트 호스트의 새 설치부터 검증합니다. 구버전 설치 프로그램을 기존 서비스 위에 다시 실행하지 마세요. 기존 에이전트 바이너리/전체 설정 자동 업그레이드는 아직 지원하지 않습니다.
4. 로컬 `discovery-report.json`, 중앙 품질 보고의 시각/카운터, 실제 고유 테스트 로그 도착을 각각 확인합니다. 어느 하나만 보고 전체 수집 완료로 체크하지 않습니다.

## 3. 저장량·보존 계획

`storage-report.py`는 조회 전용입니다. ES 인덱스의 문서 수·primary/전체 저장량·색인 작업 수·마지막 수신 시각과 노드 가용 디스크를 읽습니다. 관리 권한을 가진 bootstrap 컨테이너에서 명시적으로 실행하며 **포털 권한을 관리자로 확대하지 않습니다**.

아래 `30일`, 경고 `75%`, 위험 `85%`는 검토용 수치일 뿐 승인되거나 ES watermark에 적용된 값이 아닙니다.

```bash
cd ~/cloud-soc
umask 077
mkdir -p state/storage-reports
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml \
  run --rm --no-deps --entrypoint python bootstrap \
  /app/deploy/server/storage-report.py --proposed-days 30 \
  > state/storage-reports/first.json
```

실패하면 출력 파일을 정상 보고로 사용하지 마세요. 이전 보고를 덮어쓰지 않도록 매번 다른 파일명을 사용합니다. 최소 1시간, 권장 대표적인 24시간 이상 뒤 두 번째 측정을 하고 `--previous /run/previous.json`을 지정하면 순증가 추정치를 추가합니다. 파일은 명시적으로 읽기 전용 마운트합니다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml \
  run --rm --no-deps -v "$PWD/state/storage-reports/first.json:/run/previous.json:ro" \
  --entrypoint python bootstrap /app/deploy/server/storage-report.py \
  --proposed-days 30 --previous /run/previous.json \
  > state/storage-reports/second.json
```

컨테이너 UID 1000이 이전 보고를 읽을 수 있도록 서버 관리자가 최소 읽기 권한을 준비해야 합니다. 보고에는 비밀번호는 없지만 인덱스명/용량 정보가 있으므로 공개하지 않습니다. 처음부터 JSON을 안전한 관리자 작업 경로에 보관하고 Git에 추가하지 마세요.

순증가량은 실제 전송 바이트나 총 유입량이 아닙니다. 병합·삭제·재색인 영향을 받으며 인덱스 재생성/삭제, 순감소, 1시간 미만 표본은 추정 불가입니다. replica·translog·백업·병합 여유 공간·다른 서비스 사용량은 별도로 더해야 합니다.

보존 검토 후보는 해당 인덱스의 마지막 `event.ingested`가 기준보다 오래되고 수신 시각 결측이 없는 경우입니다. 후보라고 삭제하지 않습니다. 활성 writer, 지연 로그, 사고 조사 보존, 법적 요구, 복구 가능한 백업을 검토해야 합니다. `lifecycle_proposal()`도 정책 JSON만 생성하며 운영 적용 API/삭제 버튼은 제공하지 않습니다. ILM의 인덱스 나이와 문서 수신 시각은 다르므로 후보 보고와 ILM 정책을 같은 판정이라고 간주하지 마세요.

### 백업·복구

포털 사건/메모와 설치 패키지/발급 이력은 [포털 SQLite 백업·격리 복원](portal_backup.md) 도구를 추가했습니다. 기존 경로를 덮어쓰지 않으며 표준 라이브러리만 사용합니다. ES 스냅샷·CA/비밀 파일·에이전트 큐 백업과 운영 복구는 이 도구의 범위 밖입니다.

격리 테스트는 임시 ES에서 30일 ILM 제안 정책을 쓰고, 90일 된 합성 인덱스 삭제·새 인덱스 유지·스냅샷의 다른 이름 복구를 검사합니다. 운영 서버에 이 정책이나 테스트 저장소를 복사하지 않습니다.

운영 백업 저장소는 아직 구성하지 않았습니다. 먼저 별도 디스크/S3 등 목적지·암호화·접근 주체·보존 기간·비용을 승인하고 구성해야 합니다. 공유 파일 저장소는 모든 관련 노드의 마운트와 `path.repo` 설정이 필요합니다. [Elastic 파일 시스템 저장소 문서](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/shared-file-system-repository).

실제 적용 전에 스냅샷 성공뿐 아니라 별도 이름/격리 환경으로 복원 후 문서 수·고유 테스트 문서를 대조하세요. ES 스냅샷은 포털 SQLite, CA/비밀 파일, 에이전트 registry/큐까지 자동 백업하지 않습니다. 이 자료는 별도 보호 백업이 필요합니다. 살아 있는 ES 데이터 디렉터리를 단순 복사하는 것을 검증된 스냅샷 대체로 사용하지 마세요.

## 4. 로컬 수집 경로 정책 갱신

`deploy/agents/policy.py`는 **정책 v1을 지원하는 설치된 Filebeat 탐색기**의 경로/제외 목록만 바꾸는 도구입니다. 원격 명령·바이너리 교체·서비스 설치·키 변경 기능은 없습니다. Python 3.10 이상이 필요하지만 기본 에이전트 실행/설치에는 Python이 필요하지 않습니다. 구버전 탐색기는 지원 표식이 없어 변경 전에 중단합니다.

Windows 예시 정책 JSON:

```json
{
  "roots": ["C:\\Windows\\Logs", "C:\\Windows\\System32\\LogFiles", "C:\\ProgramData\\logs", "D:\\MyApp\\logs"],
  "exclusions": ["D:\\MyApp\\logs\\private"]
}
```

`roots`는 추가분이 아닌 **전체 파일 수집 루트 목록**입니다. 존재하는 승인 디렉터리만 지정하고, 현재 기본 경로 중 없는 것은 환경을 검토해 제외합니다. Windows 이벤트 채널과 Linux journald의 범위는 이 정책으로 변경하지 않습니다. 제외는 glob/정규식이 아니라 정확한 파일 또는 디렉터리와 그 하위 경로입니다. 내용 필터나 이벤트 ID 필터가 아닙니다.

관리자 터미널에서 먼저 검토하고 명시적으로 적용합니다. `approved-policy.json`은 검토한 정책 파일의 경로로 바꾸세요.

```powershell
python deploy/agents/policy.py --policy approved-policy.json
python deploy/agents/policy.py --policy approved-policy.json --apply --expected-version 0
# v1 적용 후 v0 설정으로 복구: 새 버전 v2로 기록
python deploy/agents/policy.py --rollback-version 0 --apply --expected-version 1
```

Ubuntu에서는 같은 인자를 `sudo python3 deploy/agents/policy.py ...`에 전달합니다. 예시 Linux 정책은 `{"roots":["/var/log","/srv/myapp/logs"],"exclusions":["/srv/myapp/logs/private"]}`입니다. 각 파일이 아니라 승인한 로그 디렉터리만 추가하세요.

도구는 탐색기와 같은 `discovery.lock`을 사용하고 정책 버전이 바뀌었으면 거부합니다. `collection-policy.txt` 하나를 원자적으로 교체하며 기존 입력 ID·`data/registry`·`data/diskqueue`·keystore를 수정/삭제하지 않습니다. `policy-history`의 이전 정책과 prepared 기록을 남기며 **현재 파일의 SHA-256과 기록의 digest가 일치해야 실제 발행된 정책**입니다. 실패한 prepared 기록도 남을 수 있습니다. 관리자가 보호된 정책 파일을 직접 수정하는 것은 지원하지 않습니다.

다음 탐색 주기와 Filebeat reload 뒤 로컬 보고/중앙 `policy_version` 및 실제 신규 로그 도착을 확인하세요. `applied=true`는 정책 파일 교체 성공일 뿐 소스 읽기·전송 검증이 아닙니다. 제외해도 이미 큐에 들어간 데이터는 폐기하지 않으므로 나중에 전송될 수 있습니다. 복구해도 제외 기간에 사라진 로그를 되살리지는 못합니다.

**아직 남은 작업:** 기존 구버전 에이전트의 전체 설정/코드 이행 도구, 실제 Ubuntu systemd·Windows 서비스의 큐 보존 갱신 시험, 큐/전송 오류 실측, 승인된 보존·운영 백업 구성, 다중 사용자 권한과 원문 접근 감사. [작업 목록](work_tracker.md)의 P2는 이 조건까지 충족하기 전 전체 완료로 표시하지 않습니다.

# 공통 런타임 설치·업그레이드

중앙 서버는 이제 `deploy/server/compose.yaml` 하나로 포털·수집 상태 정리·ES·Kibana·게이트웨이와 아래 여섯 워커를 실행한다. `runtime.compose.yaml`은 이 파일이 참조하는 공통 정의다. 서버마다 명령을 따로 복사하거나 과거 overlay를 새 구성 위에 추가하지 않는다.

| 워커 | 역할 | 보존/분리하는 상태 |
|---|---|---|
| normalizer | 기존 수신 적체 정규화 | 기존 시작점·SSH 형식 floor·미완료 스캔 |
| normalizer-priority | 최근 수신 우선 정규화 | 고정된 별도 수신 시작점 |
| detector | 기존 AUTH·초기 통지 | 기존 identity·frontier·쿨다운·통지/전달 outbox |
| detector-priority | 최근 AUTH 위험 평가 | 별도 DB·상태 보고, 동일 불변 경보 ID |
| detector-additional | 검증된 추가 룰 | AUTH와 별도 DB·상태 보고 |
| detector-retrospective | 늦게 정규화된 로그 재평가 | 별도 수신 spool·review job·재시도 ledger |

`runtime-policy.json`이 버전·마이그레이션 ID·룰 revision·필수 워커·메모리 예산을 정한다. 운영 허용 목록은 실제 인수한 AUTH-001, AUTH-SEQ-001, AUTH-SPRAY-001, ATTACK-01, WIN-AUTH-001, WEB-404-001, NET-PORT-001이다. 룰 파일이 바뀌어 revision이 달라지면 검증 기록/정책 버전의 명시적 갱신 전에는 활성화를 거부한다. AWS/OCI의 격리 검증 성공을 실제 운영 인수로 바꾸지 않는다.

## 신규 설치

기존 `install-ubuntu.sh`가 OS·주소·포트·Docker·커널과 초기 인증서를 준비한 후 아래 공통 관리자의 `install --build`를 호출한다. 초기 계정 준비는 `initialization` 프로필의 bootstrap에서 신규 설치에만 실행한다. 일반 `compose up`이나 기존 서버 업그레이드는 bootstrap의 비밀번호/계정 초기화를 재실행하지 않는다.

```bash
sudo sh deploy/server/install-ubuntu.sh --host 실제주소 --bind-ip 실제사설IP
```

실제 수집기가 아직 없는 신규 서버에서는 실행 준비만 확인할 수 있다. 관리자는 설치 후 아래 `verify`로 실제 수신/탐지까지 별도로 확인한다. `--startup-only`는 그 인수를 대신하지 않는다.

## 기존 서버 업그레이드

검토한 소스를 받은 별도 체크아웃/릴리스 디렉터리에서 먼저 빌드 전 자원 계획을 확인하고 후보 이미지를 빌드한다. 이미지 태그는 배포 계획에서 고정한 digest와 실제 파일 해시로 다시 확인한다. 아래는 서버 로컬 Docker를 사용하며 원격 Docker context와 상속된 SOC/Compose 환경 변수로 대상을 바꾸지 않는다. Compose v2.20 이상이 필요하다.

```bash
sudo python3 deploy/server/manage.py plan --before-build --state /실제/state/server --build-budget-mib 4096 --ingress-reserve-mib 1024 --plan /실제/state/server/build-budget.json
sudo docker build -f deploy/server/Dockerfile -t cloud-soc-runtime:reviewed .
sudo python3 deploy/server/manage.py plan --state /실제/state/server --image cloud-soc-runtime:reviewed --plan /실제/state/server/runtime-plan.json
sudo python3 deploy/server/manage.py apply --plan /실제/state/server/runtime-plan.json
```

계획에는 서버 사양, 전체 메모리 한도+여유 예산, Docker/state 디스크의 실제 여유, DB 두 벌 백업 공간, 기존 실행 명령·mount·site 주소 차이, 새 워커, 누락된 인덱스·역할/API키 권한이 나타난다. 인증 값은 출력하지 않는다. 실제 image 파일 검증·기존 DB identity 확인·권한 scope 검토를 통과해야 한다. 계획 이후 구성/권한/후보가 바뀌거나 자원이 부족하면 서비스를 멈추기 전에 거부한다.

빌드 전 계획은 적용할 수 없다. `--build-budget-mib`는 신규 이미지와 임시 빌드 공간을 합친 운영자 지정 상한이며, 빌드가 끝난 뒤 전체 `plan`을 새로 만든다. 기본 로그 유입 예약은 1GiB다. 배포 시간과 실제 수신율에 맞게 두 상한을 늘린다. 무제한 빌드나 로그 유입까지 공간을 보장하는 값은 아니다. 기존 이미지/백업은 현재 사용량으로 취급하고 다시 추가 사용량에 합산하지 않는다. 이미지 Size는 공유 레이어가 있으므로 단순 합계를 실제 점유량으로 표시하지 않는다.

디스크 검사는 state·사전 검사 임시 사본·Docker root·실제 ES data mount·백업 경로를 `st_dev`로 묶어 장치별 단계 최대 사용량을 계산한다. SQLite 본체+WAL, 온라인/중지 후 백업, 인수 사본, 빌드 상한, 추가 로그 공간과 ES의 실제 low/high/flood-stage 및 max_headroom을 포함한다. ES의 cluster defaults/node/persistent/transient 설정을 읽으며 보호 설정이 꺼졌거나 저장 장치를 입증할 수 없으면 거부한다. 온라인 백업 후 남은 단계의 예산도 쓰기 중지 전에 다시 계산한다. 원본 WAL에는 checkpoint/truncate를 수행하지 않는다.

신규 ES는 시작 전 고정 이미지의 기본값을 추정치로 표시하고 bootstrap 전에 실제 설정을 다시 확인한다. 기존 ES에는 실제 관측만 사용한다. native ext2/3/4·XFS의 mount 정보를 확인하고, 공유 풀·원격·휘발성 파일시스템(Btrfs/ZFS/NFS/CIFS/overlay/tmpfs)은 독립 공간을 자동 추정하지 않고 거부한다. Docker의 mount 배열은 정렬해 단순 반환 순서 변화가 stale 판정을 만들지 않으며, Compose null 명령의 이미지 상속과 실제 설정 변경을 구분한다.

외부 백업은 `plan --backup-root /별도장치/보호디렉터리`로 지정한다. root 소유의 기존 비공개 디렉터리이며 state·Docker·ES와 실제 파일시스템 장치가 달라야 한다. 다른 폴더나 같은 장치의 bind mount는 외부 장치로 인정하지 않는다. 파일시스템 분리가 독립 물리 DR을 입증하는 것은 아니다. 같은 파일시스템을 공유하는 온라인/중지 후 사본은 검증 해시가 같을 때만 hard link로 중복 저장을 줄이고, manifest에 하나의 물리 복구 객체임을 명시한다. 기존 실패 백업과 이미지는 자동 정리하지 않는다.

기존 운영 명령은 Docker label의 파일 목록과 일치하는 `compose.active.json` 영수증으로 식별한다. 경로를 추정하거나 임의 파일의 명령을 실행하지 않는다. 영수증을 찾지 못하면 먼저 기존 배포 명령을 보호 기록으로 남겨야 한다.

계획은 실행 중/중지됨/활성 정의에 없는 잔존 컨테이너를 구분한다. 활성 Compose에 없는 실행 중 서비스는 우선 복귀해야 하며, 중지된 신규 서비스 이름을 구형 `compose stop`에 넣지 않는다. 이전 구성의 이미지·환경·mount·프로젝트가 관측 실행과 일치하는지 확인하고 보호된 `previous.compose.json`에 이미지 ID를 고정한다. 복귀는 필요한 서비스만 `up --no-deps --no-build --pull never`로 시작하고, 건강한 이전 ES/워커는 유지한다. bootstrap 의존성이 있어도 초기화는 실행하지 않는다. 복귀의 readiness·실행 signature·워커 중복 검증이 끝나야 pending을 정리한다. 같은 관리형 소스·이미지·실행 signature가 유지되면 apply는 `unchanged: true`를 반환하고 재시작하지 않는다.

001 마이그레이션은 기존 데이터를 변경하지 않는 mapping 추가와 정확한 런타임 권한을 준비한다. 기존 사용자/비밀번호는 변경하지 않으며, 기존 API키는 ID·토큰·만료를 유지하고 필요한 descriptor만 추가한다. 폐기/만료 키, DLS/FLS 제약, 알 수 없는 역할/상태 scope는 자동 교체하지 않는다. 신규 설치의 키만 보호 경로에 신규 발급한다.

002 마이그레이션은 기존 SQLite를 온라인 백업·무결성·격리 memory restore로 확인하고, 워커 중지 후 일관된 사본을 공통 `state/server/runtime/state/<worker>`로 옮겨 이어 처리한다. 원래 DB·체크포인트를 지우거나 되감지 않는다. 기존 priority/additional/회고 DB도 발견하면 정확한 identity 그대로 인수한다. 없는 워커만 명시적 최근 수신 floor와 새 DB를 얻는다. 이미 활성화한 관리 상태를 다시 초기화하지 않는다.

`runtime/migrations.json`은 단계의 applying/applied/failed와 버전을 기록한다. 실패한 미활성 사본은 보존하고 원래 실행으로 복귀한다. 재시도는 원래 서버에서 계속 전진한 최신 DB를 다시 백업해 인수한다. 인덱스/권한의 호환 가능한 추가와 발급된 신규 키는 영수증/백업에 남기며 앱 복귀가 schema rollback이나 DB 과거 복원을 뜻하지 않는다. 미래 버전 ledger의 다운그레이드는 거부한다.

키 생성은 발급 의도→보호 secret 저장→로컬 공개의 상태를 먼저 journal에 기록한다. 이미 발급/저장한 키와 소유권 변경 단계는 재사용한다. ES 발급 성공 직후 응답이 유실되어 secret을 저장하지 못한 경우에는 자동 재발급하지 않고 적용 전에 명시적 대조를 요구한다. ES는 기존 API secret을 다시 조회할 수 없으므로 이 경우 자동 성공으로 처리할 수 없다. 신규 bootstrap도 running/complete 영수증으로 한 번만 실행하며, running 상태에서 끊겼다면 초기화 결과의 명시적 대조가 필요하다. journal/pending/metadata는 파일과 부모 디렉터리까지 fsync한다.

프로세스 강제 종료/전원 중단으로 `runtime/pending.json`이 남으면 새 계획/적용은 거부한다. `sudo python3 deploy/server/manage.py recover --state /실제/state/server`로 보호된 journal의 기존 실행을 복구한 뒤 다시 계획한다. SQLite를 과거 사본으로 덮어쓰지 않는다. 중단된 신규 설치에서는 고정 시작점·이미 준비된 상태를 보존해 `install`을 재시도한다. 수동 `docker run`, 다른 Compose project, 복제본이나 이름을 바꾼 SOC 워커가 실행 중이면 중복 실행을 피하기 위해 적용 전에 중단한다. 해당 워커를 임의 삭제하거나 자동 종료하지 않는다.

서버별로 보존할 것은 사이트 주소·CA·계정/정책 파일·허용 CIDR·데이터 mount다. 워커 유무·권한·룰 선택·Kibana heap은 공통 버전에서 관리한다. Kibana는 1536MiB 한도와 1024MiB Node heap을 함께 선언하며, 전체 예산을 충족하지 못하는 서버에서는 적용을 중단한다.

메모리 판정은 총 RAM 외에도 Linux `MemAvailable`과 실행 중인 관리 컨테이너별 working set을 측정한다. 교체 후 확보할 수 있는 메모리가 모든 컨테이너 한도와 512MiB 여유분보다 작으면 적용을 거부한다. 다른 컨테이너·OS의 점유분을 관리 서비스의 회수 가능량에 넣지 않는다. 예산/사용량은 계획에 기록하고 적용 직전에 다시 측정한다. SQLite 백업은 운영 연결의 온라인 backup API로 커밋된 WAL 프레임까지 읽고, 복사본만 standalone DELETE journal로 바꿔 무결성/격리 복원을 확인한다. 운영 WAL의 checkpoint/truncate는 실행하지 않는다. 기존 경보/통지 전체 문서의 해시, 사건/저장 대시보드 행, 인증서/키/사이트 파일의 해시도 적용 전후 대조한다.

백업 대상은 현재 워커 DB·필요한 AUTH early DB·포털/알림 DB다. 보존한 원본과 미활성 사본을 재귀 탐색해 다시 백업하지 않는다. 포털 쓰기가 완전히 멈춘 뒤 사건·저장 대시보드의 기준을 확보하고, 포털 재개 전에 검사한다. 중지 전 완료된 사용자 변경과 재개 후 정상 저장은 허용한다. 중지된 기준 이후 행 손실은 `preservation-failed.json`에 남겨 자동 재시도를 차단하며 과거 DB로 덮어쓰지 않는다. 등록 OFF에서는 enrollment-cleanup이 외부 요청·키 정리 없이 대기하고, ON의 기존 sweep/retry 동작은 유지한다.

경보·초기 통지는 마이그레이션 후에도 쓰기가 멈춘 상태에서 원문 해시를 비교한다. 탐지 재개 후 초기 통지의 정상 revision/확정 전이를 데이터 손상으로 오인하지 않는다. 이 보존 검사가 실패하거나 검증 불가이면 같은 보호 실패 기록으로 재시도를 차단한다. 이후 실행의 새 실환경 탐지·전달 인수는 `verify`의 별도 결과로 남는다.

## 적용 후 자동 인수

```bash
sudo python3 deploy/server/manage.py verify --state /실제/state/server --portal-origin https://실제주소 --wait-seconds 300
```

포털 비밀번호는 숨긴 프롬프트로 입력한다. 비밀번호·API키를 명령줄/환경 변수/보고서에 넣지 않는다. 자동화는 보호된 메모리 입력으로 `--password-stdin`의 JSON을 전달할 수 있다.

검증은 필수 서비스/같은 이미지·정책, 여섯 워커의 최근 성공/체크포인트, priority 처리 지연, **적용 후 실제 수신된 새 원본의 정규화 재현·정확 raw 참조**, 실제 AUTH 경보의 모든 근거 무결성, CA 검증한 실제 HTTPS 로그인/API·초기 통지·홈/개인 대시보드 자산·독립된 실시간/적체/늦은 평가 상태와 로그아웃을 확인한다. 누락·검색 부분 응답·입력 없음·기존 경보만으로 새 시험을 대신하는 경우를 성공으로 바꾸지 않는다. 실제 입력이 없으면 acceptance는 미검증/실패로 남는다.

별도 승인을 받은 시험 서버에서 새 탐지까지 재현하려면 로컬 SSH 서비스에만 존재하지 않는 시험 사용자로 10회 실패를 발생시킨다. 계정·SSH 정책·방화벽을 만들거나 바꾸지 않고 OS의 기존 공개 호스트 키를 검증한다. 원문 로그를 직접 ES에 합성 삽입하는 검사가 아니다.

```bash
sudo PYTHONPATH=src python3 -m cloud_soc.deployment.probe --state /실제/state/server
sudo python3 deploy/server/manage.py verify --state /실제/state/server --portal-origin https://실제주소 --probe /위명령의/receipt.json --wait-seconds 1200
```

SSH 명령의 실패 자체는 수신/위험 탐지 성공이 아니다. 정상 수집기→정규화 10건→기본 900초 유예를 유지한 최종 AUTH 경보1건/정확 근거10개의 인수가 필요하다. 생성한 시험 경보와 원본은 보존한다. 기존 경보/대시보드/사건을 초기화하지 않는다.

## 재현 및 검증 범위

`tests/test_deployment_parity.py`는 집 서버(기존 두 워커/누락 권한), 다른 중앙(priority·additional·회고 상태 보유), 신규 설치가 같은 필수 기능으로 수렴하는지 실제 SQLite/정규화·탐지 엔진과 합성 ES IO로 검사한다. WAL 백업/복원, 전후 identity/시작점, 기존 키 보존, 반복 적용, 중간 실패/재시도, stale/변조 계획, 메모리/디스크 부족, DLS/FLS/미검증 룰 차단, 필수 API/워커 누락·부분 검색·새 입력 부재도 포함한다. 이 검사는 실서버 신규 OS 설치나 접근 불가인 중앙의 실제 업그레이드 인수를 뜻하지 않는다.

실제 적용 결과는 작업 추적 문서의 PARITY 항목과 개별 실행 영수증을 따른다. Git 제외 `runtime/upgrades/<UTC>`에는 보호 설정·온라인/중지 후 SQLite 사본·계획/실패/적용 결과가 남고, `runtime/acceptance.json`은 실제 인수 결과다. 보호 경로가 포함된 서버 상태를 Git에 추가하지 않는다.

추가 안정화 회귀는 `test_school_runtime_compat.py`, `test_upgrade_safety.py`, `test_upgrade_lifecycle.py`다. `linux_upgrade_lifecycle.py`는 임의 프로젝트의 실제 Docker/Compose와 운영 OFF 정리 프로그램을 사용해 관리형·구형·신규 구조를 시험한다. 해당 ES/Kibana/워커 대역은 생명주기만 검사하며 실제 탐지를 입증하지 않는다. `linux_runtime_smoke.py`는 별도로 새 상태·독립 볼륨에서 실제 ES/Kibana/포털/6워커/Slack을 plan/apply로 기동하고 정상 합성 로그 정규화와 무변경 재적용을 확인한다. 이 전체 스택 시험은 필수 7168MiB+현재 OS 점유 예산을 충족하는 격리 호스트에서 명시적으로 실행한다. 두 스크립트는 운영 상태를 mount하지 않으며 Slack 발송과 공격을 수행하지 않는다. 원격 CI와 실제 학교 재배포 인수는 별도 결과다.

## Slack 관리자 알림(런타임 v2)

설치·업그레이드 후 Cloud SOC의 **설정 → 알림 연동 → Slack**에서 관리자가 Incoming Webhook URL을 입력한다. 등록·변경·삭제, 알림 ON/OFF, 최소 위험도(기본 HIGH), 테스트 전송을 제공한다. 조회 API는 등록 여부와 전송 상태만 반환한다. URL은 저장 후 입력란에서 지워지며 재조회되지 않는다. 실제 URL을 채팅·문서·명령줄에 넣지 않는다. 웹 기능은 Elasticsearch/Kibana 설정과 별개다.

003 마이그레이션은 별도 `slack-notifier`와 두 경보 인덱스에만 read/view_index_metadata 권한이 있는 신규 읽기 키를 준비한다. 기존 여섯 처리 워커의 키·명령·룰 선택·체크포인트는 유지한다. 미설정/OFF 알림 워커는 경보 검색·외부 전송을 하지 않으며 기존 수집·탐지·대시보드의 실행 조건이 아니다. 총 한도 6656MiB와 여유 512MiB를 합한 7168MiB를 실제 호스트의 교체 가능 메모리와 대조한다. Slack 단독 한도는 64MiB이며 기존 ES 3072MiB/Kibana 1536MiB 한도와 Kibana 1024MiB heap도 예산에 포함한다.

Webhook은 별도 `state/server/notifications/slack.key`로 암호화해 같은 보호 디렉터리의 SQLite에 저장한다(디렉터리0700·파일0600). 키는 최초 URL 저장에 한 번 생성하고 재시작·업그레이드·URL 변경·삭제 때 교체하지 않는다. 키가 유실되면 자동 재생성으로 복구한 척하지 않고 발송을 중단한다. DB와 이 키를 함께 보호 백업해야 한다. 기존 인증 키·CA/인증서를 이 키로 대체하지 않는다. 운영 SQLite 백업에는 온라인 backup API를 사용한다.

지원 URL은 상용 Slack의 `https://hooks.slack.com/services/...` 정확한 형식이다. GovSlack 주소는 현재 미지원이다. 서버는 모든 DNS 응답의 공인 주소 여부를 검사하고 검사한 숫자 주소로 직접 연결하며 TLS 인증서/SNI는 Slack 호스트로 검증한다. 임의 포트·IP·내부망·유사 도메인·redirect·환경 프록시를 허용하지 않는다. 관리자 역할·세션 CSRF를 적용하고 테스트는 전체 설정 기준 30초 간격 및 15분에 5회로 제한한다.

최종 `security-alerts`와 초기 `soc-alert-notices-v1`을 룰 ID 제한 없이 처리한다. 최초 활성화, OFF→ON, URL 또는 위험도 설정 저장 시 각 primary shard의 현재 sequence를 기준점으로 삼아 기존 경보를 보내지 않는다. 설정 변경은 미전송 큐를 취소하며 변경 중 들어온 경보도 새 기준점 이전이면 보내지 않는다. 워커 재시작은 저장 커서와 논리 ID/revision 기록을 이어 사용한다. 초기 통지의 상태/revision 갱신은 별도 메시지이며 최종 경보와 연결된 confirmed 통지는 최종 경보 경로와 중복 전송하지 않는다. 과거 시각 경보라도 활성화 후 새로 저장된 회고 경보는 새 경보로 처리한다.

전송은 초당 최대 1건이다. HTTP200/`ok`는 Slack의 요청 접수이며 실제 채널 표시의 증거는 아니다. 연결 전 실패·408/5xx·429는 최대8회 제한 재시도하고 429의 Retry-After를 지킨다. 3xx/그 외4xx·잘못된 응답·과도한 rate-limit 대기는 영구 실패/검토 대상으로 남긴다. POST를 시작한 뒤 응답이 유실되거나 inflight 상태로 재시작하면 `수신 미확인`으로 보류하고 자동 재전송하지 않는다. Slack Incoming Webhook에는 이 구현이 사용할 수 있는 중복 제거 응답 계약이 없어 exactly-once를 보장하지 않는다. 원격 수신 후5xx 같은 경우 재시도로 중복될 수 있고, 응답 유실 보류는 누락 가능성도 남긴다. 경보 ID를 채널에서 대조한다. outbox는 10만 건에 도달하면 별도 알림 실패로 표시하며 운영 경보 DB를 삭제하거나 되감지 않는다.

인수는 웹 등록, 테스트 요청 접수, 실제 채널의 테스트 수신, 신규 실제 AUTH 경보의 생성/정확 근거/대시보드, 같은 ID의 Slack 채널 수신을 구분한다. 실제 채널 확인은 관리자가 수행하며 URL을 전달할 필요가 없다. 격리 sender의 성공·실제 HTTP200만으로 전체 완료 처리하지 않는다. 빈 Ubuntu 실서버와 접속 불가 중앙 서버는 실제 검증 범위 밖으로 명시한다.

수신 미확인 건은 같은 관리자 화면의 전용 목록에서 경보/통지 ID·상태·revision·시도 횟수와 함께20건씩 페이지를 넘겨 확인한다. URL·원문·암호문을 목록에 넣지 않는다. 채널에서 ID를 대조한 다음 중복 가능성 확인 대화상자를 승인해야 수동 재전송을 요청할 수 있다. 서버도 명시적인 중복 위험 확인·관리자 역할·CSRF·현재 설정 revision·현재 generation을 검사한다. Webhook/설정 변경 전 이력, 이미 재전송 대기/전송된 건, 영구 실패는 이 경로로 재전송하지 않는다. 수동 요청은 테스트와 합산한30초 간격/15분5회 제한을 사용하고, 요청자·시각·경보 식별자·이전 시도 횟수를 별도 영속 감사 기록에 남긴다. 재전송은 같은 payload만 다시 큐에 넣고 ES 경보·탐지 체크포인트·알림 커서를 변경하지 않는다. 이 기능은 이미 수신된 메시지를 구별할 수 있게 해주는 것이 아니므로 관리자가 중복 가능성을 판단해야 한다.

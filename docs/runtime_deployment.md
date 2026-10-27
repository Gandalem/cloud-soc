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

## 서버 메뉴와 상태

```bash
sh soc --help
sudo sh soc
sudo sh soc install
sudo sh soc status
sudo sh soc uninstall
```

메뉴 명령은 `install`/`status`/`uninstall`/`help`/`exit`, 설치 환경은 `lab`/`lan`/`cloud`다. 접속 DNS/IPv4에는 스킴·포트·경로를 넣지 않는다. 클라우드의 접속 주소와 서버에 실제 할당된 바인딩 IP를 따로 받는다. 기존 설정이 있으면 새 설치로 덮어쓰지 않고 아래 복구 경로를 안내한다. 입력을 영어로 받는다는 것은 비밀번호 문자나 기존 장치 이름에 새 제한을 둔다는 뜻이 아니다. 관리자 비밀번호는 기존 숨김 입력과 해시 저장을 유지한다.

`status`는 고정 로컬 Docker 소켓의 inspect 결과를 사용한다. 프로젝트·서비스·현재 checkout의 Compose 경로가 일치하는 컨테이너만 표시하고, 같은 프로젝트의 다른 설치·중복 서비스·조회 실패는 오류다. 런타임 계약의 필수 상주12서비스와 일회성 bootstrap을 구분하며 bootstrap의 종료0은 준비 완료다. 실행 중이더라도 healthcheck가 없으면 `상태 점검 미설정`, starting/unhealthy는 확인 필요로 표시한다. 데이터만 남은 경우 실행 서비스와 구분한다. 실행·건강 상태가 실제 수신·탐지 완료를 뜻하지 않는다.

삭제 메뉴는 기존 설치/업그레이드 잠금 안에서 보존/삭제 방식을 선택하고, 삭제·보존 범위를 표시한 뒤 한 번 확인한다. 확인 후와 각 종료 단계마다 리소스·소유 관계·공유 사용 여부를 다시 읽는다. `keep`은 볼륨·설정·인증서·자격 증명을 보존하고 `purge`는 소유 관계를 확인한 전용 자료만 삭제한다. 보존 자료가 있는 상태에서 신규 설치는 거부한다. 복구·재사용은 기존 `manage.py recover/install` 절차로 진행한다.

종료 순서는 gateway → 작업자·정리 작업 → portal/kibana → elasticsearch다. Docker 최소24.0.0 지원을 유지하고 신구 CLI의 긴 옵션 이름 차이(`--time`/`--timeout`)를 피하도록 공통 단축 옵션 `stop -t -1`을 사용한다. 컨테이너에 지정된 StopSignal(미지정 SIGTERM)을 보내고, Python의 전체90초 대기 한도만 적용한다. SIGKILL/SIGSTOP으로 설정된 대상은 거부한다. 클라이언트 대기 초과는 서버 종료 확인이 아니며 데몬의 종료 대기가 남을 수 있다. 실행·재시작·OOMKilled·종료137이면 비강제 rm·볼륨·설정 삭제로 진행하지 않는다. 종료 확인은 애플리케이션의 모든 버퍼 flush나 모든 장애에서 무손실을 증명하지 않는다. 백업은 별도로 필요하다. gateway는 포털/Kibana 접속 경로이고 장치의9200 수신은 Elasticsearch에 직접 연결되므로, gateway 종료가 모든 수신을 차단하는 fence는 아니다. 종료 중 원본이 추가될 수 있으며 전체 분석 적체 drain 완료를 보장하지 않는다.

근거: [Docker stop의 신호와 무기한 대기](https://docs.docker.com/reference/cli/docker/container/stop/), [수동 종료와 재시작 정책](https://docs.docker.com/engine/containers/start-containers-automatically/), [Docker 27.5.1 종료 옵션 원문](https://github.com/docker/cli/blob/v27.5.1/cli/command/container/stop.go), [강제 rm의 SIGKILL](https://docs.docker.com/reference/cli/docker/container/rm/), [표준 argparse](https://docs.python.org/3.12/library/argparse.html). 새 제품 의존성은 추가하지 않는다.

### INSTALL-SERVER-UX-02 인수 구분

이 절은10/26의 초기 컴포넌트 인수 기록이다. 당시 모의 검사와 독립 Docker 엔진의 실제 종료·삭제는 빈 Ubuntu/systemd의 전체 설치를 대신하지 않았다. 새 폐기 컨테이너의 별도 데몬·소켓·데이터 루트만 사용했고 호스트 Docker 소켓·방화벽·커널 값·기존 WSL·실제 로그/키를 변경하지 않았다. 당시 남긴 전체 설치·복구·purge 인수는 다음 절의10/27 새 WSL 결과로 해당 환경에서 해소했다. WSL 배포판 추가를 커널까지 독립된 VM으로 보지 않으며 물리 VM/EC2는 별도다.

검사 결과(2026-10-26): Python 관련55검사 중54통과·Windows 실제 링크 권한1건 제외, 설치기 POSIX 보호 조건41건은 초기40통과와 문구 수정 후 해당1건 통과로 확인했다. 변경 Python의 Ruff·diff 공백 검사는 통과했다. Docker27.5.1 CLI/Engine의 독립 소켓·vfs·네트워크 none 실험에서 keep/purge, 미종료 시2초 시험 대기 초과와 강제 종료 없음/설정·볼륨 원문 보존, 다른 프로젝트 원문 보존, Linux 실제 심볼릭 링크 거부, 내부 컨테이너·볼륨0을 확인했다. 2초는 시험에서만 주입하며 제품 한도90초는 유지한다. 실제 설치 메뉴·전체12서비스의 빈 Ubuntu 설치/보존 복구/삭제는 이번 시험 범위가 아니다.

초기 실험에서 별도 데몬의 포트 프록시 설정 누락을 고쳤고, Docker27 CLI의 `--timeout` 미지원은 제품 명령을 공통 `-t`로 고쳐 영향받은 삭제 검사7건과 실제 실험을 다시 통과했다. Windows 모의 호스트 설정 누락·심볼릭 링크 생성 권한과 한국어 오류 기대값도 검사 측에서 수정했다. 실제 실패를 정상 종료나 인수 완료로 처리하지 않았다. 외부 호스트의 기존3이미지와 기존 WSL은 유지했고 이번 시험 컨테이너/이미지는 제거했다. 공유 빌드 캐시는 전역 prune하지 않았다.

재현용 `deploy/server/tests/server-removal.Dockerfile`과 `tests/manual/server_removal_docker_live.py`는 Linux amd64 컴포넌트 실험 전용이다. Docker27.5.1-dind와 Python3.12-slim-bookworm의 실제 digest를 고정했으며 새 제품 런타임 의존성은 없다. 실행은 승인받은 폐기 호스트에서만 하며, 호스트 소켓·폴더·포트를 연결하지 않는다. privileged 외부 시험 컨테이너는 VM/커널 보안 격리나 빈 Ubuntu 인수의 대체가 아니다.

### 2026-10-27 WSL 전체 설치·삭제 인수

사용자 승인으로 새 Ubuntu24.04.5 WSL의 systemd·독립 Docker29.9.2 기본 overlayfs에서 전체 흐름을 추가 확인했다. ES/Kibana9.5.2·Caddy2.11.4와12서비스 실행, CA/이름 검증 HTTPS, 메뉴/상태/도움말, 삭제 취소, keep/보존 상태/신규 설치 거부, 기존 관리자를 통한 복구, 같은 키·인증서·합성 원본 대조, purge/반복 제거가 통과했다. 따라서 앞서 남겼던 전체 설치 인수는 이 WSL 범위에서 완료다. 물리 VM/EC2·재부팅·실장치 수신/경보·HA 인수는 별도다.

이 과정에서 Windows 작업본의 `soc` CRLF 실행 오류를 LF 및 `.gitattributes`로 고쳤다. 또한 Python이 컨테이너 PID1일 때 SIGTERM으로 멈추지 않는 실증을 확인했다. 공통7작업자와 등록 정리 작업자에 `init: true`를 적용해 Docker의 내장 초기 프로세스가 신호를 전달하고 자식을 회수하게 했다. 작업자 명령·권한·룰·키·체크포인트 의미는 바꾸지 않는다.90초 한도에서 미종료이면 삭제를 중단하는 조건도 유지한다. init가 있다고 작업 중 버퍼 flush나 전체 분석 drain까지 보장되는 것은 아니다. 근거: [Compose init](https://docs.docker.com/reference/compose-file/services/#init), [Tini MIT 라이선스](https://github.com/krallin/tini/blob/master/LICENSE).

재현 도구는 `tests/manual/server_install_wsl_live.py`다. 새로운 시험 경로와 checksum 고정 Ubuntu WSL 이미지가 필요하며 기존 Ubuntu와 Docker Desktop에는 설치하지 않는다. 실패 시에도 소유 이름·레지스트리 BasePath·소유 표시를 대조해 새 trial만 unregister한다. 시험은 별도 네트워크 namespace/slirp4netns1.2.1를 사용하고 포트·호스트 Docker 소켓을 외부에 연결하지 않는다. 그 환경에서는 외부 containerd와 Docker의 mount 공간 불일치가 있었으므로 새 trial의 packaged containerd만 runtime mask하고 Docker 자체 containerd를 사용한다. 기존/운영 Docker 설정을 바꾸는 배포 처방이 아니다. 새 제품 의존성은 없고 시험용 패키지만 폐기 WSL에 설치한다. [slirp4netns 공식 사용법](https://github.com/rootless-containers/slirp4netns), [WSL systemd](https://learn.microsoft.com/en-us/windows/wsl/systemd), [Docker image store](https://docs.docker.com/engine/storage/containerd/).

초기 시험 환경 실패·PID1 대기 초과를 성공으로 처리하지 않았고, 수정 후 새 trial의 전체 흐름으로 재확인했다. 최종 보고서는 Git 제외 `state/server-ux-wsl-20261026-10`의 result/cleanup/final-audit JSON이다. 모든 trial 디스크와 임시 소스·과거 다운로드 이미지도 제거했고 기존2배포판과 공유 Docker 이미지3개는 유지했다. 잠시 올린 공통 커널 값은262144로 원복하고 trial 밖 방화벽 규칙도 대조했다. 비밀값은 보고서에 남기지 않는다.

이후 PR21의 Windows CI에서 monotonic 반올림으로 종료 대기값이90.00000000000006초가 되는 실패를 확인했다.5bcef7f는 공통 deadline을 유지하면서 대기값이90초를 넘지 않게 보정했다. 결정적 반올림·단계별 예산을 포함한 영향9검사와 Actions40424825929의 Windows/Ubuntu 두 job이 성공했고 main e804569로 병합됐다(기록b737b23). 이 후속은 코드/CI 검증이며 위 WSL 전체 인수를 다시 실행한 것은 아니다. 운영 서버·키/데이터·재부팅도 변경하지 않았다.

## 신규 설치

기존 `install-ubuntu.sh`가 OS·주소·포트·Docker·커널과 초기 인증서를 준비한 후 아래 공통 관리자의 `install --build`를 호출한다. 초기 계정 준비는 `initialization` 프로필의 bootstrap에서 신규 설치에만 실행한다. 일반 `compose up`이나 기존 서버 업그레이드는 bootstrap의 비밀번호/계정 초기화를 재실행하지 않는다.

```bash
sudo sh deploy/server/install-ubuntu.sh --host 실제주소 --bind-ip 실제사설IP
```

실제 수집기가 아직 없는 신규 서버에서는 실행 준비만 확인할 수 있다. 관리자는 설치 후 아래 `verify`로 실제 수신/탐지까지 별도로 확인한다. `--startup-only`는 그 인수를 대신하지 않는다.

## 기존 서버 업그레이드

검토한 소스를 받은 체크아웃/릴리스 디렉터리에서 후보 이미지를 먼저 빌드한다. 이미지 태그는 배포 계획에서 고정한 digest와 실제 파일 해시로 다시 확인한다. 아래는 서버 로컬 Docker를 사용하며 원격 Docker context와 상속된 SOC/Compose 환경 변수로 대상을 바꾸지 않는다.

```bash
sudo docker build -f deploy/server/Dockerfile -t cloud-soc-runtime:reviewed .
sudo python3 deploy/server/manage.py plan --state /실제/state/server --image cloud-soc-runtime:reviewed --plan /실제/state/server/runtime-plan.json
sudo python3 deploy/server/manage.py apply --plan /실제/state/server/runtime-plan.json
```

계획에는 서버 사양, 전체 메모리 한도+여유 예산, Docker/state 디스크의 실제 여유, DB 두 벌 백업 공간, 기존 실행 명령·mount·site 주소 차이, 새 워커, 누락된 인덱스·역할/API키 권한이 나타난다. 인증 값은 출력하지 않는다. 실제 image 파일 검증·기존 DB identity 확인·권한 scope 검토를 통과해야 한다. 계획 이후 구성/권한/후보가 바뀌거나 자원이 부족하면 서비스를 멈추기 전에 거부한다.

기존 운영 명령은 Docker label의 파일 목록과 일치하는 `compose.active.json` 영수증으로 식별한다. 경로를 추정하거나 임의 파일의 명령을 실행하지 않는다. 영수증을 찾지 못하면 먼저 기존 배포 명령을 보호 기록으로 남겨야 한다.

### 2026-10-27 실제 Portal 배포 준비 중 확인된 문제

기존 중앙 서버에서 새 Windows 설치 도구의 Portal 배포를 준비하던 중 `plan`이 `Cannot identify the exact active Compose command; provide its protected receipt`로 중단됐다. 보호된 실행 기록에는 기본 Compose 파일과 `runtime/site.json` 두 개가 있었지만, 실행 중인 Portal에는 ngrok 환경 설정과 외부 링크 진입 수정의 두 파일이 추가로 적용돼 있었다. 게이트웨이에는 세 파일, 나머지 확인한 서비스에는 두 파일이 표시됐다. 실제 네 파일을 결합해 계산한 구성의 이미지 ID는 확인한 실행 서비스 12개의 이미지 ID와 각각 일치했다. 구성 전체가 실행 상태와 일치한다거나 업그레이드 후에도 ngrok가 작동한다는 인수는 아니다.

추가 파일 두 개는 기존 배포 관리자가 허용하는 경로 밖에도 있다. 따라서 보호 기록에 파일명만 추가하거나 검사를 우회해 적용해서는 안 된다. 다음 작업에서는 실제 설정과 파일 소유·무결성, 서비스별 차이, 승인된 경로와 기존 구성·ngrok 복구 방법을 검토한 뒤 정확한 실행 기록과 새 계획을 준비해야 한다. 이 기록 시점에 후보 이미지는 별도 태그로 서버에 불러왔으나 배포 계획은 성공하지 않았고 서비스 중지나 적용도 없었다. 추가 원인 진단을 위해 준비한 도구는 사용자의 중지 요청에 따라 실행하지 않았다.

별도로 기존 업그레이드 실패 복구가 `runtime/site.json`을 새 설정으로 덮어쓴 뒤 이전 명령에서 같은 경로를 읽는 문제를 발견했다. 로컬 코드는 이전 사이트 파일을 보호된 복구 폴더에 보관하고 해시를 확인한 후 이전 서비스 실행 전에 복원하도록 수정했다. 직접 영향 모의 검사 13건을 통과했으며, 실제 서버 적용·장애 복구 검증은 아직 하지 않았다. 앞서 서버에 불러온 후보 이미지는 이 후속 수정을 포함하지 않는다.

Windows 운영 코드 서명도 별도 미완료다. 이 PC와 시험 VM에서는 유효한 개인키가 있는 코드 서명 인증서를 찾지 못했으며, HTTPS용 CA를 코드 서명 인증서로 사용하지 않는다. 서명 도구 준비와 서명 없는 시험 파일 거부 확인은 했지만 운영 서명 파일의 생성·Portal 공급·실제 설치/수신 검증은 수행하지 않았다.

001 마이그레이션은 기존 데이터를 변경하지 않는 mapping 추가와 정확한 런타임 권한을 준비한다. 기존 사용자/비밀번호는 변경하지 않으며, 기존 API키는 ID·토큰·만료를 유지하고 필요한 descriptor만 추가한다. 폐기/만료 키, DLS/FLS 제약, 알 수 없는 역할/상태 scope는 자동 교체하지 않는다. 신규 설치의 키만 보호 경로에 신규 발급한다.

002 마이그레이션은 기존 SQLite를 온라인 백업·무결성·격리 memory restore로 확인하고, 워커 중지 후 일관된 사본을 공통 `state/server/runtime/state/<worker>`로 옮겨 이어 처리한다. 원래 DB·체크포인트를 지우거나 되감지 않는다. 기존 priority/additional/회고 DB도 발견하면 정확한 identity 그대로 인수한다. 없는 워커만 명시적 최근 수신 floor와 새 DB를 얻는다. 이미 활성화한 관리 상태를 다시 초기화하지 않는다.

`runtime/migrations.json`은 단계의 applying/applied/failed와 버전을 기록한다. 실패한 미활성 사본은 보존하고 원래 실행으로 복귀한다. 재시도는 원래 서버에서 계속 전진한 최신 DB를 다시 백업해 인수한다. 인덱스/권한의 호환 가능한 추가와 발급된 신규 키는 영수증/백업에 남기며 앱 복귀가 schema rollback이나 DB 과거 복원을 뜻하지 않는다. 미래 버전 ledger의 다운그레이드는 거부한다.

프로세스 강제 종료/전원 중단으로 `runtime/pending.json`이 남으면 새 계획/적용은 거부한다. `sudo python3 deploy/server/manage.py recover --state /실제/state/server`로 보호된 journal의 기존 실행을 복구한 뒤 다시 계획한다. SQLite를 과거 사본으로 덮어쓰지 않는다. 중단된 신규 설치에서는 고정 시작점·이미 준비된 상태를 보존해 `install`을 재시도한다. 수동 `docker run`, 다른 Compose project, 복제본이나 이름을 바꾼 SOC 워커가 실행 중이면 중복 실행을 피하기 위해 적용 전에 중단한다. 해당 워커를 임의 삭제하거나 자동 종료하지 않는다.

서버별로 보존할 것은 사이트 주소·CA·계정/정책 파일·허용 CIDR·데이터 mount다. 워커 유무·권한·룰 선택·Kibana heap은 공통 버전에서 관리한다. Kibana는 1536MiB 한도와 1024MiB Node heap을 함께 선언하며, 전체 예산을 충족하지 못하는 서버에서는 적용을 중단한다.

메모리 판정은 총 RAM 외에도 Linux `MemAvailable`과 실행 중인 관리 컨테이너별 working set을 측정한다. 교체 후 확보할 수 있는 메모리가 모든 컨테이너 한도와 512MiB 여유분보다 작으면 적용을 거부한다. 다른 컨테이너·OS의 점유분을 관리 서비스의 회수 가능량에 넣지 않는다. 예산/사용량은 계획에 기록하고 적용 직전에 다시 측정한다. SQLite 백업은 운영 연결의 온라인 backup API로 커밋된 WAL 프레임까지 읽고, 복사본만 standalone DELETE journal로 바꿔 무결성/격리 복원을 확인한다. 운영 WAL의 checkpoint/truncate는 실행하지 않는다. 기존 경보/통지 전체 문서의 해시, 사건/저장 대시보드 행, 인증서/키/사이트 파일의 해시도 적용 전후 대조한다.

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

## Slack 관리자 알림(런타임 v2)

설치·업그레이드 후 Cloud SOC의 **설정 → 알림 연동 → Slack**에서 관리자가 Incoming Webhook URL을 입력한다. 등록·변경·삭제, 알림 ON/OFF, 최소 위험도(기본 HIGH), 테스트 전송을 제공한다. 조회 API는 등록 여부와 전송 상태만 반환한다. URL은 저장 후 입력란에서 지워지며 재조회되지 않는다. 실제 URL을 채팅·문서·명령줄에 넣지 않는다. 웹 기능은 Elasticsearch/Kibana 설정과 별개다.

003 마이그레이션은 별도 `slack-notifier`와 두 경보 인덱스에만 read/view_index_metadata 권한이 있는 신규 읽기 키를 준비한다. 기존 여섯 처리 워커의 키·명령·룰 선택·체크포인트는 유지한다. 미설정/OFF 알림 워커는 경보 검색·외부 전송을 하지 않으며 기존 수집·탐지·대시보드의 실행 조건이 아니다. 총 한도 6656MiB와 여유 512MiB를 합한 7168MiB를 실제 호스트의 교체 가능 메모리와 대조한다. Slack 단독 한도는 64MiB이며 기존 ES 3072MiB/Kibana 1536MiB 한도와 Kibana 1024MiB heap도 예산에 포함한다.

Webhook은 별도 `state/server/notifications/slack.key`로 암호화해 같은 보호 디렉터리의 SQLite에 저장한다(디렉터리0700·파일0600). 키는 최초 URL 저장에 한 번 생성하고 재시작·업그레이드·URL 변경·삭제 때 교체하지 않는다. 키가 유실되면 자동 재생성으로 복구한 척하지 않고 발송을 중단한다. DB와 이 키를 함께 보호 백업해야 한다. 기존 인증 키·CA/인증서를 이 키로 대체하지 않는다. 운영 SQLite 백업에는 온라인 backup API를 사용한다.

지원 URL은 상용 Slack의 `https://hooks.slack.com/services/...` 정확한 형식이다. GovSlack 주소는 현재 미지원이다. 서버는 모든 DNS 응답의 공인 주소 여부를 검사하고 검사한 숫자 주소로 직접 연결하며 TLS 인증서/SNI는 Slack 호스트로 검증한다. 임의 포트·IP·내부망·유사 도메인·redirect·환경 프록시를 허용하지 않는다. 관리자 역할·세션 CSRF를 적용하고 테스트는 전체 설정 기준 30초 간격 및 15분에 5회로 제한한다.

최종 `security-alerts`와 초기 `soc-alert-notices-v1`을 룰 ID 제한 없이 처리한다. 최초 활성화, OFF→ON, URL 또는 위험도 설정 저장 시 각 primary shard의 현재 sequence를 기준점으로 삼아 기존 경보를 보내지 않는다. 설정 변경은 미전송 큐를 취소하며 변경 중 들어온 경보도 새 기준점 이전이면 보내지 않는다. 워커 재시작은 저장 커서와 논리 ID/revision 기록을 이어 사용한다. 초기 통지의 상태/revision 갱신은 별도 메시지이며 최종 경보와 연결된 confirmed 통지는 최종 경보 경로와 중복 전송하지 않는다. 과거 시각 경보라도 활성화 후 새로 저장된 회고 경보는 새 경보로 처리한다.

전송은 초당 최대 1건이다. HTTP200/`ok`는 Slack의 요청 접수이며 실제 채널 표시의 증거는 아니다. 연결 전 실패·408/5xx·429는 최대8회 제한 재시도하고 429의 Retry-After를 지킨다. 3xx/그 외4xx·잘못된 응답·과도한 rate-limit 대기는 영구 실패/검토 대상으로 남긴다. POST를 시작한 뒤 응답이 유실되거나 inflight 상태로 재시작하면 `수신 미확인`으로 보류하고 자동 재전송하지 않는다. Slack Incoming Webhook에는 이 구현이 사용할 수 있는 중복 제거 응답 계약이 없어 exactly-once를 보장하지 않는다. 원격 수신 후5xx 같은 경우 재시도로 중복될 수 있고, 응답 유실 보류는 누락 가능성도 남긴다. 경보 ID를 채널에서 대조한다. outbox는 10만 건에 도달하면 별도 알림 실패로 표시하며 운영 경보 DB를 삭제하거나 되감지 않는다.

인수는 웹 등록, 테스트 요청 접수, 실제 채널의 테스트 수신, 신규 실제 AUTH 경보의 생성/정확 근거/대시보드, 같은 ID의 Slack 채널 수신을 구분한다. 실제 채널 확인은 관리자가 수행하며 URL을 전달할 필요가 없다. 격리 sender의 성공·실제 HTTP200만으로 전체 완료 처리하지 않는다. 빈 Ubuntu 실서버와 접속 불가 중앙 서버는 실제 검증 범위 밖으로 명시한다.

수신 미확인 건은 같은 관리자 화면의 전용 목록에서 경보/통지 ID·상태·revision·시도 횟수와 함께20건씩 페이지를 넘겨 확인한다. URL·원문·암호문을 목록에 넣지 않는다. 채널에서 ID를 대조한 다음 중복 가능성 확인 대화상자를 승인해야 수동 재전송을 요청할 수 있다. 서버도 명시적인 중복 위험 확인·관리자 역할·CSRF·현재 설정 revision·현재 generation을 검사한다. Webhook/설정 변경 전 이력, 이미 재전송 대기/전송된 건, 영구 실패는 이 경로로 재전송하지 않는다. 수동 요청은 테스트와 합산한30초 간격/15분5회 제한을 사용하고, 요청자·시각·경보 식별자·이전 시도 횟수를 별도 영속 감사 기록에 남긴다. 재전송은 같은 payload만 다시 큐에 넣고 ES 경보·탐지 체크포인트·알림 커서를 변경하지 않는다. 이 기능은 이미 수신된 메시지를 구별할 수 있게 해주는 것이 아니므로 관리자가 중복 가능성을 판단해야 한다.

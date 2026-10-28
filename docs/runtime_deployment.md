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

### ngrok 설정 인수 절차 — 2026-10-28

현재 구현은 기존 보호 기록의 두 Compose 파일 뒤에 Portal/gateway용 JSON 추가 설정이 적용된 경우에 한정한다. 최초 설치나 IP 자동 변경 기능이 아니다. 기존 설정 파일의 순서를 운영자가 명시하며, 컨테이너 레이블은 임의 실행 명령을 만드는 용도로 사용하지 않는다. 다른 서비스의 명령·포트·연결 파일 변경, 알 수 없는 환경 변수는 이 절차에서 인수하지 않는다.

아래 명령은 해당 변경을 포함한 소스에서 중앙 서버 로컬 Docker에 대해 실행한다. `review-compose`는 실행 중인 서비스 전체의 설정 지문과 이미지 ID를 확인하고 보호된 검토 폴더만 생성한다. 현재 실행 기록·서비스·CA·키는 바꾸지 않는다. 예시 경로는 10/27 확인한 서버의 경로이며 실제 파일이 바뀌었으면 다시 확인한다.

```bash
sudo python3 deploy/server/manage.py review-compose \
  --state /home/kopo/cloud-soc/state/server \
  --compose-file /home/kopo/cloud-soc/deploy/server/compose.yaml \
  --compose-file /home/kopo/cloud-soc/state/server/runtime/site.json \
  --compose-file /home/kopo/cloud-soc-ngrok/portal.compose.json \
  --compose-file /home/kopo/cloud-soc-ngrok/link-entry-fix/entry.compose.json
```

추가 파일은 JSON의 Portal/gateway 환경 설정과 Portal 이미지 변경만 허용한다. 기본 파일과 환경 파일은 보호된 기존 실행 기록과 일치해야 한다. 같은 순서의 설정으로 계산한 모든 서비스의 Compose 지문이 각 실행 컨테이너의 지문과 같아야 하며, 이미지 태그가 가리키는 로컬 이미지도 실제 실행 이미지와 같아야 한다. 지문 레이블 외에 실제 환경값·명령·연결 파일·공개 포트·네트워크·메모리/읽기 전용/재시작 설정도 대조한다. Compose 버전 차이 등으로 지문이 다르면 자동 통과시키지 않는다. 먼저 해당 차이를 진단한다.

출력의 `review` 경로를 사용해 후보 배포 계획을 만든다. 검토 폴더의 정규화된 Compose 사본은 원래 기준 디렉터리에서 다시 해석해 동일성을 확인하며, 복구용 서비스 이미지에는 태그 대신 당시 이미지 ID를 사용한다. 사본/검토 기록에는 환경값이 포함될 수 있으므로 root 전용 상태 폴더에 보관하고 Git·채팅에 올리지 않는다.

```bash
sudo python3 deploy/server/manage.py plan \
  --state /home/kopo/cloud-soc/state/server \
  --image cloud-soc-runtime:reviewed \
  --compose-review /실제/출력된/review.json \
  --plan /home/kopo/cloud-soc/state/server/runtime-plan.json
```

후보는 현재 소스와 파일 해시가 일치하는 이미지로 별도 준비한다. 현재 소스의 외부 링크 진입 수정과 로그인/인증 경계 검사가 후보 검토 대상이다. 과거 서버에 불러온 후보가 이 변경까지 포함했다고 가정하지 않는다. `plan`과 `apply`는 원본 입력·참조 설정의 해석 결과·컨테이너 신원과 이미지·보호 사본을 다시 확인한다. 기존 Portal/gateway 환경과 포트·연결 파일을 새 계획이 보존하는지도 확인한다. 검토 후 파일/실행 상태가 바뀌면 새 검토와 계획이 필요하다. 이전 서비스를 멈추기 직전에도 검토를 재확인한다.

검토된 계획의 적용/검증은 위의 공통 `apply`/`verify` 절차를 따른다. 실패 복구는 먼저 검토 사본의 무결성과 이전 이미지의 로컬 존재를 확인하고, 이전 site.json과 고정 이미지 구성을 복구한다. 복구에 실패하면 pending 기록을 유지하고 성공으로 표시하지 않는다. DB를 과거로 되감지 않는다. 성공한 새 배포는 통합된 두 설정과 보호 실행 기록을 남긴다. 실제 ngrok 직접 접속·링크 클릭·모바일 로그인·기존 장치의 새 로그 수신은 별도로 확인해야 한다.

검증 기록(2026-10-28): 구현 완료 후 설정 인수 새 검사33건·기존 coordinator/신규 설치 경로14건·Portal/서버 CLI97건 및28 subtests가 통과했다. Windows의 링크 생성 제한으로 건너뛴1건은 WSL에서 실제 제품 함수의 링크 거부로 보완했다. 같은 실행에 포함된 기존 Windows 설치기2건은 로컬 PowerShell 실행 정책으로 실패했으며 정책은 변경하지 않았다. WSL 실제 Docker/Compose의 격리 idle 서비스12개에서 인수·변조/권한 거부·이전 이미지 태그 삭제 후 복구·자료 보존·시험 리소스 정리를 통과했다. 이 결과는 실제 중앙 제품/후보 배포·ngrok 접속·원격 에이전트 수신의 완료가 아니다. 실제 서버에서는 현재 상태를 다시 읽고 새 후보와 plan을 준비해야 한다.

중앙 VM 후속 검증(2026-10-28): 실제192.168.32.60의 사용자 sudo 실행으로 Portal4/gateway3/나머지2개 구성 인수와 새 후보/정식 배포 계획 생성을 통과했다. 최종 안전 요약은 verified/plan_ready/resources_ok=true, 기존 서비스/보호 입력 불변=true, services_stopped/applied/live_ingestion_verified=false다. 후보 image_id는 sha256:8463a7eb1746b557bfc90b0f1355fe21afb14cb07cce893da0f1056d4bd1b7b3이며 source_sha256은44514f64f115de90b85dc043537acbdf5508105dbf7c098390df48da81399fde다. 계획은 /home/kopo/cloud-soc-ngrok-review-20261028-1de9d113/runtime-plan.json에 있다. 앞 문단의 실서버 plan 준비 필요 항목은 이 범위에서 해소됐으며, 실제 적용과 새 로그 수신은 아직 검증하지 않았다. 기존 내부 Portal의 CA 검증/로그인 문서는 정상이나 당시 ngrok는 ERR_NGROK_3200과 프로세스 부재로 터널 미실행 상태였다. 설정 인수 성공과 터널 기동/외부 접속 성공은 구분한다.

### 중앙 실제 기본 흐름 인수 완료 — 2026-10-28

위 후보8463a7e...를 사용자 sudo로 실제 적용하고 기존 ngrok 설정으로 터널을 복구했다. 실제 Portal HTTPS API에서 Ubuntu 패키지/1일 수집 키를 만들고 별도 임시 WSL에 제품 install-ubuntu.sh로 설치했다. 원래192.168.32.60:9200 주소와 CA의 TLS1.3/인증을 유지했으며, WSL 직접 LAN 연결 제한은 시험 전용 netns와 Windows의 불투명 TCP pipe로 처리했다. 이 경로는 TLS를 해제하거나 원본/정규화/경보를 직접 삽입하지 않는다. 기존 WSL 공유 경로·Windows 방화벽은 바꾸지 않았다.

실제 루프백 sshd/PAM의 존재하지 않는 시험 사용자로 비밀번호 실패10회를 발생시켰다. 시험 조직 flow-20261028-dc1fc213의 원본98건→정규화98건 중 SSH authentication/failure10건을 확인하고, 기존900초 지연 유예 후 AUTH-001 최종 경보1건을 받았다. 경보 ID는 b9e0f77b1403db5c08a6f3f4dbaff53fd549352b8555a11f75083b81142c2783이며 모든 근거10개의 원본/정규화 참조·무결성·재현을 통과했다. 사용자도 실제 경보 화면과 근거10건이 표시된다고 확인했다.

제품 manage.py verify의2026-10-28 12:33 KST 최종 결과는 verified=true·issues=[]다. 여섯 워커가 모두 통과했고, 새 정규화98건 중20개 원본 재현 샘플과 정확한 시험 관측10개, HTTPS Portal 로그인·10개 API·알림 워커 heartbeat·대시보드 현재/적체 상태 및 HTML/JS 자산을 확인했다. 설정 변경은 없었으며 결과는 중앙 state/server/runtime/acceptance.json에 저장됐다. 앞선 계획만 통과한 상태와 실제 배포/수신 미검증 표시는 이 기본 경로에서 해소됐다.

다음 배포 계획 검수에서는 별도 릴리스 폴더의 기본 Compose가 기존 checkout 루트 밖이라 거부되는 것을 재현했다. 관리 코드가 명시된 workspace의 정확한 기본 Compose와 state/runtime/site.json 두 파일만 추가 허용하도록 보완하고, 직접 영향5검사와 실제 다음 계획 생성을 통과했다. 호스트 관리 소스는cf9083f...이며 다음 후보66c265b...와 next-runtime-plan.json을 준비했다. Portal/워커는 인수한8463a7e...로 유지했고 후속 후보는 적용하지 않았다.

시험 키의 실제 폐기와 로컬/원격 전송 키 복사본 제거, 소유·등록 경로를 확인한 임시 WSL 제거, 기존 WSL 이름 보존, 시험 pipe프로세스0을 확인했다. 원본·정규화·경보는 근거로 남긴다. 기존 대기 중 Ctrl+C로 폐기된 첫 시험 키는 재사용하지 않았으며, 서버 재적용 없이 새 시험 키로 이어갔다. 설치 준비를 포함한20분 대기가900초 최종 유예보다 일찍 끝나는 문제는 읽기 전용 최종 확인으로 분리해 처리했고 탐지 유예/임계값을 바꾸지 않았다.

이번 인수는 Ubuntu 패키지/키 수동 설치 경로다. 토큰/managed-device 신규 등록, Windows, WAF, 실제 Slack 채널, 모바일 실기기, 제품 제거 명령과 재부팅/자동 시작은 포함하지 않는다. 자동 브라우저 검수는 URL 안전 확인 실패로 중단돼 화면 증거는 사용자 확인이다. ngrok는 현재 실행 상태를 복구했으며 새 자동 시작 서비스를 추가하지 않았다.

### ngrok 사용 중 Portal 배포 중단 해결 초안 — 2026-10-28 (설계 이력)

사용자 요청에 따라 위 배포 중단만 다루는 검토 초안이다. 10/27 사용자 제공 진단에서 보호된 기존 기록은 기본 Compose 파일과 site.json 2개였고, Portal에는 ngrok 환경·링크 진입 수정 2개가 추가돼 4개였다. gateway는 3개, 다른 확인 대상 서비스는 2개였다. 네 파일을 조합해 계산한 이미지 ID는 당시 실행 서비스 12개와 각각 일치했지만 설정 전체의 동등성이나 현재 상태를 증명하지는 않는다. 실제 두 ngrok 추가 파일은 현재 배포 관리자의 허용 루트 밖이며, 기존 plan은 정확한 기록과 허용 경로 모두를 요구한다. 서비스 중지·배포 적용은 하지 않았다.

제안하는 해결 방식은 ngrok를 유지한 채 기존 구성을 명시적으로 인수하는 것이다.

1. 현재 프로젝트와 각 서비스의 실행 파일 목록·순서·작업 디렉터리·이미지 ID·mount·포트·필요 환경을 다시 읽고 기존 보호 기록과 대조한다. 운영자가 볼 결과에는 불일치 내용과 영향 서비스만 표시하고 인증값은 출력하지 않는다. 대상이나 파일이 바뀌면 다시 확인한다.
2. 실제 기본/ngrok/link 설정을 보호된 위치에 별도 사본으로 보관하고 원본 경로·파일 해시·소유자·Compose 기준 디렉터리 및 서비스별 연결 관계를 기록한다. 외부 파일을 통째로 신뢰하거나 기존 label/기록에 파일명만 덧붙이지 않는다. 검토된 원본과 사본을 명시적으로 연결하는 인수 검사를 추가한다. 원본 label은 원래 경로인데 사본은 다른 경로이므로 현재의 단순 경로 동등 검사를 그대로 호출하는 것만으로는 해결되지 않는다. 이동 전후 상대 경로와 최종 렌더링 결과의 동등성도 검토한다. [Docker Compose 병합](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)
3. 기존 Portal의 ngrok 공개 주소·Host/Origin·인증·링크 클릭 수정과 gateway 접근 정책 및 에이전트 수집 주소를 새 배포 구성에 반영한다. 실제 파일의 공개 설정·이미지·포트·mount와 서비스별 차이를 비교하고, 현재 ngrok용 Portal 이미지에만 있는 다른 변경이 없는지 확인한다. 사이트/환경 설정과 이전 이미지 ID는 보호된 복구 기록에 남긴다. CA·기존 키·로그/DB·체크포인트는 유지한다.
4. 실제 서버에 올려둔 이전 후보 이미지는 후속 사이트 복구 수정을 포함하지 않으므로, 수정 후 새 이미지와 계획을 만들고 파일/이미지/실행 상태가 검토 시점과 같은지 적용 직전 다시 확인한다. 승인된 배포 절차가 중단됐을 때 이전 사이트 설정과 서비스별 이미지/접속 구성을 복구하는 흐름을 검증한다. 이전 앱 실행 복구가 DB를 과거 시점으로 되감는다는 뜻은 아니다.
5. 이후 SOC가 ngrok 설정을 변경할 때는 적용한 Compose 구성과 보호 기록을 같은 절차에서 갱신해 같은 불일치가 반복되지 않도록 한다. 사용자가 직접 다른 파일을 적용해 불일치가 생기면 조용히 덮지 않고 원인과 인수 경로를 안내한다.

주소 입력에도 사용자 요청을 반영한다. 현재 DNS 이름 또는 IPv4를 받는 입력을 재사용하고 IP/도메인/동시 사용의 별도 필수 메뉴는 만들지 않는다. 입력 형식을 판별해 인증서와 접속 조건을 안내하며, 도메인과 IP를 함께 사용할 때는 추가 주소를 필요한 경우에만 등록한다. 각 주소의 Host/Origin 허용과 인증서 이름·신뢰를 확인한다.

브라우저 Portal·장치 등록·로그 수집은 내부에서 각각 목적지와 인증서 신뢰를 구분한다. 같은 서버 주소가 각 경로에서 사용 가능하면 기본값을 공유하고, 포트와 실제 장치에서의 연결 가능성은 따로 확인한다. ngrok의 Portal 주소는 웹 터널이며 같은 이름의 9200 수집 포트나 설치 묶음에 포함된 CA로 등록이 된다고 가정하지 않는다. 다른 망·다른 인증서 때문에 공유가 안 되면 해당 등록 또는 수집 주소를 입력받는다. 중앙 서버에서의 연결 성공만으로 원격 장치의 연결 성공을 표시하지 않는다. 기존 설치 묶음·장치의 주소와 CA를 자동으로 바꾸지 않는다.

사용자가 든 추가 사례는 AWS EC2의 중지 후 시작으로 공인 IP가 바뀌는 경우다. 설치 메뉴에서 사내망의 주소가 한 개면 이를 접속 기본값으로 제안하고, cloud 모드는 EC2 IMDSv2로 확인 가능한 공인 IPv4를 제안한다. 실제 bind는 서버에 할당된 사설 IPv4를 사용하고, 메타데이터를 읽지 못하거나 주소가 여러 개면 수동 선택한다. 운영자가 도메인을 입력하면 감지된 IP 대신 그 이름을 사용한다. 사설 IP와 공인 IP를 혼동하지 않으며 IMDS 토큰이나 IAM 자격은 저장/출력하지 않는다. 이는 초기 주소 제안이며 실제 AWS 인수는 별도다.

EC2의 일반 공인 IPv4는 stop/start 시 바뀔 수 있지만 기존 장치의 설치 묶음·TLS 이름과 수집기 설정은 자동으로 바뀌지 않는다. 안정적인 도메인이 있다면 장치는 고정 도메인으로 접속하고 실제 공인 IP가 바뀔 때 사용 중인 DNS 제공자의 DDNS/자동 갱신으로 해당 레코드를 바꾸는 방식을 제안한다. DNS 갱신 권한·전파·재시도 및 장치의 실제 재접속 검증이 필요하며 이 프로젝트에 해당 자동화가 이미 구현돼 있다는 뜻은 아니다. 도메인이 없다면 Elastic IP 같은 고정 주소 또는 장치가 접근할 수 있는 별도 안정 연결 경로가 필요하다. ngrok 웹 주소는 수집기 9200까지 해결하지 않는다. Elastic IP는 사용 중과 미사용 모두 공인 IPv4 요금이 발생한다. 사설 IP만 고정해도 외부 공인 IP 문제는 해결되지 않는다. [AWS 인스턴스 중지/시작](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html), [AWS Elastic IP](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html), [DNS 동적 갱신 예시](https://developers.cloudflare.com/dns/manage-dns-records/how-to/managing-dynamic-ip-addresses/).

**추가 요구와 수정 방향:** 기존 에이전트도 서버 공인 IP 변경 후 사용자의 주소 재입력이나 재설치 없이 재연결해야 한다. 별도 도메인 구매, DDNS 가입 또는 Elastic IP를 필수 조건으로 정하지 않는다. 현재 사용 중인 ngrok 주소를 안정적인 연결 경로로 재사용하는 방안을 우선 검토하되, 그 주소가 실제 계정의 지속 주소인지와 서버 재시작 후 터널 자동 복구를 확인해야 한다. Portal 연결과 별도로 등록·수집 연결 및 인증서 신뢰를 실제 장치에서 검증해야 한다. ngrok HTTPS는 기본적으로 ngrok에서 TLS를 종료하며, 기존 Linux 수집기는 제품 CA를 명시해 검증하므로 주소만 바꾸는 것으로 호환을 보장할 수 없다. Filebeat의 역방향 프록시 경로 지원은 후보일 뿐이며 제품의 인증·경로 및 기존 장치 전환은 미구현이다. [ngrok 개발 도메인](https://ngrok.com/blog/free-static-domains-ngrok-users), [ngrok TLS](https://ngrok.com/security), [Elastic 출력 설정](https://www.elastic.co/docs/reference/beats/filebeat/elasticsearch-output).

이미 구현된 지속 heartbeat는 장치 상태를 보고하고 수락 여부를 확인하지만 현 클라이언트는 수집기 주소 변경 명령을 적용하지 않는다. 기존 장치가 숫자 IP만 알고 있고 변경 후 접근 가능한 별도 경로도 없다면, 서버가 새 IP를 감지하더라도 해당 장치에 새 주소를 전달할 방법이 없다. 따라서 모든 기존 장치의 무조작 자동 전환은 현재 코드만으로 불가능하다. 연결 가능한 기존 관리 경로가 있는 장치는 그 경로를 통한 안전한 전환을 조사하고, 경로가 없는 장치는 일회성 전환 방법이 필요한지 명확히 안내한다. 이후 안정 경로로 전환된 장치의 IP 변경 후 재접속을 목표로 한다. ngrok 구성 인수 문제와 이 연결 경로 문제는 각각 해결 및 검증한다.

검증 기준은 격리 환경에서 2/3/4개 설정·허용 루트 밖 파일·파일 변경·복구 실패를 재현하고, 검토된 경우만 계획이 생성되는지와 기존 이미지/설정으로 복귀하는지 확인하는 것이다. IP만, 도메인만, 허용된 IP와 도메인 동시 사용을 각각 확인한다. 주소 공유가 가능한 경우 불필요한 중복 입력이 없는지와 ngrok 주소를 쓰면서 등록/수집이 다른 경우 필요한 주소를 받는지, 실제 장치에서 이름·CA·연결 확인 실패가 성공으로 표시되지 않는지를 시험한다. 실제 서버에서는 새 계획 검토 후 서비스 영향 범위를 확인하고, 배포 이후 ngrok 주소 직접 입력·링크 클릭·휴대폰 접속과 기존 Portal 로그인 및 에이전트 수집 상태를 각각 확인한다. DB·키 보존과 실제 새 로그 수신은 별도로 대조한다. 이 초안은 코드 변경이나 서버 배포를 뜻하지 않는다.

### 배포 개선 2안 — 검토용, 2026-10-28

사용자 요청에 따라 기존 초안을 재검토한 제안이며 구현·배포 승인이 아니다. 기준은 codex/portal-deployment-handoff-20261027 ba9ad3b와 이 PC의 보존된 문서 수정이다. 다른 작성자의 9종 시나리오는 이 안의 개발 근거로 포함하지 않는다.

유지할 목표는 범용 독립 SOC, Git 복제 후 간편한 한글 설치와 영문 확인 입력, Windows·Ubuntu 및 일반 Apache/Nginx/Docker 웹 로그, Portal 설치 묶음/등록 자격 발급부터 장치 설치·상태·일반 원본 수신·정규화·근거 경보·대시보드, 도메인 유무에 따른 배포, 선택 ModSecurity/WAF, 설치 복구·제거다. Security Mall은 선택 앱 감사 시연 대상이며 기본 인수의 필수 조건이 아니다. 호환 이미지 재사용과 부족한 버전/미준비 산출물 안내, 기존 키·자료·다른 서비스 보존도 유지한다.

기본 설치는 이미 있는 DNS/IPv4 입력을 사용한다. 별도의 IP/도메인/동시 사용 메뉴를 새로 만드는 대신 주소 형식을 판별하고 접속 범위·인증서 조건을 설명한다. 도메인+IP 동시 접속은 필요할 때 추가하는 별칭으로 다루며 허용 Host·Origin·SAN을 명시적으로 관리한다. DNS 없음은 보유 도메인 없이 숫자 IP로 사용한다는 의미이며 인터넷 다운로드까지 필요 없는 오프라인 설치를 뜻하지 않는다.

| 검토 관점 | 2안의 보완 |
| --- | --- |
| 설치 운영자 | 기존 soc 명령 안에서 설정 불일치 종류·관련 파일·조치 안내를 제공한다. 진단 스크립트를 반복 실행해야만 오류명을 알 수 있는 흐름을 개선한다. 비밀값은 출력하지 않는다. |
| 1차/조사 분석가 | 등록 확인, 최근 일반 원본, 정규화, 규칙 평가/근거 경보를 구분한다. 프로세스 실행과 heartbeat만으로 수집 완료를 표시하지 않는다. |
| 책임자/인계 담당 | 실제 서버 이미지·규칙 버전·배포 시점·미확인 범위를 기록하고, 검증되지 않은 배포 성공으로 인계하지 않는다. |
| 탐지/데이터 엔지니어 | 서비스별 실제 Compose 입력·순서와 보호 기록, 렌더링된 이미지·mount·공개 설정을 대조한다. 원본 설정은 해시와 함께 보관하며 승인된 경로·상대 경로 기준을 유지한다. |

현재 문제의 우선순위는 다음과 같다.

1. 기존 실행 구성 인수: 2/3/4개로 다른 서비스별 입력과 보호 기록을 확인한다. 실제로 검토한 설정을 보호된 위치에 보관하고 해시·출처·기준 경로를 기록하는 명시적 인수 절차를 설계한다. labels나 기록만 임의로 바꿔 기존 검사를 통과시키지 않는다. 새 배포는 사이트 설정의 한 관리 경로를 사용하고 설정을 바꿀 때 기록도 함께 갱신한다. 기존 파일을 복사할 때 첫 Compose 파일 기준의 상대 경로가 달라지지 않는지 확인한다. [Docker Compose 병합](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)
2. 인증서/등록 계약: 현재 prepare.py는 CRL 배포 주소를 생성하지 않지만 Linux 등록은 서명된 같은 호스트 CRL을 요구한다. 새 서버에서 실제 제품 경로로 확인해야 할 불일치다. 기존 CA를 유지하면서 필요한 서버 인증서·CRL 발급/갱신·제공과 실패 복구를 연결한다. 기존 격리 설치 시험이 별도로 준비한 CRL을 썼다는 점을 제품 신규 설치 인수와 구분한다.
3. 브라우저/장치 경로: 현재 별도 수집 endpoint는 유지한다. Portal 공개 주소가 설치 묶음의 등록 주소가 되는 부분을 보완해, 장치가 실제 접근하고 묶음 CA로 검증할 수 있는 등록 경로를 명시한다. 기본값은 공유할 수 있지만 도달 가능성·이름·CA·폐기 확인을 통과해야 한다. 공개 인증서를 사설 CA 고정 등록기에 그대로 적용하지 않는다. 서로 다른 망에서 접근해야 할 때의 주소만 운영자가 추가로 지정한다.
4. 복구와 산출물: 기존 사이트 복구 수정은 코드/모의 검증이며 현재 서버 이미지에 적용되지 않았다. 후속 후보 이미지를 다시 만들고 검토한다. Windows EXE 운영 서명·Portal 릴리스 mount/hash 고정은 별도 완료 조건으로 유지하며 unsigned 시험 파일의 성공을 운영 배포로 바꾸지 않는다.

대안 비교는 다음과 같다. 네트워크 접근과 TLS 신뢰는 각각 충족해야 한다.

| 방식 | 맞는 사용 상황 | 제약과 2안 판단 |
| --- | --- | --- |
| 기존 사설 CA + IP 또는 내부 DNS | 사내망·같은 네트워크, 기본 독립 설치 | 기존 CA를 재사용한다. 브라우저용 공개 CA 신뢰 안내와 실제 등록/CRL 제공을 완성하는 기본 경로다. Caddy 내부 CA를 새로 만들면 기존 장치의 신뢰가 달라지므로 단순 교체하지 않는다. |
| 공개 도메인 + Caddy 공개 인증서 | 별도 VPN 프로그램 없이 브라우저로 접속할 외부 사용자 | 도메인 소유/검증·도달 가능성·자동 갱신과 보존 저장소가 필요하다. 브라우저 인증과 장치의 기존 고정 CA 등록을 구분한다. 현재 Caddy 자동화 off 설정을 그대로 두고 자동 발급된다고 안내하지 않는다. |
| ngrok | 기존 방식의 임시 외부 시연 | 선택 경로를 보존한다. HTTP 터널은 기본적으로 ngrok에서 TLS를 종료하므로 설치 묶음의 고정 CA와 등록 주소를 별도 검토한다. 새 터널 제품으로 교체하는 것을 이번 기본 과제로 삼지 않는다. |
| Tailscale 같은 VPN | 관리자가 자신의 PC/휴대폰과 원격 서버를 연결 | 도메인 구매 없이 장치 IP로 연결할 수 있으나 양쪽 설치·가입·접근 정책이 필요하다. 모든 일반 방문자가 프로그램 없이 접속해야 하는 요구의 대체는 아니다. HTTPS 신뢰와 실제 등록/수집은 계속 확인해야 한다. |
| Cloudflare Quick Tunnel | 계정·도메인 없이 짧은 브라우저 시연 | 임시 주소이며 공식 문서는 운영용으로 일반 Tunnel을 안내한다. 기본 설치나 장치의 영구 등록/수집 주소로 사용하지 않는다. |
| 공인 IP 공개 인증서 | 도메인 구매 없이 공개적으로 신뢰되는 IP HTTPS가 필요한 경우 | Let's Encrypt IP 인증서는160시간 유효하므로 발급·갱신·적용·만료 감시가 한 흐름으로 필요하다. 기본 사설 IP 지원을 이 자동화 완료에 종속시키지 않는다. 필요 요구는 후속 선택 경로로 보존한다. |

공식 근거: [Caddy 자동 HTTPS/로컬 신뢰](https://caddyserver.com/docs/automatic-https), [ngrok TLS 종료](https://ngrok.com/security), [Tailscale 장치 연결](https://tailscale.com/docs/how-to/connect-to-devices), [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/), [Let's Encrypt IP 인증서](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability). 이러한 도구의 지원이 현재 Cloud SOC 코드와 바로 호환된다는 의미는 아니다.

구현은 기존 배포 인수/안전한 복구 → 신규 설치의 인증서·등록 일치 → IP/도메인 접속과 기존 상태 표시 연결 → 실제 장치의 일반 수신/경보 → 선택 외부접속/WAF 및 운영 Windows 산출물 인수 순으로 제안한다. WAF 수집과 WAF 설치는 별도이며 선택 시 지원 엔진/감사 형식과 실제 요청 근거를 확인한다. DetectionOnly의 관측과 차단 성공을 구분한다. 새로운 PKI 서버·오케스트레이터·대형 관리 화면은 이번 목적 달성의 선행 조건으로 추가하지 않는다.

인수 조건은 빈 Ubuntu의 Git 복제→설치→Portal 로그인, 도메인 없는 IP와 실제 DNS 이름의 두 경로, 별도 Windows/Ubuntu의 Portal 묶음 설치→최초 등록과 일반 원본 구분→정규화→실제 활성 규칙 경보/근거→대시보드다. 기본 시나리오는 쇼핑몰 없이 일반 웹/시스템 로그를 사용한다. Slack 선택 시 새 경보의 실제 채널 수신, WAF 선택 시 실제 감사 로그·경보와 모드를 추가 확인한다. 보존 제거·명시적 완전 제거·같은 자료로 복구 및 실패 중단을 각각 확인하고, 관리 EXE·상태 이력 등이 남는 현재 제거를 전체 완전 삭제로 표현하지 않는다. manager까지 제거할 범위는 명시적으로 설계해야 한다. 기존 사용자 데이터/웹사이트/공유 Docker 자원은 삭제 대상에 포함하지 않는다. 테스트/운영 적용은 이 제안 작성 중 실행하지 않았다.

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

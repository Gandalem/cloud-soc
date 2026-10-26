# Cloud SOC 작업 목록

문서 기준: 2026-10-27, Gandalem/cloud-soc main31de814의 학교 문서 통합·보관본에 이번 문서 수정을 더한 상태다. 기존 기능 대조의 코드 기준은 ac64198이며, 문서 정리 커밋과 기능 변경 커밋을 구분한다. 특정 PC의 D:/cloud-soc 경로가 항상 최신이라는 뜻은 아니다. 현재 기능/검증은 [프로젝트 상태](project_status.md), 사용은 [문서 색인](README.md)을 따른다.

## 작업 원칙

- 새 사용자 지시가 우선한다. 구현 시작 전에 관련 ID를 진행 중으로 기록하고, 명시된 인수 기준을 검증한 뒤에만 완료 체크한다.
- 작업 목록 안내나 개발 재개 전에는 실제 저장소 경로·원격 주소·브랜치·미커밋 변경과 로컬/원격 커밋을 확인한다. 다른 PC에서 push해도 현재 파일이나 대화는 자동 갱신되지 않는다. [동기화 기준 확인](local_development.md#여러-pc에서-같은-작업-목록-읽기)에 따라 최신 문서를 먼저 읽고, 원격 확인이 불가능하면 로컬 기준 커밋과 미확인 범위를 밝힌다.
- 구현·격리 검사·실제 설치·수신·배포는 별도다. 과거 부모 미체크나 오래된 실패를 현재 기능 전체의 부재로 확대하지 않는다.
- 기존 수정·로그/키/데이터·체크포인트와 완료 이력을 보존한다. 비밀값은 기록하지 않는다. 커밋/푸시·운영 배포·재부팅은 별도 요청 범위에서만 한다.
- 모든 이전 작업 ID의 상세 요구·순서·승인·완료 체크·실패/제한은 [압축 전 작업 목록](archive/README.md#record-docs-work-tracker-md)과 [10/12 누적 이력](archive/README.md#record-docs-work-history-20261012-md)에 원문 그대로 있다. 아래 ID가 생략됐다고 완료/취소된 것이 아니다.

## 현재 작업

- [ ] GIT-PUBLISH-20261027-01 진행 중(2026-10-27): 사용자 요청으로 현재 codex/agent-clean-reinstall의 장치 삭제 후 새 등록 설치·수동 키 연장/화면 정리·서버 설치/삭제 및 WSL 인수 변경과 관련 검사/문서를 Gandalem/cloud-soc에 커밋·푸시한다. 앞선 작업의 커밋/푸시 제외는 이 게시 요청 범위에서 대체한다. main 병합·운영 배포·새 기능 개발·전체 재검사는 하지 않는다. 게시 후보46경로를 확인했고 runtime/state·디스크/로그/개인키 확장자와 식별 가능한 비밀값 패턴은 포함되지 않았다. 기존 변경은 삭제·초기화하지 않고 현재 스냅샷으로 보존하며 원격 반영 결과는 후속 기록으로 확정한다.

- WSL 최종 인수/정리 결과(2026-10-27): 새 Ubuntu24.04.5/systemd·전용 Docker CLI/Engine29.9.2·기본 containerd image store(overlayfs), ES/Kibana9.5.2·Caddy2.11.4에서 실제 `soc install`→12서비스/CA 검증 HTTPS→상태/메뉴/도움말→삭제 취소→keep 확인1회/정상 종료→보존 상태→신규 설치 거부→공통 recover/install 복구→동일 키·인증서·합성 원본→purge 확인1회→반복 제거를 통과했다. Python 작업자8개의 HostConfig.Init=true도 실제 inspect로 확인했고 종료 한도90초·비강제 rm·권한/룰/체크포인트 계약은 유지했다. 보고서 state/server-ux-wsl-20261026-10/reports/result.json·cleanup.json·final-audit.json이며 원래 입력 비밀값/키는 기록하지 않는다.
- 실제 발견/수정(2026-10-27): Windows checkout의 확장자 없는 `soc` CRLF가 dash의 Illegal option 오류를 냈다. 작업본을 LF로 정리하고 .gitattributes의 /soc text eol=lf 및 POSIX/LF 회귀 검사를 추가했다. 전체 서비스 실험에서는 Python PID1 작업자가 SIGTERM을 무시해 keep가90초 대기 후 중단했고 원본/설정은 남았다. runtime.compose.yaml 공통7작업자와 compose.yaml enrollment-cleanup에 Docker 내장 init를 추가했다. 직접 영향 설정1검사(7하위 사례)·launcher1검사·Ruff를 통과한 뒤 새 WSL 전체 흐름을 다시 통과했다. 사용자 코드/규칙/상태/키·권한을 완화하거나 미종료를 성공으로 바꾸지 않았다.
- 시험 환경 실패 이력(2026-10-26~27): 초기 slirp 백그라운드 유지/식별 정보 전달·오류 기록 문제를 고쳤다. 별도 네트워크에 둔 Docker와 외부 containerd의 mount namespace가 달라 이미지 안 /bin/sh·python이 보이지 않는127 실패를 직접 진단했다. 새 trial에서만 packaged containerd를 runtime mask하고 Docker가 같은 공간의 자체 containerd를 쓰도록 설정했다. 진단용 overlay2 확인 뒤 최종은 Docker29.9.2 기본 overlayfs로 재검증했다. WSL 자동 유휴 종료로 /run·/tmp 진단이 사라진 시도는 비교 미확인으로 남기고, 최종에는 제한 시간 keepalive를 두었다. 준비/수정 과정의10개 trial은 동시에 누적하지 않고 앞 trial을 지운 뒤 진행했다.09의 미종료 작업자8개는 시험 정리 때만 SIGINT로 중단했으며 SIGKILL/제품 정상 종료 성공으로 세지 않았다.
- 공간/기존 환경 대조(2026-10-27): 최종 trial VHD8,568,963,072bytes와 재사용한 과거 Ubuntu WSL 다운로드388,975,696bytes, 각 trial의 임시 source.tar를 삭제했다.10개 시험 이름 등록0·시험 VHD0·임시 소스0이며 소량의 비밀값 없는 보고서만 남겼다. 기존 Ubuntu(D:/WSL/Ubuntu)·docker-desktop2개 배포판과 공유 Docker의 python/ES/Filebeat3이미지 ID, 기존 컨테이너/볼륨0은 유지했다. 임시 상향한 공통 vm.max_map_count는262144로 되돌렸고 최종 trial 밖 방화벽 규칙 대조도 일치했다. C 여유 공간은 최종 약46.3GB다. 호스트/기존 VM 재부팅·실제 로그/기존 키 변경·운영 배포·이관·커밋·푸시는 하지 않았다.
- 완료 범위(2026-10-27): 앞선 전체 설치 잔여 항목은 사용자가 선택한 새 WSL/systemd/독립 Docker 범위에서 해소했다. 물리 Ubuntu/EC2 설치·호스트 재부팅·실장치 수집/경보·부하 중 버퍼 flush/전체 분석 drain·HA/백업 복구 완료로 확대하지 않는다. 재현 도구 tests/manual/server_install_wsl_live.py는 시험 전용 slirp4netns1.2.1·이름/경로/소유 nonce 검증·실패 시 정리·공통 커널 원복을 사용한다. 제품의 새 Python/바이너리 의존성은 없으며 init는 Docker 기본 제공(Tini MIT)이다. 사용/공식 근거와 한계는 docs/runtime_deployment.md에 기록했다.

- [x] INSTALL-SERVER-UX-02-GRACEFUL-WORKERS 완료(2026-10-27, WSL 실제 종료 확인): 실제 WSL 설치12서비스는 성공했지만 Python PID1 작업자8개가 기본 SIGTERM에 종료하지 않아 keep의90초 한도가 실패했다. 미종료 데이터를 삭제하지 않은 것을 확인했다. 신호 전달/자식 회수를 위한 Docker 내장 init를 공통7작업자·enrollment-cleanup에 추가하고 명령/룰/상태/키/권한/종료 한도는 유지한다. 공식 Compose init와 Tini MIT 라이선스를 확인했으며 외부 실행 파일/새 Python 의존성은 추가하지 않는다. 수정 후 직접 영향 검사와 새 WSL의 전체 보존/복구/삭제를 재실행한다. 기존 배포/실서버는 변경하지 않는다.

- [x] INSTALL-SERVER-UX-02-WSL-LAB 완료(2026-10-27): 사용자가 WSL 전체 설치 시험과 시험 잔여물 정리/종료 후 새 시험 배포판 삭제를 요청했다. 기존 Ubuntu(D:/WSL/Ubuntu)·Docker Desktop은 유지하고 기존 검증 이력/보고서를 지우지 않는다. 이전 시험 배포판은 이미 정리됐으며 checksum이 기록된 Ubuntu24.04.5 WSL 이미지를 재사용한다. 사용자는 공통 vm.max_map_count의262144→1048576 시험 중 변경과 종료 후 원복을 명시 승인했다. 새 trial 전용 이름·소유 표시·레지스트리 BasePath를 대조한 뒤 새 systemd/전용 Docker 환경에서 soc 설치→상태→keep/재설치 차단→기존 자료 복구→purge/반복 삭제를 확인한다. 합성 자료/새 자격 증명만 사용하고 운영·기존 WSL 파일/서비스/키·공유 Docker 리소스·재부팅·이관·커밋/푸시는 제외한다. 종료 시 trial 배포판/VHD·임시 복사본을 정리하고 공통 커널 값·기존 배포판/공유 Docker 상태를 대조한다. 실제 실패와 남은 한계는 결과에 기록한다.

- [x] INSTALL-SERVER-UX-02 구현·WSL 실제 인수 완료(2026-10-27): 사용자 승인2안에 따라 중앙 서버의 정상 종료 확인 후 비강제 제거·한 번의 삭제 확인·구조화된 상태 표시·기존 설치/도움말/입력 안내를 보완한다. 안내/오류/도움말은 한글, 명령·주소·확인 입력은 영문으로 하고 개발 약속·AI식 설명은 제품 출력에 넣지 않는다. 실제 경로 cloud-soc-main/codex/agent-clean-reinstall이며 기존 미커밋 변경을 보존한다. 작성100% 전에는 검사·lint·빌드·실행 확인을 하지 않고 이후 필수 직접 영향 검사만 수행한다. 중앙 서버 기존 설치 엔진과 소유권/공유 자원/잠금·확인 대상 재검사를 유지하고 새 관리 UI/DB·중지재개 메뉴·에이전트 변경·운영 배포/키/데이터/재부팅·커밋/푸시는 제외한다. 실제 설치/삭제 통합은 독립 Docker 엔진과 폐기 가능한 Linux 환경에서만 수행하고 준비되지 않으면 모의/실제 검증 범위와 미완료를 구분한다.


- [x] INSTALL-SERVER-UX-02-CLI-CODE(2026-10-26): 승인2안의 소규모 서버 메뉴·입력 재안내·한글 도움말/오류·실제 Docker State/Health/ExitCode 상태, 일회성 bootstrap 구분, 잠금 안의 삭제 방식 선택/한 번 확인, 단계별 정상 종료/비강제 rm을 구현했다. 잘못된 주소·메뉴만 다시 받고 기존 최초 설치 엔진·ES 기본값·소유권/공유 자원/경로·확인 대상 재검사를 유지한다. 제품 출력에는 개발 약속·미완성 배지·AI식 서술을 추가하지 않았다. 파일: deploy/server/{soc.py,server_cli.py,prepare.py,install-ubuntu.sh,uninstall.py}, tests/{test_server_cli.py,test_install_device_tools.py,test_install_lifecycle.py,test_server_prepare.py}, deploy/server/tests/install-ubuntu.test.cjs, CI의 Windows 관련 검사 추가, deploy/server/README.md·docs/runtime_deployment.md. 기존 장치/Portal/키 연장 미커밋 변경과 CI 선행 변경은 보존했다.
- 최종 필수 검사 결과(2026-10-26): 작성100% 뒤 관련 Python55건 중54통과·Windows 링크 생성 권한1건 제외, POSIX 설치기41건은 초기40통과와 한국어 기대값 수정 후 해당1건 통과로 확인했다. 실패한 모의 Linux 호스트 설정은 제품 guard를 완화하지 않고 테스트의 플랫폼 객체를 수정했으며 lifecycle14통과·링크1제외를 확인했다. Ruff·직접 영향 diff 공백 검사 통과. 신구 Docker 긴 옵션 차이로 실제27 CLI가 실패한 것을 공통 `-t -1`로 수정하고 삭제7검사 및 실제 격리 시험을 다시 통과했다. 문구만 바뀐 상태4검사도 통과했다. 전체 프로젝트/UI/기존 장치 검사를 반복하거나 CI를 원격 실행하지 않았다.
- [x] INSTALL-SERVER-UX-02-REMOVAL-LAB(2026-10-26): 사용자의 새 시험 자원 추가 승인 후, 폐기 컨테이너 내부 Docker27.5.1 CLI/Engine·별도 소켓/데이터 루트·vfs·network none에서 실제 keep, purge, 종료2초 시험 한도 초과(강제 종료 없음/실행 상태·원래 설정·볼륨 원문 보존), 다른 프로젝트 컨테이너/볼륨 원문 보존, 실제 Linux 심볼릭 링크 설정 거부를 통과했다. 내부 컨테이너·볼륨0, 외부 시험 컨테이너·시험 이미지 제거를 확인했고 기존 python/ES/Filebeat3이미지는 같은 ID로 유지됐다. 초기 데몬 프록시 설정 누락은 시험 설정에서 수정했다. 고의로 TERM을 무시한 시험 컨테이너만 harness에서 강제 청소했으며 제품의 정상 종료 성공으로 세지 않았다. 파일: deploy/server/tests/server-removal.Dockerfile, tests/manual/server_removal_docker_live.py. 기존 WSL·커널/sysctl·호스트 방화벽·서비스·키·로그는 변경하지 않았다. 공유 빌드 캐시에는 전역 prune을 하지 않았다.
- 남은 인수/범위(2026-10-26): 부모 INSTALL-SERVER-UX-02는 빈 Ubuntu/systemd에서 메뉴→전체 신규 설치→상태→보존 제거/복구→purge 인수가 없어 미체크로 유지한다. 별도 VM/시험 서버와 최소 메모리·디스크·네트워크/이미지·터미널 조건이 필요하다. 이번 private Docker는 Linux 컴포넌트 확인이며 VM/커널 격리·실제12서비스 설치·실수신·분석 적체 drain·무손실·백업 복원 인수가 아니다. gateway는 포털/Kibana 접속 경로이며 장치9200 직접 수신의 차단 fence가 아니므로 종료 중 추가 원본 가능성도 설계 문서에 기록했다. 재부팅·이관·배포·커밋·푸시는 하지 않았다.

- INSTALL-SERVER-UX-02 작성 완료/최종 검사 시작(2026-10-26): 코드·한국어 안내·관련 검사·사용/삭제 문서 작성 뒤에만 검사를 시작했다. 새 시험 이미지 빌드가 공유 Docker 상태 변경으로 자동 승인 거부됐고, 사용자에게 이유와 범위를 설명한 뒤 사용자가 새 시험 자원만 추가하는 것을 명시적으로 승인했다. 기존 공유 Docker의 컨테이너/볼륨·키는 그대로 두고 새 폐기 컨테이너 안의 별도 소켓·데몬·데이터 루트로 컴포넌트 검사를 진행한다. 빈 VM 전체 설치 인수로 확대하지 않는다. 초기 검사 오류와 재검사 결과는 종료 후 아래에 기록한다.

- INSTALL-SERVER-UX-02 2안 검토/제안(2026-10-26): 사용자가 페르소나·필요성·인터넷 대안을 재검토하도록 요청했다. history-docs.zip의 siem_product_requirements 사용자4역할을 실제로 읽고 분석가용 새 운영 화면/대형 CLI 전환 필요성을 낮췄다. 현 uninstall.py의 중앙 컨테이너 docker rm -f가 보존 제거에도 적용됨을 확인했고, Docker 공식 rm/stop 문서로 강제 SIGKILL 및 기본 stop 시간초과 뒤 강제종료 동작을 확인했다. 2안의 핵심은 중앙 서버 정상 종료 확인 뒤 비강제 제거(시간초과 시 데이터 삭제/완료 처리 금지), 삭제 범위 요약과 동일 대상 한 번 확인·대상 변경 재확인, 기존 Docker 조회 경계의 State/Health/ExitCode·필수 상주/일회성 작업 구분이다. 메뉴/입력/도움말은 소규모 문구·재입력 보완에 한정한다. 보존 삭제를 백업/무손실/자동 복구로 부르지 않고 기존 소유권·경로·공유 자원·잠금/재검사·실제 종료 상태 보호를 유지한다. argparse 표준 라이브러리와 현재 Docker 경계를 재사용하며 Rich/Typer/TUI/웹 관리·중지/재개 신규 메뉴·설치 엔진 재작성은 도입하지 않는 제안이다. 별도 dry-run 의무화·전역 --yes/force 우회·실사용 자원 변경·커밋/푸시 없이, 구현 승인 전 제안으로만 남긴다. 공식 근거: docs.docker.com/reference/cli/docker/container/{rm,stop}/ 및 compose/{ps,down}/, docs.python.org/3.12/library/argparse.html, rich.readthedocs.io/en/stable/introduction.html, CLI 저자 지침 clig.dev. 새 검사·서비스 실행은 하지 않았다.


- INSTALL-SERVER-UX-02 초안 제안(2026-10-26): 사용자 요청으로 실제 soc.py/uninstall.py를 읽고 설치·상태·삭제·도움말4개 중심의 개선안을 작성한다. 현재 soc 메뉴에 중지/재개는 없으므로 이전 안내의 해당 항목은 새 구현이 필요한 후속으로 구분하고 이번 최소 범위에서 제외한다. 메뉴 입력 재안내·사용자용 상태/실패 설명·삭제 대상/보존 범위 요약과 상위 DELETE/하위yes 중복 확인 정리, 기존 소유권/공유 자원/동시 작업 보호 유지가 제안 범위다. 별도 dry-run 명령을 요구하지 않고 실제 삭제 전 최종 요약/확인은 유지한다. 코딩 착수/운영 실행/커밋/푸시 승인이 아니며 작업을 진행 중 또는 완료로 표시하지 않는다.


- CLICK-LAB 종료/인수 확정(2026-10-26): 사용자가 수동 연장 성공/화면 수정을 확인한 뒤 다음 작업을 요청해, 앞서 승인된 시험 종료·키/환경 정리를 stop.json으로 실행했다. session23891이0으로 종료됐다. cleanup-audit.json에서 전용 컨테이너/볼륨/네트워크0, TLS/Portal 비밀 디렉터리0,18780/18770/18766 포트 모두 닫힘, private_state_removed=true를 확인했다. 사용자 수동 클릭 성공 보고·실제 원격/로컬 만료 일치·동일 수집기/역할/limits·연장 뒤 정확 원본 수신 근거로 이 시험 범위를 완료했다. 새 UI 배치의 모델 직접 시각 확인·기존 만료 경과 장기 시험·운영 배포·재부팅은 포함하지 않는다. 원래 WSL/VM/기존 설정·키·데이터 및 미커밋 변경은 유지했다. 시험 포털은 이제 꺼진 상태다.
- 다음 작업 안내 제안(2026-10-26): 사용자 요청에 따라 기존 deploy/server/soc.py의 설치/상태/중지·재개/제거/도움말 사용 흐름을 다음 후보로 좁혔다. 메뉴 코드는 이미 구현돼 있으므로 새 메뉴를 중복 제작하지 않고 현재 설치 안내·삭제 범위/확인·실패 설명을 대조한 뒤 필요한 수정과 별도 실제 인수만 제안한다. 새 개발 착수·운영 실행·확정된 전체 우선순위 승인은 아니다. 정상 키 자동 회전/보존 큐 복원/이력 삭제 정책·커밋/푸시는 기존 보류/별도 요청을 유지한다.


- DEVICE-UI 작성100%(2026-10-26): 빈 알림 :empty 처리, 장치 정보/설치 details/수집 키 카드/연장 패널/분리된 종료 영역, OS/수집 목적 표시명·최초 수신/키/등록 문구와 실제 조치 사유 안내를 작성했다. 설치 완료 여부에 따른 설치 안내 기본 접힘, 최초 설치/연장/응답 유실 재조회/폐기 경고·종료 확인의 직접 영향 화면 검사도 작성했다. 지금부터 이 화면 검사만 최종 실행하며 엔진/키/권한 코드는 변경하지 않는다.


- [x] INSTALL-DEVICE-UX-04-DEVICE-UI 구현·직접 영향 검사 완료(2026-10-26): 사용자가 장치 관리 화면3개를 첨부해 문구/배치 수정을 요청했다. 빈 알림 영역, 설치 완료 뒤에도 펼쳐진 신규 설치 안내, OS/수집 목적 코드, 키 연장과 접근 차단 버튼의 인접 배치를 개선한다. 실제 상태·권한·연장/폐기 API·동일 요청 재확인 의미를 유지한다. 작성100% 뒤 직접 영향 화면 검사만 수행하며 전체 회귀/재부팅/커밋/푸시는 하지 않는다. 사용자 수동 연장 성공 보고는 기존 클릭 시험의 실제 엔진/수집 observer 결과와 구분해 기록한다.


- DEVICE-UI 최종 결과(2026-10-26): 작성100% 뒤 prototype/tests/devices.test.cjs의9건 통과, devices.js 구문·diff 공백 확인을 수행했다. 최초 장치 생성/설치 정보 펼침, 중복 제출, Windows 범위 차단, 안전한 키 이름 표시, 연장 미리보기/확인, 응답 유실의 같은 요청 재확인, 미제출 취소, 완료 장치의 한국어 표시/설치 정보 접힘, 폐기 경고·종료 전 확인을 확인했다. prototype/devices.{html,css,js}·직접 영향 UI 검사만 변경했고 backend/키/권한/만료 API는 변경하지 않았다. 시험 포털의 비로그인 CSS 접근은401로 차단됨을 확인했고, 별도 시험 로그인 세션에서 새 HTML/CSS 제공200을 확인한 뒤 그 확인용 세션만 logout했다. 사용자 기존 세션은 유지했다. 실제 브라우저의 새 배치 시각 확인은 도구 오류로 미수행이며 사용자 새로고침으로 확인 가능하다. 전체 회귀·재부팅·운영 배포·커밋/푸시는 하지 않았다.
- CLICK-LAB 사용자 확인/서버 대조(2026-10-26): 사용자가 직접 화면에서 연장이 잘 된다고 보고하고 스크린샷3개를 제공했다. 동시에 native-report.json에서 remote_extension_seen/local_confirmation/same_sender_identity/roles_unchanged/limits_unchanged=true와 연장 뒤 원본77건/정확 참조를 확인했다. 이는 사용자 수동 클릭 보고와 실제 ES/Filebeat observer의 결합 근거이며 모델이 클릭을 직접 수행/시각 확인했다는 뜻은 아니다. 첨부된 폐기 키/조치 필요 화면은 실제 상태를 감추지 않고 사유를 추가했다. 실행 자원은 시험 종료 기한까지 유지 중이며 정리 완료로 표시하지 않는다.
- [x] INSTALL-DEVICE-UX-03-KEY-EXTEND-CLICK-LAB 사용자 수동 클릭·서버 대조·정리 완료(2026-10-26): 사용자의 시험용 포털 실행 요청으로 새 TLS ES9.5.2·합성 managed 장치·실제 Filebeat 컨테이너와 내 PC loopback 전용 세션 로그인 포털을 준비한다. 사용자가 직접 연장 버튼을 누를 때까지 연장을 대신 적용하지 않는다. 기존 WSL/VM/키/데이터/서비스를 변경하지 않고 새 시험 자원만 사용한다. 화면 도구 오류는 유지됐지만 사용자가 직접 클릭 성공을 보고했고 서버 대조 및 정리는 아래 후속 기록으로 확인했다. 시험 로그인 비밀값은 채팅 전달만 하며 tracker/일반 로그에는 남기지 않는다. 자동 종료/정리 기한과 수동 stop 파일을 제공하고 커밋/푸시하지 않는다.


- CLICK-LAB 실행 준비 완료/수동 클릭 대기(2026-10-26): state/key-extension-click-20261026-attempt2의 새 TLS ES9.5.2·실제 Filebeat9.5.2 컨테이너, 같은 격리 DB의 내 PC loopback 세션 포털을 실행했다. 포털은 http://127.0.0.1:18780/devices.html이며 자동 종료 예정22:11 KST다. 사용자가 직접 선택할 합성 키 연장 클릭 시험 장치의 실제 Filebeat probe receipt·일반 합성 로그 수신을 확인했고 아직 키 연장은 적용하지 않았다. 로그인 비밀값은 일회성 채팅 전달만 하며 기록하지 않는다. 사용자가 연장한 뒤 원격/로컬 만료·동일 수집기 시작 시각/UUID/keystore hash·후속 원본을 read-only observer로 확인한다. 자동 정리는 stop.json 또는 lease 만료 시 수행하며 실행 중 자원을 정리 완료로 표시하지 않는다. 실행 session23891, 자원 label soc-os-lab-c64494f598, 기록 native-report.json이다.
- CLICK-LAB 초기 입력/배포 안내(2026-10-26): attempt1은 시험 helper가 /synthetic-click/access.log를 넣어 기존 Linux 웹 경로의 최소 parts4 조건(parts3)에 걸렸다. 제품 검증을 완화하지 않고 시험 경로만 /var/log/cloud-soc-click/access.log로 수정해 attempt2가 성공했다. 다른 사용자가 같은 짧은 경로를 입력하면 동일하게 거부되며 표준 경로 설치/수집 전체의 실패로 일반화하지 않는다. 사용자 지적으로 현재 오류 문구가 최소 깊이를 설명하지 않는 배포 UX 개선 후보를 기록한다. 이 안내 개선은 이번 실행 요청에 자동 포함하거나 구현 완료 처리하지 않는다. 초기 미사용 변수 lint 오류1건도 시험 helper에서 정리했으며 최종 Ruff 통과다. 제품 코드·기존 WSL/VM·운영 설정/키/데이터·커밋/푸시는 변경하지 않았다.
- [x] INSTALL-DEVICE-UX-03-KEY-EXTEND-WSL 실제 WSL/API 인수 완료(2026-10-26): 사용자가 WSL/Docker 실행 준비 후 실제 진행 방법을 요청해 새 격리 WSL의 제품 Filebeat 설치→연장 전 합성 로그→기존 키 연장→서비스/keystore/장치/수집기 ID 유지와 새 로그→폐기·환경 정리를 진행한다. 기존 Ubuntu/docker-desktop·VM·운영 데이터/키는 변경하지 않는다. 화면 도구는 초기 연결2회에서 trusted Node process exited unexpectedly로 실패해 가능한 실제 수집 확인을 먼저 진행하고 화면 직접 클릭은 확인된 범위만 기록한다. 기존 통과 회귀/경보/재부팅은 반복하지 않고 커밋/푸시는 하지 않는다.


- KEY-EXTEND-WSL 실제 결과(2026-10-26): 새 CloudSOC-KeyExtend-2404-* Ubuntu24.04.5/systemd·TLS ES9.5.2/Portal·실제 Filebeat9.5.2 제품 설치/receipt 후 합성 일반 로그 before-key-extension을 수신했다. 실제 HTTPS 관리 API로1일 수동 연장·동일 요청 재확인을 수행하고 after-key-extension 새 원본을 받았다. 동일 key/agent/org/package/enrollment 연결, 원격 역할/limited_by·캐시 만료 일치, 서비스 MainPID/시작 시각·설정/CA/keystore/receipt 해시 불변, 정확한 전후 요청 각1건과 이전 원본 source 해시 불변을 확인했다. 수집기 재시작/재설치는 하지 않았다. 제품 제거→키 invalidated=true·장치 ended·service/process/root 부재를 확인했다. 신규 manual 도구 tests/manual/device_key_extension_wsl_live.py만 추가했으며 제품 코드를 더 수정하지 않았다.
- KEY-EXTEND-WSL 제한/정리(2026-10-26): Computer Use/CUA 도구는 초기2회 모두 trusted Node process exited unexpectedly로 실패했고 사용자 첨부 스킬 목록에서도 보이지 않았다. 로컬 지침 파일 존재를 정상 실행/설치 상태로 해석하지 않는다. 플러그인 검색에도 정확 항목이 없었지만 삭제/장애 원인은 확정하지 않았다. 따라서 실제 브라우저 클릭은 미인수다. 기존 API/UI7검사를 새 클릭 인수로 바꾸지 않는다. 최소 발급1일의 기존 만료 경과·Windows·공격/경보·재부팅/운영 반영은 이번에 수행하지 않았다. initial attempt1은 새 Ubuntu 준비 명령에서 실패했고 해당 시험 배포판을 제거했다. attempt2에 새 최소 Ubuntu의 python/curl/openssl/CA/systemd 준비를 명시한 뒤 전체 흐름을 통과했다. 공식 준비 참고는 https://learn.microsoft.com/en-us/windows/wsl/systemd 와 https://learn.microsoft.com/en-us/windows/wsl/tutorials/linux 이다.
- KEY-EXTEND-WSL 근거(2026-10-26): Git 제외 state/key-extension-wsl-20261026-attempt2/{native-report.json,cleanup-audit.json,prepare.log} 및 native-soc-os-lab-334e3e8160/report.json·redacted 설치/제거 로그. 생성 전 이름 목록·이번 작업 token·WSL registry BasePath가 새 작업 경로와 일치함을 대조한 뒤 해당 trial만 terminate/unregister했다. original_distro_names_preserved/trial_distro_removed/trial_resources_removed/private_directories_removed=true, 시험18770/18766 포트 닫힘과 전용 컨테이너/볼륨0을 실제 확인했다. TLS/Portal DB/WSL 내 키는 정리했고 공개 결과만 남겼다. 기존 Ubuntu/docker-desktop·원본 D:/cloud-soc·기존 수정/실데이터/키·VM은 유지했으며 커밋/푸시/배포/재부팅하지 않았다. 직접 도구 Ruff와 diff 공백 검사 통과, 기존 통과 회귀를 다시 전부 실행하지 않았다.
- [x] LOCAL-DOCKER-CLEANUP-20261026 완료(2026-10-26): 사용자 요청으로 현재 Docker 이미지 사용을 조사했다. 컨테이너0이며 Docker/Ubuntu WSL은 실행 중이다. 이번 ES/Filebeat 수집 시험용 Elasticsearch9.5.2·Filebeat9.5.2·Python3.12 이미지를 유지하고 과거 상용화/OpenSearch 격리 시험용 PostgreSQL18.6·SeaweedFS4.48·OpenSearch3.9.0 미참조 이미지만 실제 이미지 ID/참조 부재를 대조하고 일반 image rm으로 삭제했다. Docker가 대상3개 모두 Deleted를 반환했으며 사후 목록은 Python3.12·ES9.5.2·Filebeat9.5.2만 남고 컨테이너0이다. 컨테이너·볼륨·WSL·소스·기존 데이터는 삭제하지 않고 시험 실행/커밋/푸시로 범위를 확대하지 않는다.


- KEY-EXTEND 작성100%(2026-10-26): 서버 미리보기/단일 제출 장벽/원격 재확인·권한 스냅샷 증명/기존 작업·감사 저장과 장치 상세의 연장·취소·같은 요청 결과 재조회, 직접 영향 API/UI·명시 opt-in TLS ES 시험 및 운영 계약 작성을 마쳤다. 기존 DB schema를 추가하지 않고 device_operations/result를 사용해 백업 경계를 유지한다. 지금부터 최종 필수 영향 검수·격리 검증을 처음 실행한다. 작성 완료를 배포나 실제 장치 수집 인수로 표시하지 않는다.


- [x] INSTALL-DEVICE-UX-03-KEY-EXTEND 구현·필수 격리 인수 완료(2026-10-26): 사용자 승인 3안에 따라 정상 설치된 로그 전용 장치의 기존 수집 키 수동 유효기간 연장만 구현한다. 실제 경로 cloud-soc-main / codex/agent-clean-reinstall / origin Gandalem/cloud-soc이며 기존 재설치·문서 미커밋 변경을 보존한다. 새 키 교체·자동 연장·제품 설치기 변경·운영 키/서비스·배포·재부팅·커밋/푸시는 제외한다. 원격 소유권/바인딩/최소 권한/유한 만료 검사, 상대 기간의 중복 재적용 방지, 불확정 결과 재조회 및 로컬 기록 조정, 기존 상세 화면과 감사 기록이 범위다. 작성100%까지 검수·테스트·빌드·lint를 하지 않고 이후 새 격리 ES9.5.2/합성 키의 필수 검사를 모아 수행한다. 완료 조건은 같은 키 수집 유지, 권한 보존, 원격/로컬 만료 일치, 폐기·권한/조직 경계·재시도/저장 실패 확인 및 시험 환경 정리다.
- KEY-EXTEND 최종 결과(2026-10-26): 작성100% 이후에만 첫 검수/검사를 수행했다. 기존 직접 영향 장치·키·TLS 회귀36건, 신규 연장 API/상태 검사17건(5 subtests 포함), 화면 동작7건, opt-in 실제 TLS ES9.5.2 시나리오1건이 최종 통과했다. 고유 Python54건+UI7건이며 재실행을 중복 합산하지 않는다. 신규 검사는 정상·중복/내용 충돌·동시 적용·응답 유실·완료 저장 후 rollback·attempted 뒤 중단/새 서비스 객체 재확인·취소·다른 장치/조직·만료/폐기/무기한/network·소유자 권한 축소·CSRF/비관리자·시각 차이/부분 노드·종료 경합을 확인했다. 기존 백업 스키마/검증은 바꾸지 않았다. 변경 파일 Ruff·diff 공백 검사와 아래 최종 문서 확인을 수행했다.
- KEY-EXTEND 실제 범위(2026-10-26): 새 loopback TLS ES9.5.2/새 native realm 발급 계정·합성 managed 장치·원본 인덱스에서 제품 등록/receipt API 후 연장 전후 같은 키 create_doc 수집, 키 ID/할당 역할/limited_by 보존, 원격/캐시 만료 일치, 범위 밖 쓰기·읽기·키 관리403, 실제 원격 성공 후 응답 유실/로컬 완료 저장 실패와 같은 요청 재확인, 발급 권한 축소/잘못된 인증·폐기/만료 거부, 장치 종료, 신뢰 CA/호스트 이름 검증 실패를 확인했다. 송신은 Python ES API이며 실제 Filebeat/Windows/WSL 설치·브라우저 직접 클릭·새 경보·재부팅/운영 배포 인수로 확대하지 않는다. 근거는 Git 제외 state/key-extension-20261026의 units.xml·units-repair.xml·final.xml·live-final.xml과 검사 소스다. final.xml은 신규17건 통과와 이후 수정한 live 시험 도구 순서 실패를 포함하므로 live-final.xml의 후속 성공과 함께 읽는다.
- KEY-EXTEND 수정/정리(2026-10-26): 초기 새 fixture의 Ubuntu/Windows proof 참조, 시험 issuer의 기존 pipeline 읽기 권한과 Python api_key 표현, 추가 실패 주입의 실행 순서 오류를 수정했다. 실제 ES의 get API 응답에 Date 헤더가 없어 잘못된404가 되던 제품 호환 오류는 기존 monitor 권한의 Nodes Stats timestamp/전체 노드 성공 확인과 명시 오류로 수정했다. 각 수정의 영향 검사만 다시 실행했으며 제품 권한·인수 기준을 완화하지 않았다. 각 live 실행 finally에서 해당 컨테이너/전용 TLS 볼륨 제거를 확인했고 최종 Docker 목록의 soc-key-extension-* 컨테이너/볼륨은0이다. 새 비밀 파일·키·DB는 시험 TemporaryDirectory cleanup, 원격 키/원본은 폐기 컨테이너 제거로 정리했다. 공개 결과 XML만 보존한다. 기존 미커밋 재설치/문서 변경·D:/cloud-soc·운영 설정/데이터/기존 키는 유지했고 커밋/푸시·배포·재부팅은 하지 않았다.
- KEY-EXTEND 남은 제한/다음 조건: 실제 단말/운영 반영은 별도다. 연장은 새 비밀값 교체나 유출 대응이 아니다. attempted 저장 후 미전송 중단·불일치 표식은 자동 재연장/자동 취소하지 않고 확인 필요로 유지한다. 다른 엔진/버전·전체 OS/브라우저·장기/다중 노드 장애·사이트 손실/백업 복원 조정은 미인수이며 분산 exactly-once를 보장하지 않는다. 세부 정책과 공식 근거는 agent_management.md의 수동 유효기간 연장 절을 따른다. 정상 키 교체·자동 회전·별도 자격 원장·종료 이력 정리 등 기존 부모 작업은 이번 완료로 표시하지 않는다.
- [x] INSTALL-DEVICE-UX-02-REINSTALL-WSL 실제 Linux 재설치·중앙 수신 완료(2026-10-26): 최신 사용자 요청으로 남은 Linux 실제 삭제→새 등록 설치→중앙 수신을 새 Ubuntu24.04.5/systemd WSL에서 확인했다. 기존 Ubuntu·Windows 결과와 미커밋 변경을 보존하고 새 TLS ES9.5.2/Portal·합성 장치2개·실제 Filebeat9.5.2만 사용했다. 작성100% 이후 최종 인수의 연속이며 기존 Windows/공격/경보 검사는 반복하지 않았다. 이번 확인으로 제품 코드를 추가 수정하지 않았고 명시 실행 전용 tests/manual/device_wsl_reinstall_live.py와 결과 문서만 추가/갱신했다. 기존 서비스/실제 데이터/키·호스트/VM 재부팅·커밋/푸시는 변경/실행하지 않았다.
- WSL 준비/결과: 공식 Ubuntu WSL 이미지의 HTTPS SHA256SUMS와 bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e를 대조한 뒤 기존 목록에 없던 CloudSOC-Reinstall-2404-20261026을 별도 경로에 import했다. 실제 OS24.04.5/PID1 systemd/필수 도구를 확인했다. 제품 bootstrap→keystore/서비스/새 receipt/정확한 합성 일반 로그→다운로드 원본 제거 뒤 status→자료 보존 제거/새 설치 거부와 기존 receipt hash 불변→기존 관리 도구에서 DELETE 확인 후 보존 자료 삭제/이전 장치 별도 종료→새 장치 설치/다른 수집기 UUID/새 receipt/after-clean-reinstall 요청 ID의 정확한 새 수신→이전 원본 source·제거 이력 receipt hash 불변→두 번째 자료 삭제/장치 종료와 서비스·프로세스0을 실제 확인했다. 보존 큐 복원·새 경보·DEB 패키지·일반 VM 부팅 인수로 확대하지 않는다.
- WSL 정리/근거: 생성 이력과 WSL 등록 BasePath가 이번 작업의 절대 시험 경로와 일치함을 확인한 뒤 해당 배포판만 terminate/unregister했다. 원래 Ubuntu/docker-desktop 이름 목록 유지, 시험 컨테이너/볼륨0·TLS/Portal DB 디렉터리0·시험 포트 닫힘을 확인했다. 공식 공개 이미지 캐시와 비밀 없는 결과만 남겼다. 기록은 Git 제외 state/agent-clean-reinstall-20261026/wsl-lab/{image.json,native-report.json,distro-cleanup.json,cleanup-audit.json} 및 native-*/report.json·redacted 로그다. source: https://releases.ubuntu.com/24.04/ 및 SHA256SUMS. 새 수동 도구 Ruff 통과, 최종 문서/변경 확인만 수행하고 이미 통과한 단위·Windows 시험은 반복하지 않았다. 운영 서명/GUI·보존 큐/신원 복원·키 자동 회전·장기/장애/독립 복구·전체 OS 매트릭스는 후속 범위로 유지한다.

- [x] INSTALL-DEVICE-UX-02-REINSTALL-BASIC 기본 구현·필수 검수/Windows 격리 인수 완료(2026-10-26): 사용자 승인 2안으로 범위를 축소해 수집기 자료 삭제 완료 후 같은 PC에서 새 등록으로 설치하는 경로만 보완했다. 상위 INSTALL-DEVICE-UX-02-RECOVERY의 큐/신원 복원은 이번 범위가 아니다. Windows native의 purged 기록 처리·기존 제거 화면 선택/도움말, Linux 완료 기록 잔존 차단과 보존 제거 후 명시 자료 삭제를 수정했다. 기존 문서4개 미커밋 변경은 state/agent-clean-reinstall-20261026/baseline에 보존했다. 작업은 cloud-soc-main의 codex/agent-clean-reinstall, 기준 main31de814이며 원본 D:/cloud-soc는 변경하지 않았다. 사용자 지시대로 작성100% 전에는 검수·빌드·테스트·lint를 하지 않았고 이후 필수 영향 검사만 수행했다. 실제 Linux 에이전트 재설치/새 중앙 수신·운영 서명 릴리스·GUI 시각/직접 클릭 전체 인수는 이번 완료에 포함하지 않는다. 운영 서버·기존 데이터/키·배포·재부팅·커밋/푸시는 제외했다.
- 작성100%(2026-10-26): Windows의 purged+새 장치/등록+관리 파일 무결성+잔여물 부재를 확인한 이전 관리 폴더의 보호 이력 이동과 기본 신규 설치 연결, 기존 제거 화면의 보존 기본/명시 삭제·추가 확인·도움말을 작성했다. Linux는 complete-*.json의 전역 잔존이 새 패키지를 차단하는 조건을 확인해 자료 삭제 기록과 대조한 완료 receipt 보관, 보존 제거 후 명시 자료 삭제를 기존 관리 도구에 추가했다. 새 Portal/등록 API·키 회전·큐 복원은 없다. C# 계약/실제 임시 파일 경계·제거 선택 기본값, Python 임시 파일/OS 대역·신규 진입점·실패 재시도 검사와 Windows CI 선택 목록, 장치 설치 문서를 작성했다. 지금부터 필수 영향 검사/빌드/문서 확인을 처음 실행하며, 작성 완료를 실제 VM 재설치·중앙 수신 인수로 표시하지 않는다.
- 최종 코드 검사(2026-10-26): 작성100% 뒤 첫 집중 검사45 passed/14 subtests passed, C# 실제 컴파일/실행 계약41항목·제거 선택의 보존 기본/취소·purged 외 차단·새 등록 강제·기존 장치/등록/TLS 회귀를 통과했다. 호스트가 비관리자여서 C# 실제 ACL/이력 이동은 명시 skip이며 통과로 세지 않는다. 별도 network=none/read-only/code-only 격리 Python3.12 컨테이너에서 Linux root 소유권·실제 symlink/hardlink·보존/삭제·receipt 이동·새 설치 진입·삭제 실패 재시도12항목을 통과했다. systemctl/pgrep/등록 전송은 대역이며 실제 Linux 에이전트 재설치로 확대하지 않는다. 시험 EXE 빌드·변경 파일 Ruff·직접 영향 문서2검사·diff 공백도 통과했다. 근거는 Git 제외 state/agent-clean-reinstall-20261026/results.xml·linux-root-result.json·release-lab이다.
- 실제 VM 인수 준비 이력(2026-10-26): 사용자가 VM을 켜고 새 시험 접속 준비를 할 수 있다고 응답해 새 공개키·원복 전 상태 기록·호스트 한정 방화벽의 준비 명령과 응답 창구를 제공했다. 기존에 사용자가 확인한 Windows 지문과 새 준비 응답을 대조한 뒤 새 키로만 접속했다. tests/manual/device_windows_reinstall_live.py는 명시 --run 전용으로 새 TLS ES/Portal·합성 장치2개의 최소 재설치 흐름을 확인하며 pytest가 VM을 변경하지 않는다.
- 실제 Windows 결과(2026-10-26): Restricted/관리자 VM에서 별도 임시 EXE의 실제 ACL·manager 해시·잔여 session 차단·부재 검사 실패 시 상태 유지·이력 이동/충돌 차단을 통과했다. 이어 제품 EXE의 첫 설치/새 receipt/합성 일반 로그→보존 제거 후 새 설치 차단→명시 purge/별도 기존 장치 종료→새 장치·enrollment·수집기 UUID/새 receipt·일반 로그→두 번째 purge/장치 종료를 통과했다. 이전 원본 검색 참조의 source 해시와 제거 이력 state.json SHA256 불변, 실행 정책 Restricted를 대조했다. GUI는 폼 객체의 기본 선택/취소 계약만 검사했고 실제 설치 엔진은 CLI로 실행했다. 기존 공격/경보·재부팅 검사는 반복하지 않았다. 근거: state/agent-clean-reinstall-20261026/vm-lab/native-report.json 및 native-*/report.json·redacted 로그.
- 정리/제한(2026-10-26): 이번 VM 수집기/service/task/관리 폴더와 소유 이력·합성 장치 키, 임시 ES/볼륨·TLS/Portal DB·호스트 시험 개인키를 정리했다. 새 공개키·방화벽·준비 폴더·정리 task 제거와 OpenSSH.Server 원래 NotPresent/Restricted 복원을 vm-access-cleanup.json으로 확인했다. Windows가 capability 제거 후 restart_needed=true를 보고했으나 재부팅하지 않았고 시험 포트5개/VM SSH는 닫힌 것을 확인했다. cleanup-audit.json의 개인키=false·private TLS/DB 디렉터리0이다. Linux root 검사 컨테이너도 제거됐다. 공개 결과·시험 공통 EXE·검사 소스만 Git 제외 상태 경로에 보존한다. CI는 새 Windows 검사 파일과 Linux root fixture 실행을 기존 workflow에 연결했지만 원격 Actions를 실행/통과한 것으로 표시하지 않는다. 관련 파일: agent-manager.py·enrollment-linux.py·native/{Contracts,Installer,Program}.cs·native-installer-tests.cs·test_agent_clean_reinstall.py·test_windows_native_contracts.py·수동 도구·ci.yaml·device_installation.md·project_status.md. 부모 복구·수명주기·운영 릴리스와 다른 작업은 완료 처리하지 않았다.

- [x] DOC-BASELINE-20261026-01 문서 수정 완료(2026-10-26): 학교에서 게시한 main31de814의 문서 정리를 보존하고 작업 안내의 기준을 수정했다. 저장소/브랜치/로컬·원격 커밋 확인 절차, 코드 기준과 문서 기준의 구분, 이미 구현된 기능과 후속 개발·추가 인수의 구분을 명시했다. 이전 답변의 설치 마무리→배포→서버→키/트래픽 순서는 제안일 뿐 사용자 승인된 전체 순위가 아니다. 변경 파일은 work_tracker.md·project_status.md·local_development.md·docs/README.md다. 직접 영향 안내 문서의 기존 구문/링크 검사3건과 diff 공백 검사를 통과했다. 기존 완료/미체크 이력·보관 ZIP과 기능 코드는 유지했다. 기능 개발·실서버 검사·배포·재부팅·커밋/푸시는 수행하지 않았다. 학교에서 이번 수정본을 보려면 별도 커밋/푸시와 해당 작업 폴더의 갱신이 필요하다.

- DOC-PUBLISH-20261026-01 요청/범위(2026-10-26): 사용자 추가 지시로 아래 문서 통합·압축 변경을 main에 커밋하고 origin/main으로 일반 푸시한다. 이전 문서 정리 시점의 커밋/푸시 제외는 이번 Git 반영 요청으로 대체한다. 대상은 README·문서/보관 ZIP·문서 검사 경로 수정이며 기존 Portal app.py/test_alert_navigation.py 미커밋 변경은 제외·보존한다. 운영 배포·키/데이터·재부팅 허가로 확대하지 않는다. 커밋과 원격 반영의 실제 결과는 Git 이력과 최종 응답으로 확인한다.
- 게시 결과 확인(2026-10-26): 원격 main31de814bd9ed25d243466cee25811ff867ba973b에서 학교의 문서 통합·보관 변경을 확인했다. 이 PC의 별도 작업 폴더 cloud-soc-main은 ac64198에 머물러 있었으며, 미커밋 변경이 없는 것을 확인한 뒤31de814로 fast-forward했다. 원본 D:/cloud-soc의 별도 브랜치와 미추적 파일은 변경하지 않았다. 학교 PC의 미커밋 Portal 수정은 이 PC에 전달된 것으로 간주하지 않는다.

- [x] DOC-ARCHIVE-20261026-02 완료(2026-10-26): docs 루트85파일→현재 안내32개, 하위 포함125→41파일로 정리했다. 과거 설계/날짜별 검증·긴 작업 이력, Mall17문서, 참고/루트 중복 안내2개, 포트폴리오10자료, Word2개를5개 ZIP의 원래 경로·MANIFEST.json에 보존했다.98개 원본의 CRC/크기/SHA256을 대조한 뒤 개별 파일94개만 삭제했다. docs 전체 용량은 약4.40→3.14MB(약29% 감소)다. 현재 사용은 portal_usage.md와 optional_integrations.md로 모으고 이전 미체크 ID49개/전체 완료·승인 원문은 그대로 유지했다.
- 검수/범위: 문서 구문·참조16검사와 README 추가 정리 후 직접 영향2검사가 통과했다. 현재 상대 링크274개·압축 원문406개 누락0, 소스의 삭제 문서 참조0을 확인했다. CI용 coverage.svg/evaluation.json과 기존 app.py/test_alert_navigation.py 수정은 해시 불변이다. 원본/ZIP 계획·검수 결과는 Git 제외 state/document-archive-20261026에 있다. 문서 검사 외 기능 실행·서비스/배포·키/데이터 변경·재부팅·커밋/푸시는 하지 않았다. 압축 원문은 조회/복원용이며 현재 코드/서버에 덮어쓰는 배포물이 아니다.

## 다음 작업을 정하는 기준

아래는 남은 범위의 구분이며 새 전체 실행 순서가 아니다. 다음 개발을 시작할 때 사용자 요청에 맞는 관련 ID와 인수 조건만 선택한다. 이전 대화의 설치 마무리→배포→서버→키/트래픽 순서는 제안으로 남기고 확정된 우선순위로 재사용하지 않는다.

| 구분 | 남은 범위 | 이미 있는 기능/근거 |
| --- | --- | --- |
| 후속 개발 · INSTALL-DEVICE-UX-02-RECOVERY | 제거 완료 장치의 재설치·보존 큐 복원과 신원/키 조정 | 기존 Windows Repair/Resume·일부 설치/제거 재시도는 있음. 복구 전체를 처음 만드는 작업이 아님 |
| 후속 개발 · INSTALL-DEVICE-UX-03-LIFECYCLE | 정상 등록 장치의 수집 키 교체, 종료 이력의 보관·한도 회수 정책 | 실패 재등록·미사용 등록 정보 갱신·키 폐기·별도 heartbeat 자격 증명 회전은 있음 |
| 추가 인수 · INSTALL-DEVICE-UX-01-WINDOWS-NATIVE-RELEASE / INSTALL-DEVICE-UX-01-RELEASE | 운영 서명 산출물 공급·Portal 연결/조직 정책, 실제 DEB 설치·제거, 새 서버 메뉴 실제 흐름 | sign/verify·Portal mount/SHA pin·DEB 빌드·soc 메뉴는 구현됨. 10/25 양 OS 설치·합성 경보·제거도 확인됨 |
| 정책 결정 후 개발 | Windows manager 자체 제거와 감사/상태 보존의 선택, 다중 배포·업데이트 | 수집기/큐 purge는 있음. 관리 기록 보존을 무조건 결함으로 단정하지 않음 |

기능별 제한과 다른 트랙은 [프로젝트 상태](project_status.md#implementation-gaps), 설치 세부 조건은 [장치 설치](device_installation.md#남은-범위)를 따른다. 완료된 기본 수집→경보 흐름을 위 부모 미체크만으로 미구현으로 되돌리지 않는다.

## 최근 완료 요약

- [x] DOC-CONSOLIDATION-20261026-01(10/26): 중복11문서→4문서, 대상170,534→56,077bytes·1,162→473행. 문서16검사/상대 링크660개 통과. 현재 정리로 후속 경로가 다시 바뀌었으며 원본/기록은 history-docs.zip에 보존했다.
- [x] CODE-GAP-AUDIT-20261026-01 / DOC-STATUS-AUDIT-20261026-01(10/26): 문서/코드 대조 완료. 기본 설치·실수신·경보·기존 Repair/재등록·지속 heartbeat는 존재한다. 정상 설치 수집 키 교체/제거 후 복원과 보존 정책, 릴리스/미인수 범위를 구분했다. 새 실서버 검증은 하지 않았다.
- [x] GIT-UPDATE-20261026-01(10/26): 기존3파일 수정/백업을 보존하고 main34c2139→ac64198 fast-forward. 갱신이 배포를 뜻하지 않는다.
- [x] INSTALL-DEVICE-UX-01-NATIVE-MERGE(10/26): PR20 병합17a32c4, 코드50ebce9의 Ubuntu/Windows CI 성공 기록.10/25 양 OS 제품 설치·합성 경보·제거/TLS 결과는 [장치 설치](device_installation.md#검증-이력)에 모았다. 운영 서명/모든 복구/GUI 전체 인수는 별도다.

## 이전 미체크 작업 ID

압축 전 목록의 미체크49개를 관리상 그대로 남긴다. 아래는 현재 미구현 기능이나 새 실행 순서가 아니다. 예를 들어 WINDOWS-POLICY의 초기 실패는 후속 native LAB 성공으로 갱신됐지만 운영 릴리스 부모 체크는 유지됐고, DASHBOARD-MOVE-01은 사용자 지시로 검수를 생략했다. P2-02의 독립 저장소/보관·복원과 OCI 운영 연결 보류도 유지한다. 각 원문과 후속 완료를 함께 확인한 뒤 관련 ID만 갱신한다.

- [ ] INSTALL-DEVICE-UX-01-WINDOWS-NATIVE
- [ ] INSTALL-DEVICE-UX-01-WINDOWS-NATIVE-RELEASE
- [ ] INSTALL-DEVICE-UX-01-OS-LAB
- [ ] INSTALL-DEVICE-UX-01-WINDOWS-POLICY
- [ ] INSTALL-DEVICE-UX-01
- [ ] INSTALL-DEVICE-UX-01-RELEASE
- [ ] AWS-AGENT-EXEC-01
- [ ] PORTAL-NGROK-ENTRY-01
- [ ] VIDEO-E2E-01
- [ ] DASHBOARD-FUNCTIONS-02
- [ ] DASHBOARD-MOVE-01
- [ ] RULE-AUTHORING-01
- [ ] CORE-INGEST-ALERT-01
- [ ] GENERIC-WAF-01
- [ ] GENERIC-CORE-01
- [ ] GENERIC-SITE-01
- [ ] GENERIC-OPERATIONS-01
- [ ] OPS-RUNTIME-01
- [ ] OPS-ACCEPTANCE-01
- [ ] RULE-MANAGEMENT-08
- [ ] MALL-APP-06E2A-TWO-STOP-TRANSITION
- [ ] MALL-APP-06E2A-APPROVED-TRANSITION
- [ ] MALL-WAF-06E2A-FINAL-TRANSITION
- [ ] MALL-WAF-06E2A-WAF-RETRY
- [ ] MALL-WAF-06E2A
- [ ] MALL-WAF-06D
- [ ] GIT-INTEGRATE-20261015-CI
- [ ] PARITY-FRESH-OS-01
- [ ] PARITY-CENTRAL-LIVE-01
- [ ] DET-EXT-ACTIVATE-20261014
- [ ] SITE-AGENT-01
- [ ] SITE-LIVE-01
- [ ] ISSUE-12
- [ ] DET-EXT-LIVE-01
- [ ] DASH-01
- [ ] UX-02
- [ ] P0-02
- [ ] P2-02
- [ ] P2-03
- [ ] P3-01
- [ ] P4-01
- [ ] P5-01
- [ ] P5-02
- [ ] P5-03
- [ ] P5-05
- [ ] P6-02
- [ ] P6-04
- [ ] P7-01
- [ ] P7-02

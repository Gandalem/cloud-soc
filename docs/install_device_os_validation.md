# VM·WSL 실제 수집 시험 — 2026-10-25

작업은 `codex/install-device-experience`의 `defcaa1`에서 시작했다. 원본 `D:/cloud-soc`와 상용화 PoC, 운영 서버·실제 로그·기존 키는 수정하지 않았다. 새 시험에서 발견한 수정은 미커밋 상태이며 추가 커밋·푸시·main 병합·재부팅을 하지 않았다.

## 결과 구분

| 범위 | 실제 결과 | 완료로 확대하지 않는 범위 |
| --- | --- | --- |
| 새 Ubuntu24.04.5 WSL/systemd | 제품 bootstrap→manager→실제 Filebeat9.5.2 설치·TLS/CRL·keystore·서비스·등록 receipt·수집·분석·경보·자료 보존 제거 통과 | 일반 Ubuntu VM의 부팅/재부팅, 전체 출처/규칙, 장기 무손실 운영 |
| Windows10 VM/build19045 | 공식 Filebeat9.5.2의 실제 네이티브 실행·TLS·keystore·동적 입력·합성 수집→분석→경보·원본/hash·원격 키 폐기 통과 | 제품 bootstrap/EXE의 설치 성공, Windows 서비스 설치/제거, Windows 설치기 CRL/Schannel 전체 경계, 서명 배포물 |
| Windows 제품 진입점 | 기본 Restricted에서 bootstrap ps1 실행 차단을 실제 확인. 정책은 전후 Restricted로 유지 | 코드 서명만 하면 Restricted가 해결된다는 가정, 정책을 바꾼 시험의 제품 배포 인수 전용 |
| Portal | Windows 경보의 실제 `/api/alerts/detail`에서 같은 경보 ID와 근거3건 조회 확인 | 브라우저 시각 검수나 모든 대시보드 기능 인수 |

Windows의 수집기 시험은 설치기 우회 성공으로 표시하지 않는다. 시험 제어기가 실제 enrollment API를 호출해 새 합성 장치 키를 발급하고, 보호된 임시 전송 파일에서 native Filebeat keystore의 stdin으로 넣은 뒤 그 임시 파일을 즉시 제거했다. 제품의 Windows 등록 helper/관리자 권한 화면을 통과한 결과가 아니다. 보호된 시험 디렉터리와 이름이 고정된 폐기용 Scheduled Task로 실행했으며, 제품 수집기 서비스를 설치하지 않았다. 실행 정책 변경·Bypass·Unrestricted·제품 ps1 내용 재입력은 사용하지 않았다.

분석은 기존 `processing.worker.run_once`와 `detection.worker.run_once`를 제한된 새 분석 키로 실제 Elasticsearch에 실행했다. 새 source profile은 system=false의 명시적 웹/WAF 파일만 허용했다. 규칙은 변경하지 않은 `WEB-SITE-WAF-001`이며 기본 선택에 유지되는 AUTH-001의 입력은 만들지 않았다. 이동 시간 창300초·서로 다른 SQLi 요청3건·cooldown300초를 완화하지 않았다. 이 시험은 정상 서비스의 연속 작업자 배포나 실제 쇼핑몰 공격 시험이 아니다.

## 양성·음성·증거

양 OS에서 각각 별도의 새 엔진/장치를 사용했다. 입력은 명시적 UTC ModSecurity 형식의 합성 JSON이며, 실제 공격 요청을 보내지 않았다.

1. 서로 다른 SQLi 요청2건과 비SQLi 규칙 요청3건을 실제 파일에 기록했다. 실제 수집 문서5건과 정규화5건을 확인한 뒤 경보0건을 확인했다. 입력 미도착을 음성 결과로 세지 않았다.
2. 같은 조직·호스트·사이트·출발지의 SQLi 요청 한 건을 추가했다. 정규화6건과 `WEB-SITE-WAF-001` 경보1건을 확인했다.
3. 동일 범위를 다시 분석해 기존 경보1건, 신규 중복0건을 확인했다.
4. 경보의 근거3건에서 normalized index/id, raw index/id, 조직·호스트·사이트·실제 키의 패키지 연결을 대조했다. 기존 `event_evidence`로 각 event_hash를 재계산해 일치함을 확인했다.
5. HTTP URI의 시험 privacy canary가 수집 raw metadata에 남지 않음을 확인했다. 기존 개인정보 선별 의미를 유지하며, 수집 raw metadata와 디스크의 원래 WAF JSON 전체를 같은 바이트라고 주장하지 않는다.

WSL의 설치 완료 receipt는 수집기가 직접 보낸 문서로 확인했다. 단기 원본 다운로드 폴더를 삭제한 뒤 보호된 설치 경로의 manager status를 실행했고, 실제 stop/start와 자료 보존 uninstall을 수행했다. 제거 후 `/opt/cloud-soc-agent`와 소유 unit3개가 없고 retired data 아래 파일6개가 남음을 확인했다. 이후 장치를 원격 폐기했다. 보존 확인 후 폐기용 WSL 배포판 전체를 정리했으므로 시험 큐를 운영 복구 자료로 보관하지 않는다.

## 발견한 오류와 수정

### 동적 입력의 경로 변수

설치 proof는 도착했지만 웹/WAF 입력은 `Unable to hash given config: missing field accessing '0.processors'/'1.processors'`로 재적재되지 않았다. `collection-profile.json`의 script.file 값 `${path.config}/site-privacy.js`가 외부 설정 hash 단계에서 해석되지 않았다.

[Elastic Script Processor 공식 문서](https://www.elastic.co/docs/reference/beats/filebeat/processor-script)는 상대 파일 경로가 path.config 기준이라고 명시한다. `src/cloud_soc/portal/site_agents.py`를 `site-privacy.js` 상대 경로로 수정했다. Linux와 Windows가 같은 프로필 생성기를 사용하며, 실제 양 OS 수집으로 경로 처리를 확인했다. 처리기·필터·키 권한·규칙은 제거하거나 완화하지 않았다. 기존 운영 프로필은 자동으로 다시 쓰지 않았다.

직접 영향 `tests/test_site_agents.py` 16개 통과, 수정 소스와 새 수동 시험 도구 Ruff 통과. 이전의 전체 통과 suite나 원격 CI를 반복 실행하지 않았다.

### 시험 도구의 전달·시각·범위

Windows→WSL 코드 전달의 백슬래시 이스케이프를 제거했다. Windows OpenSSH에서 자식 콘솔의 stdin 종료/줄 입력 대기로 파일 전달이 멈추는 현상을 확인해 SFTP로 바꿨다. 장치 키는 보호된 일회성 파일에서 자식 native 프로세스의 명시적 stdin으로 전달하고 즉시 정리했다. 문제 해결 참고는 [Microsoft OpenSSH 문서](https://learn.microsoft.com/en-us/windows-server/administration/OpenSSH/openssh-server-configuration)와 [OpenSSH 파이프 대기 이슈](https://github.com/PowerShell/Win32-OpenSSH/issues/2452)다. 제품 동작 변경과 시험 도구 수정은 구분한다.

WSL은 host 대비 약1.8초 선행하는 측정이 있었다. [Canonical 시간 동기화 설명](https://ubuntu.com/wsl/docs/stable/explanation/time-sync/)과 [Microsoft WSL 이슈](https://github.com/microsoft/WSL/issues/11790)를 참고했다. 공유 WSL/host 시각을 변경하지 않았다. 기록된 수신 시각이 실제 과거가 될 때까지 최대61초만 기다리며 차이가60초를 넘으면 실패한다. 원본 이벤트·수신 시각을 조작하거나 탐지 창을 변경하지 않았다.

기존 normalizer는 한 cycle에 제한된 수신 구간을 전진시키므로, 설치/다운로드가 오래 걸리면 첫 cycle만으로 실제 새 입력에 도달하지 않는다. 시험 도구는 같은 영속 상태로 반복해 실제 수신 시각까지 따라잡고 정규화 입력 수를 먼저 확인한다. 경보0건을 무조건 통과시키지 않는다.

정리 작업은 Windows 명령줄 길이 제한에 걸린 첫 시작 시도가 있어, 작업 인수 데이터를 별도 전달하고 확인된 Scheduled Task API로 등록했다. [Microsoft 명령줄 제한](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation)을 참고했다. 시험 환경 복원은 별도의 단일 작업으로 실행하고 결과를 받아 확인했다.

## 기본 정책을 지키는 Windows 배포: 다음 우선 작업

`INSTALL-DEVICE-UX-01-WINDOWS-POLICY`가 남아 있다. [Microsoft 실행 정책](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)에서 Restricted는 명령은 허용하지만 스크립트 파일은 막는다. 현재 NSIS recipe는 ps1 wrapper라 기본 정책에서 제품 설치를 완료하지 못한다.

다음 구현은 서명된 EXE/MSI의 네이티브 설치·관리 경계를 만들어 사용자가 매번 PowerShell 정책을 바꾸지 않게 해야 한다. 실행 파일·내장 파일의 서명/hash 검증, 시스템 서비스/작업 등록, 보호된 keystore와 복구 상태, 원격 등록·수신 확인·삭제 의미를 유지한다. 서명만 추가하거나 Bypass/Unrestricted/스크립트 내용 실행으로 정책 문제를 숨기지 않는다. 일반 Windows UAC 관리자 요청과 PowerShell 실행 정책 변경은 별개이며, 기업 관리 배포 권한도 따로 설계한다. 구현 후 새 기본 정책 VM에서 제품 진입점 자체를 다시 인수해야 한다.

## 정리·보존·한계

- 기존 Ubuntu26.04의 지원 검사를 완화하거나 배포판을 교체하지 않았다. 새 CloudSOC-Lab-2404-20261025의 등록명과 Windows 저장 경로가 이번 생성분임을 확인한 뒤 그 배포판만 등록 해제했다.
- Windows 수집기 시험 디렉터리·등록 ZIP·publisher 일회성 파일·keystore/큐·native 작업을 제거했다. 사용자가 준비한 새 SSH 공개키와 시험 방화벽 규칙도 제거했다. 준비 전 OpenSSH.Server 기능이 NotPresent였으므로 이번 추가분을 제거해 NotPresent로 복원했다. 정리 작업은 self-unregister했고 restart_needed=false였다. 기본 실행 정책은 Restricted다. 재부팅하지 않았다.
- SSH 기능이 보존할 수 있는 ProgramData/ssh의 일반 호스트 설정/호스트키 파일은 생성 전 존재 여부를 완전히 확인하지 않았으므로 무조건 지우지 않았다. 시험용 관리자 authorized key는 제거했고 SSH 기능·접속은 닫혔다. 해당 OS 호스트키를 수집/발급 원장의 장치 키로 사용하거나 외부로 내보내지 않았다.
- 새 ES 컨테이너·전용 TLS 볼륨과 임시 HTTP/HTTPS 서버를 정리했다. host의 새 SSH 개인키·CA 개인키·인증서·비밀번호 파일·Portal DB/전달 복호화 키를 제거했다. 기존 Docker/공식 이미지 캐시와 VM/기존 WSL은 보존했다.
- 비밀값을 제거한 결과는 Git 제외 `state/install-device-ux/os-lab-20261025/{wsl-result.json,windows-result.json,vm-access-cleanup.json,site-regression.xml}` 및 native 로그에 남긴다. 실제 시험 비밀값이나 저장소를 Git에 넣지 않는다.
- 다중 조직·모든 규칙·Windows 제품 설치/서비스 제거·서명 EXE/MSI·배포 서버 연결·전체 대시보드 시각·연속 운영·HA/백업 복구·재부팅은 이 결과로 완료하지 않는다. OS-LAB 부모와 RELEASE는 Windows 제품 설치 문제가 해결될 때까지 미체크다.

재실행 도구는 `tests/manual/device_os_live.py`, `tests/manual/device_windows_live.py`다. 자동 pytest 수집이나 생산용 설치 도구가 아니며 명시적 `--run`이 필요하다. Windows 도구는 별도로 준비한 새 SSH 개인키/검증된 known_hosts와 공개 연결 metadata(guest-ready.json)가 있는 보호된 state 디렉터리가 필요하다. 이 파일은 의도적으로 정리됐으므로 다음 시험에서 새로 준비한다. 특정 시험 네트워크·VM·폐기용 배포판 전용 도구이며 주소/환경을 확인하지 않고 다른 장치에 적용하지 않는다.

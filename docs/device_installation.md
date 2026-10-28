# 장치 설치와 배포

새 관리 장치의 설치·패키징·OS 시험 안내다. 상태 기준은 `main b737b23`(2026-10-27, PR21 병합e804569·기능 head5bcef7f)이며 이전 ac64198 시험 이력도 유지한다. 기존 수동 패키지는 [에이전트 운영](agent_management.md), 기존 Windows의 Discovery 갱신/Repair는 [Windows 운영](windows_agents.md)을 따른다. 전체 검증 상태는 [프로젝트 상태](project_status.md)에 모았다.

## 장치 설치

장치 상세에서는 운영체제·수집 목적을 표시명으로 보여주고, 최초 수신 확인과 최근 일반 로그 수신을 구분한다. 등록이 끝난 장치의 설치 안내는 기본으로 접힌다. 수집 키와 유효기간 연장, 서버 접근 차단/사용 종료는 별도 영역이며 폐기·만료 등 조치 이유를 표시한다. 빈 알림은 표시하지 않고 실제 오류는 유지한다. 2026-10-26 직접 영향 화면9검사와 시험 포털 HTML/CSS 제공을 확인했으며 새 배치의 자동 브라우저 시각 검사는 미수행이다. 기존 만료/폐기 및 권한 계약을 변경한 작업이 아니다.


1. Portal의 `devices.html`에서 이름·조직·OS·수집 목적과 실제 로그 경로를 지정한다.
2. 설치 정보를 준비하고 ZIP을 다운로드한다. 같은 생성 요청은 같은 장치에 연결되며, 재다운로드는 같은 미사용·미만료 등록 정보를 쓴다.
3. ZIP 전체를 새 폴더에 푼다. Linux에서는 다음 명령을, Windows에서는 `Start.cmd`를 실행한다. 일반 관리자 승인은 필요하며 실행 정책을 변경하지 않는다.

```bash
sudo sh soc-agent install
sudo sh soc-agent status
sudo sh soc-agent stop
sudo sh soc-agent start
sudo sh soc-agent uninstall
sh soc-agent --help
```

Linux 관리 도구는 `/var/lib/cloud-soc-bundles/<device-id>`에 남아 다운로드 원본을 지운 후에도 사용할 수 있다. DEB 전역 진입점을 설치한 경우 `sudo soc-agent status`처럼 실행한다. 여러 장치 도구가 있으면 전역 진입점의 `--device <device-id>`로 선택한다. 네트워크 수집은 실제 NIC 선택이 필요하다.

Windows의 새 관리 경로는 `Start.cmd → cloud-soc-agent-setup.exe`다. x64 Windows10 이상과 .NET Framework4.8이 필요하다. 시스템·웹 로그를 지원하며 **새 native 설치기의 Packetbeat/Npcap은 미지원**이다. network=true는 생성/등록 준비 전에 거부한다. 기존 고급 패키지의 네트워크 수집은 별도다.

설치기는 패키지/등록 바인딩, OS·권한·기존 설치·디스크·TLS/폐기를 검사하고 수집 키를 keystore의 표준 입력으로 전달한다. 키를 복사하거나 명령 인수에 넣을 필요가 없다. 실제 수집기 UUID와 `installation_probe`의 중앙 수신을 확인해야 receipt가 완료된다. receipt는 최초 전송 증명이며 일반 로그·정규화·경보 성공은 [별도로 확인](agent_management.md#received-activity)한다.

## 등록 상태와 복구 경계

`packages.sqlite3`의 managed_devices/device_operations/device_transfers/device_audit가 장치 신원, 요청 fingerprint/version, 설치 전달 정보, 감사를 저장한다. actor·요청 ID·내용이 다른 재사용은 충돌이다. 원격 발급 후 로컬 저장 실패는 uncertain으로 남기며 결정적인 enrollment ID로 추적한다.

미사용 등록 정보의 만료/분실은 명시적 갱신 대상이다. 이미 키를 전달한 issued/complete 세션을 새 등록으로 덮어쓰지 않는다. 단기 전달만 Fernet으로 암호화하며 `device-transfer.key`는0600·백업 제외다. 키 분실/복호화 실패 후에는 원격 폐기와 명시적 갱신이 필요하다. 장기 수집 키 재조회 금고가 아니다.

Linux는 보호된 같은 설치의 확인된 실패에만 재등록한다. 새 Windows EXE는 stable attempt/token/session을 ACL·DPAPI LocalMachine 봉투에 저장해 같은 세션으로 일부 중단 단계를 재개한다. reserved/exchanging/session_saved/prepared/starting/awaiting_receipt는 지원하지만 초기 preparing·파일/manifest 불일치·불명확한 외부 성공은 관리자 검토로 남긴다. 모든 전원 손실/복원 지점의 자동 재개를 보장하지 않는다.

기존 정상 설치의 키 자동 교체, 기존 장치 신원 인수, 보존 큐 복원, 일반 바이너리 업그레이드는 별도 후속이다. 자료 삭제 후 **새 장치로 설치**하는 경로는 아래 절차를 따른다. 기존 Windows Repair/Resume와 확인된 실패 설치의 새 토큰 재등록은 별도 기능이다.

## 로컬 제거와 서버 접근 차단

로컬 stop/start/uninstall은 소유 기록·고정 경로·ACL·해시·링크를 확인한 해당 설치만 다룬다. 원본 웹/OS 로그와 중앙 로그·경보는 삭제하지 않는다. 로컬 제거와 Portal 장치 종료의 키 폐기는 별개다. 원격 셸/원격 자동 uninstall은 제공하지 않는다.

| 선택 | Linux manager | Windows native |
| --- | --- | --- |
| 기본 제거 | 서비스 제거, 큐/설정을 보호된 retired 디렉터리에 보존 | service/task 제거, 전체 collector tree·keystore·큐 보존 |
| 수집기 자료 삭제 | 선택2와 DELETE 확인 후 소유 수집기 디렉터리 삭제 | `--uninstall --purge`로 소유 수집기 트리 삭제 |
| 남는 자료 | 관리 도구·완료/제거 기록 | ProgramData/Cloud-SOC-Native의 관리 EXE·상태/감사 |

Windows 관리 EXE의 명령은 `--install --bundle <folder>`, `--status`, `--start`, `--stop`, `--uninstall`, `--uninstall --purge`, `--help`다. GUI 제거에서는 자료 보존을 기본으로 선택하고 자료까지 삭제할 때 추가 확인을 받는다. `--refresh`는 SYSTEM task 내부 동작이고 `--quiet`는 메시지 창 대신 CLI 출력을 사용한다. 보존 제거 후 purge 재호출과 일부 제거 재시도는 지원하지만 manager self-uninstall/in-place upgrade는 제공하지 않는다. 시험 controller가 manager까지 정리한 결과를 제품 완전 삭제 기능으로 해석하지 않는다.

Windows에서 설치 기록을 찾지 못하면 상태 변경을 중단하고 기존 수집기와 자료를 확인하도록 안내한다. 기록이 없다는 이유만으로 수집기 자료를 삭제하거나 새 설치가 안전하다고 판단하지 않는다.

서버 장치 종료는 해당 패키지·조직·소유자 범위의 키를 폐기하고 원격 재조회까지 확인한다. 실패는 revocation_pending/uncertain으로 남으며 같은 요청을 재시도한다. 이력 영구 삭제/자동 보관 만료는 제공하지 않는다. 종료 이력도 장치/패키지200개 한도에 포함된다.

### 자료 삭제 후 새 설치

같은 PC에서 새 장치로 설치할 때만 사용하는 절차다. 이전 장치 신원·키·큐·읽기 위치를 복원하지 않는다.

1. 기존 관리 도구의 제거에서 **수집기 자료까지 삭제**를 선택한다. 보존 제거만 한 경우에는 기존 도구의 제거를 다시 실행해 자료 삭제를 명시적으로 선택한다. Windows CLI는 `--uninstall --purge`, Linux는 제거 메뉴의 DELETE 확인을 사용한다.
2. 포털에서 기존 장치의 접근 차단을 완료한다. 로컬 자료를 지운 사실은 서버 키 폐기 확인이 아니다.
3. 포털의 기존 장치 추가 기능으로 새 장치를 등록하고 새 설치 묶음을 받는다. 이전 설치 토큰·패키지·receipt를 재사용하지 않는다.
4. 새 묶음의 설치 프로그램을 실행한다. Windows에서는 다운로드한 새 EXE를 실행하며 이전 관리 폴더에서 설치를 실행하지 않는다.
5. 새 설치의 중앙 수신 확인과 일반 로그 수신을 따로 확인한다. 설치 확인은 경보 생성 또는 과거 자료의 전송 완료를 뜻하지 않는다.

Windows는 `purged`와 자료 삭제 의도, 보호된 manager 해시, 서비스/작업/프로세스·수집기 폴더 부재를 확인한다. 이전 관리 폴더는 같은 볼륨의 `ProgramData/Cloud-SOC-Native-History/<device-id>-<enrollment-id>`로 이동해 기록을 보존한다. 기존 이력·잔여 큐·미확정 삭제·lab/production 전환·같은 등록 재사용은 덮어쓰지 않는다. 이력 이동 후 새 설치가 중단되면 새 설치 상태의 기존 중단 처리 규칙을 따른다.

Linux는 명시적인 자료 삭제 완료 기록과 같은 장치/세션의 완료 receipt를 대조하고, 이전 완료 receipt만 해당 retired 폴더로 옮긴다. 보존 자료·미완료 삭제·수집기/서비스 파일이 남으면 차단한다. 보존 제거 후 자료 삭제는 기존 보존 트리의 소유권/파일 해시와 서비스·프로세스 중지를 확인한 뒤 수행한다. 새 복원 API·키 발급 방식은 추가하지 않는다.

큐·읽기 위치를 지우면 미전송 자료가 사라지고 디스크에 남은 과거 원본을 새로 읽을 수 있다. 기존 최초 수집 정책과 중복 처리 계약을 유지하며 재수집이나 중복 경보가 절대 없다고 보장하지 않는다. 중앙 원본·정규화·경보·감사 이력과 소유하지 않은 수집기/서비스는 삭제하지 않는다.

2026-10-26 INSTALL-DEVICE-UX-02-REINSTALL-BASIC은 작성100% 이후 코드 검사45건/14 subtests·C# 계약41항목·Linux root 파일 경계12건을 통과했다. 별도 Windows VM에서 제품 EXE의 보존 상태 덮어쓰기 차단→자료 삭제→새 장치 설치/새 receipt·일반 로그→정리를 실제 확인했다. 후속 INSTALL-DEVICE-UX-02-REINSTALL-WSL에서 새 Ubuntu24.04.5/systemd WSL의 제품 bootstrap/실제 Filebeat·서비스로 같은 삭제→새 등록 설치·새 receipt 및 정확한 새 요청 ID의 일반 수신을 확인했다. 양 OS의 이전 원본과 제거 이력 해시를 유지했고 Windows 정책은 Restricted 그대로다. GUI 직접 클릭/시각·운영 서명 릴리스·실제 DEB 패키지·모든 장애/일반 VM 재부팅 인수는 별도이며 작업 목록에서 구분한다.

## 서버 도우미

저장소 루트의 systemd Ubuntu에서 다음 진입점을 사용한다. 실제 설치/제거는 기존 도구의 자원·주소·포트·소유권 검사를 재사용한다.

```bash
sudo sh soc
sudo sh soc install
sudo sh soc status
sudo sh soc uninstall
sh soc --help
```

설치는 실습/사내망/클라우드, 접속 주소와 할당 IP, 수집 주소, 시간 동기화를 확인한다. 기존 `state/server`가 있으면 덮어쓰지 않고 [공통 복구/업그레이드](runtime_deployment.md)를 안내한다. 제거의 기본 선택은 데이터/CA 보존이고 완전 삭제는 DELETE 추가 확인이 필요하다. 공용 Docker 제거·global prune·Apache 삭제는 호출하지 않는다.10/27 새 WSL에서 메뉴를 통한12서비스 설치·상태·삭제 취소·보존 제거·동일 키/인증서/합성 원본 복구·purge/반복 제거를 확인했다.10/21 시험과 별도의 후속 인수이며 물리 VM/EC2·재부팅·실장치 경보 인수로 확대하지 않는다.

## Windows 보안 계약

EXE는 C#5/.NET4.8 x64 WinForms이며 실행 중 PowerShell·스크립트 호스트·컴파일러를 호출하지 않는다. UAC requireAdministrator를 사용하고 GPO/WDAC/AppLocker/SmartScreen/EDR 차단을 우회하지 않는다. Program Files/ProgramData 전용 경로는 SYSTEM/Administrators만 쓸 수 있다. UNC/reparse·ZIP traversal/중복/용량 초과·기존 수집기 충돌을 거부한다.

공식 Filebeat9.5.2 Windows ZIP의 고정 SHA512를 검사하며 다운로드의 redirect·크기·시간을 제한한다. Endpoint/Portal은 번들 CA·호스트 이름·serverAuth EKU·전체 체인/유효기간·온라인 폐기를 검사한다. native 전용 CertCreateCertificateChainEngine의 hExclusiveRoot 메모리 저장소를 쓰며 OS CA 저장소나 전역 캐시를 변경하지 않는다. offline/unknown/revoked를 허용하지 않는다. 기존 PS helper의 컴파일 경계는 유지한다.

키 교환 전 DPAPI 봉투를 저장하고 keystore stdin으로만 키를 전달한다. 성공 후 봉투는 삭제하되 다운로드한 등록 파일은 사용자가 정리한다. 설정/응답/키 원문을 진단에 남기지 않고 오류 코드·예외 종류·HRESULT만 보호된 diagnostic.json에 기록한다. Filebeat service의 정확한 ImagePath와 SYSTEM task의 action/principal, 설치 파일 해시를 관리/제거 전에 다시 확인한다. 로컬 관리자 침해 방어 또는 모든 단계의 원자성을 주장하지 않는다.

## 패키징과 Portal 배포

서버 요청 중 실행 파일을 빌드하지 않는다. Linux 공통 runtime은 허용된 정적 도구만 정렬·고정 timestamp로 묶고 장치별 package/CA/profile/registration과 분리한다. 원본 package SHA256, outer ZIP, runtime hash는 서로 다른 계약이다. 파일별 checksum만으로 미서명 다운로드의 출처를 보장하지 않는다.

Windows는 빌드 호스트의 Windows inbox Framework64 csc와 운영자가 준비한 Windows SDK SignTool을 사용한다. **이전 NSIS/PowerShell wrapper recipe는 native EXE로 대체됐다.** Ubuntu는 공식 checksum을 확인한 nFPM2.48.0을 사용한다. build.py는 도구를 자동 다운로드/실행하지 않는다.

```text
python deploy/agents/packaging/build.py windows --tool C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe --output <new-release-directory> --signtool <Windows-SDK-signtool.exe> --certificate <public-certificate-thumbprint>
python deploy/agents/packaging/build.py ubuntu --tool <verified-nfpm> --output <new-output-directory>
```

production은 Authenticode SHA256+timestamp와 SignTool verify를 통과해야 release.json을 쓴다. 인증서 공개 thumbprint만 인수로 받으며 개인키/비밀번호를 받지 않는다. 실행 시 WinVerifyTrust로 EXE 서명/폐기를 확인한다. 인증서 발급/보호/교체·조직 정책 승인은 별도 운영 조건이다.

Portal은 `deploy/server/windows-native.compose.yaml`을 명시 적용한다. SOC_WINDOWS_INSTALLER_DIR는 EXE/release.json의 read-only 폴더, SOC_WINDOWS_INSTALLER_SHA256은 metadata와 별도로 고정한 EXE SHA256이다. 소스 fingerprint·mode·서명 metadata·파일 해시/크기/형식이 다르면503이며 스크립트 fallback이 없다. CRLF/LF 차이만 정규화한다.

격리 시험용 `--lab`은 별도 unsigned 컴파일이며 실행 때도 `--lab`을 요구한다. SOC_WINDOWS_INSTALLER_ALLOW_LAB 기본값은 false이고 lab은 private/loopback IPv4에 한정한다. 운영에 연결하지 않는다. Ubuntu DEB는 manager 전역 진입점을 배포하며 prerm은 소유 수집기 unit이 남아 있으면 manager 제거를 거부한다. package upgrade를 제거로 처리하지 않는다.

추가 NuGet/NSIS runtime은 없다. .NET은 OS API이며 Filebeat/Packetbeat의 기존 배포 라이선스를 바꾸지 않는다. [Elastic 라이선스](https://www.elastic.co/legal/elastic-license), [nFPM MIT](https://github.com/goreleaser/nfpm/blob/main/LICENSE.md), [Microsoft 실행 정책](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies), [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)를 참고한다.

## 검증 이력

날짜가 같은 초기 실패와 후속 성공은 아래 순서로 읽는다. 코드 검사·실제 OS 설치·운영 배포를 합쳐 완료 처리하지 않는다.

| 날짜/범위 | 기록된 결과 | 범위 밖 |
| --- | --- | --- |
|10/23 코드/loopback | Python88항목·기존13 subtests·후속 경계3, UI26항목, 로컬 도구/백업/PS 검사. 합성 issuer로 생성→다운로드→등록→proof→폐기/이력·TLS 거부 | 실제 ES/OS 설치가 아님 |
|10/23 패키징 | nFPM checksum·DEB 빌드/내용/prerm 확인. NSIS portable 다운로드는 HTTP 오류로 중단 | 실제 DEB 설치/제거·당시 EXE 서명 미수행. NSIS는 이후 대체 |
|10/23 실제 TLS ES/Beat | 명시적 device_management_live.py의8항목: 같은 장치/발급 재시도, proof와 일반 로그 분리, 키401/권한403·종료 이력·원본 보존, cleanup=true | OS bootstrap·경보/서비스 검증을 대신하지 않음 |
|10/25 Ubuntu24.04.5 WSL/systemd | 제품 bootstrap/manager·Filebeat9.5.2·TLS/CRL·서비스·receipt, 합성 WAF 정규화/경보/근거, stop/start·다운로드 삭제 후 status·보존 uninstall/원격 폐기 | 실제 DEB 패키지 설치/제거·일반 VM 부팅·실제 웹 공격·장기 무손실 |
|10/25 Windows 초기 시험 | 기본 Restricted가 PS wrapper를 차단. 정책은 유지. 별도 native Filebeat로 합성 경보/근거 확인 | 이 단계 자체는 제품 설치 성공이 아님 |
|10/25 Windows 후속 native | build19045/.NET4.8/Restricted에서 제품 EXE가 ACL·DPAPI·keystore·service·SYSTEM COM task·receipt 구성. stop/start·합성 경보·보존 uninstall/purge·키 폐기 통과 | unsigned lab, 실제 GUI 클릭·운영 서명·native 재부팅/모든 중단 지점·network 미인수 |
|10/25 native TLS | 동일 제품 소스로 정상 CA 통과, 다른 CA·이름 불일치·폐기·CRL503·만료 거부6경계 | OS CA 설치/폐기 검증 완화 없음 |
|10/26 Git/CI | PR20 main 병합17a32c4, 최종 코드50ebce9 Actions40204762899 Ubuntu/Windows 성공, 기록main ac64198 | 운영 서버/장치 자동 배포 아님 |
|10/26 최소 재설치 | 작성100% 후 필수 코드 검사·Linux root 임시 파일 검사, Windows 실제 EXE 자료 삭제/새 장치 설치·새 receipt/일반 로그·이전 원본/이력 보존·정리 | 이전 큐/신원 복원·Linux 실제 재설치·GUI 직접 클릭·운영 서명·새 경보/재부팅 검사 아님 |
|10/26 후속 WSL 재설치 | 새 Ubuntu24.04.5/systemd의 실제 bootstrap/Filebeat·TLS ES/Portal에서 첫 설치/수신→보존 제거/덮어쓰기 차단→명시 자료 삭제/이전 장치 종료→새 장치·수집기 UUID/새 receipt·정확한 새 일반 요청 수신→기존 원본/제거 이력 해시 유지→자료 삭제·장치 종료·시험 배포판/서버/비밀값 정리 | 보존 큐·기존 신원 복원·실제 DEB 패키지·일반 VM 부팅·새 공격/경보/재부팅 인수 아님 |
|10/26 수동 키 연장 | 실제 WSL/Filebeat의 같은 키·수집기 ID/프로세스·설정/keystore/receipt·권한을 유지해 연장 전후 새 로그 수신. 사용자 클릭 성공과 원격/로컬 만료 대조·정리 | 새 비밀값 교체/자동 회전·기존 만료 시각 경과·Windows 추가 인수·운영 배포와 별도 |
|10/27 Ubuntu24.04.2 VMware DEB | 제품1.0.0 실제 dpkg 설치·소유권/모드·전역 도움말·제거, 동일 소스의 합성 낮은 버전→제품 교체, 비활성 수집기 unit/합성 자료 잔존 시 제거 거부·명시 정리6단계 통과. 사후 패키지/고정 경로8개 부재·시험 staging 정리 확인 | 실행 중 수집기·과거 출시 버전 호환·새 등록/실제 수신 시험 아님. 기존 중앙/Docker/키/로그 변경 없음 |
|10/27 서버 메뉴 WSL | 새 Ubuntu24.04.5/systemd·독립 Docker의12서비스 설치·HTTPS·keep/동일 자료 복구·purge/반복 제거·작업자 init·시험 자원 정리 | 물리 Ubuntu/EC2·재부팅·실장치 수신/경보·전체 분석 drain/HA 인수는 아님 |
|10/27 PR21/CI | 종료 시간 반올림 수정5bcef7f의 Actions40424825929 양 OS 성공·main 병합e804569·기록b737b23 | WSL 보고서의 재실행이나 운영 배포를 뜻하지 않음 |

양 OS의 합성 WAF 시험은 SQLi2+비SQLi3→정규화5/경보0, SQLi3번째→정규화6/WEB-SITE-WAF-001 경보1, 재분석 기존1/신규0이다. 근거3건의 normalized/raw index/id·event_hash·조직/host/site/package와 privacy canary 미전송을 확인했다. 설치 probe는 분석용 양성 입력에 세지 않았다. 파일에 기록한 합성 입력이며10/19~20의 실제 HTTP/SQLi 시험과 별도다.

실제 시험에서 발견한 오류는 다음과 같이 수정했다. 과거 실패를 삭제하지 않고 후속 결과로 범위를 갱신했다.

- 동적 입력의 `${path.config}/site-privacy.js`는 reload hash 오류를 내 상대 경로 `site-privacy.js`로 수정했다. 양 OS 실수집과 영향16검사를 통과했고 기존 운영 프로필을 자동 재작성하지 않았다.
- Windows .NET 폐기 설정 API 차이, task 부재 HRESULT의 FileNotFoundException, ExtraStore의 OfflineRevocation을 수정했다. 새 native 전용 exclusive chain engine으로 실제 CRL/오류0을 확인했다. 영향 고유40검사와 최종 TLS 영향24 재검사, production/lab 컴파일·계약 harness를 통과했다. production 컴파일과 실제 운영 서명은 다르다.
- ACL 포함 독점 디렉터리 생성, 같은 ZIP snapshot의 해시/파싱, purge rename 전후 복구 경계를 보완했다. PowerShell/WSL 인수·stdin 대기는 시험 도구 전달을 수정했고 제품 정책을 완화하지 않았다. WSL 약1.8초 시각 차이는 원본/시스템 시각을 바꾸지 않고 bounded 대기로 처리했다.
- CI 독립 Python 환경, DOM 유효성 shim, certifi/filelock 보안 pin을 수정한 뒤 최종 양 OS job이 통과했다. 검사 우회·취약점 ignore는 하지 않았다.

명시 실행 전용 도구는 tests/manual의 device_management_live.py, device_os_live.py, device_windows_live.py, device_windows_native_live.py, windows_native_tls_live.py다. pytest가 자동으로 실제 VM을 수정하지 않으며 보호된 접속 metadata/승인된 새 환경이 필요하다.

시험 후 폐기용 WSL·Windows 수집기/service/task/root와 시험 manager, 키/방화벽/임시 task·컨테이너/전용 볼륨·개인키/Portal DB/접속 창구를 정리했다. Windows OpenSSH.Server는 원래 NotPresent, 정책은 Restricted, restart_needed=false로 복원했다. 존재 여부가 불확실한 일반 SSH host key/config와 기존 Docker/공식 이미지 캐시는 보존했고 재부팅하지 않았다. 비밀 없는 결과는 Git 제외 state/install-device-ux/{live-lab-attempt6.json,os-lab-20261025,windows-native-20261025}에 기록됐으며 일부 원본은 현재 체크아웃에 없다.

## 남은 범위

기능 구현과 추가 인수를 구분한다. 남은 릴리스 인수는 운영 인증서로 서명한 Windows EXE 공급·Portal 연결/조직 정책, 실제 GUI·OS/정책·중단 경계다. DEB 패키지 자체의 실제 설치·동일 소스 합성 낮은 버전 교체·제거 보호/정리는10/27 Ubuntu VM에서 확인했다. 과거 출시 버전/실행 중 수집기의 업그레이드 호환까지 확인한 것은 아니다. sign/verify·Portal release 설정은 구현돼 있다. 서버 메뉴의 WSL 실제 설치·복구·제거와 bootstrap/native의 설치·재설치도 완료됐으므로 이 항목들을 다시 미검증으로 묶지 않는다.

INSTALL-DEVICE-UX-02-RECOVERY에 남은 것은 보존 큐·읽기 위치·기존 신원 복원과 키 조정이다. 자료 삭제 후 새 등록 재설치는 하위 REINSTALL-BASIC/WSL로 완료했다. INSTALL-DEVICE-UX-03-LIFECYCLE의 수동 유효기간 연장도 KEY-EXTEND/WSL/CLICK-LAB으로 완료했으며, 새 비밀값 교체/자동 회전·감사 보관/한도 회수·일괄 배포/승인/업데이트는 후속 범위다. manager 자체 제거는 감사/상태 보존 정책을 먼저 선택해야 한다. control channel·RFC8628·공인 인증서 갱신·TUF 업데이트는 이번 범위에 포함하지 않았으며 새 실행 승인으로 해석하지 않는다.

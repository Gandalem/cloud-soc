# Windows 네이티브 설치 — INSTALL-DEVICE-UX-01-WINDOWS-NATIVE

2026-10-25. 실제 작업 체크아웃은 cloud-soc-main, 브랜치는 codex/install-device-experience다. 원본 D:\cloud-soc, 상용화 실험 체크아웃, 기존 VM/운영 서비스는 변경하지 않는다. 기존 WSL script processor 경로 수정과 OS 검증 기록을 보존한다.

## 실행 경계

새 관리 장치의 Windows 다운로드는 `Start.cmd → cloud-soc-agent-setup.exe`다. EXE는 C# 5/.NET Framework 4.8, x64, WinForms로 빌드한다. 제품 실행 중 PowerShell/스크립트 호스트/컴파일러를 실행하지 않는다. manifest의 requireAdministrator에 따라 UAC 관리자 승인은 필요하다. Restricted를 바꾸지 않으며 GPO, WDAC/AppLocker, SmartScreen, EDR의 EXE 차단을 해제하지 않는다. MSI도 반드시 동시에 만들 필요는 없으므로 이번 산출물은 EXE다.

시스템·웹 로그와 기존 네이티브 Discovery를 사용한다. 네트워크 packetbeat/Npcap 설치는 포함하지 않는다. 요청한 network=true는 장치 생성 및 등록 정보 준비 전에 명시적으로 거부한다. 기존 고급 unmanaged Windows 스크립트 패키지 API와 Linux 패키지는 유지한다. 지원 범위 축소를 조용히 적용하거나 고급 설치기로 자동 우회하지 않는다.

구성 요소:

- `deploy/agents/native`: WinForms/명령 옵션, 입력·등록 계약, ACL/DPAPI/서명, SCM, Task Scheduler COM, 설치/관리.
- 기존 `enrollment-http.cs`, `tls-probe.cs`, `discovery-native.cs`를 같은 EXE에 컴파일한다. privacy.js/site-privacy.js/security-catalog.json은 내장 리소스다.
- `windows_native.py`: 별도 서버 설정으로 고정한 EXE SHA-256, 소스 fingerprint, 모드·서명 메타데이터, bounded regular file을 확인한다. 요청 중 빌드하지 않는다. 누락/변조/소스 불일치는 503, 스크립트 fallback은 없다.
- 다운로드는 발급 계약의 정확한 원본 `package.zip`과 짧은 등록 token, 공통 EXE를 포함한다. 네이티브 설치기는 기존 패키지 해시와 서버 enroll의 확인을 결합한다. 원본 archive 안의 기존 스크립트는 추출·실행하지 않는다. 로컬에서 해시만 바꾸어도 서버의 원본 package hash와 일치하지 않아 키를 받을 수 없다.

## 설치·인증·실패

실행 전에 OS x64/Windows10 이상/.NET4.8, 관리자, 기존 서비스/프로세스/대표 collector 경로, task·설치 상태, 원본 archive/등록 바인딩, 범위·디스크 여유를 확인한다. UNC/reparse 경로와 ZIP traversal/중복 이름/용량 초과를 거부한다. Program Files·ProgramData의 새 전용 경로는 SYSTEM/Administrators만 쓰기 가능하게 한다. 사용자 로그 경로와 OS 신뢰 저장소는 변경하지 않는다.

Filebeat9.5.2 공식 Windows x64 ZIP의 기존 SHA512 고정을 유지한다. HTTPS 신뢰·호스트 이름·폐기 검증, redirect 거부, 수신 크기·시간 제한, 추출 경계와 SHA512를 확인한 후에만 사용한다. 이미 수신된 합성 로그를 재작성하지 않는다. 새 다운로드의 .ps1 파일은 실행하지 않는다.

키 교환 전 stable attempt/token을 ACL 보호 상태 폴더의 DPAPI LocalMachine 봉투에 원자 저장한다. 같은 요청의 TLS/409/503 재시도는 같은 attempt를 쓴다. 받은 session/key도 봉투에 저장하여 프로세스 중단 후 동일 등록 세션으로 재개한다. 평문 수집 키는 Filebeat keystore의 stdin으로만 전달하며 argv·일반 상태·오류 출력에 넣지 않는다. 관리 메모리의 문자열·keystore는 관리자/호스트 침해를 방어하는 암호 저장소가 아니다. 성공 후 봉투를 삭제한다. 사용자가 받은 등록 파일 사본은 별도로 삭제해야 한다.

Endpoint/Portal의 CA·호스트 이름·온라인 폐기 검증을 유지한다. 새 EXE의 `NATIVE_INSTALLER` 컴파일 경로만 Windows CertCreateCertificateChainEngine의 hExclusiveRoot 메모리 저장소를 사용한다. 번들 CA만 신뢰 루트로 삼고 서버 중간 인증서는 별도 보조 저장소에만 추가한다. serverAuth EKU, 전체 체인 오류0, 정확한 루트 bytes, 루트를 포함한 유효 기간을 확인한다. 호스트 이름 오류는 SslStream/HttpWebRequest에서 그대로 거부한다. 온라인 폐기는 루트를 제외한 체인에 적용하고 누적 URL timeout5초를 지정한다. offline/unknown/revoked를 허용하거나 OS에 CA를 설치하지 않는다. 기존 PS helper 컴파일에는 이 심볼이 없어 기존 ES 경로를 보존한다. `allowUnavailable=false`이며 다른 엔진·관리자 계정·비보안 연결로 우회하지 않는다. 상세 응답/구성/비밀값 대신 오류 코드·HRESULT만 CLI와 보호된 diagnostic.json에 남긴다.

SCM으로 LocalSystem Filebeat 서비스와 자동 시작을 등록한다. COM으로 SYSTEM의 제한된 Task Scheduler 항목을 만들고 같은 EXE `--refresh`만 실행한다. 시작/중지/삭제 전에 정확한 service ImagePath/task action·principal 및 보호된 설치 파일 해시를 확인한다. 기존 이름의 다른 서비스/task는 갱신하지 않는다.

설치 완료는 service/task 구성만으로 판단하지 않는다. 실제 agent UUID와 installation_probe 문서로 기존 Portal receipt API의 `id`, `verified=true`, `state=complete`를 확인한다. 기존 최대180초 수신 확인 계약을 유지한다. 일반 로그/정규화/경보까지 완료했다는 의미는 아니다. 실패 시 소유 서비스 중지를 시도하고 같은 attempt의 abort를 호출한다. 폐기를 확인하지 못하면 revocation_unconfirmed를 기록하고 성공으로 표시하지 않는다. 큐/설정/불확정 상태는 보존한다.

파일 flush+replace와 단계 저장을 사용하지만 파일과 SCM/원격 작업 전체를 원자화할 수는 없다. 설치 준비 초기(`preparing`) 중단, config 기록과 상태 manifest 사이의 중단, 지원하지 않는 기존 설치의 복구는 자동 채택하지 않고 관리자 검토로 남긴다. 외부 성공 후 로컬 commit 실패에서 새로운 token/key를 자동 발급하지 않는다. receipt 성공 뒤 commit 실패는 봉투가 남은 같은 세션으로 확인을 다시 수행한다. 실제 전원 손실 내구성, 디스크 복원, 폐기 키 부활 방지는 이번 코드 검사로 보장하지 않는다.

## 관리·삭제

GUI: 설치, 상태 확인, 수집 시작, 수집 중지, 제거, 도움말. 명령: `--install --bundle <folder>`, `--status`, `--start`, `--stop`, `--uninstall`, `--uninstall --purge`, `--help`. 진단 없이 시험하는 `--quiet`도 지원한다. `--refresh`는 보호된 SYSTEM task의 내부 동작이다. CLI secret 인수는 받지 않는다.

기본 제거는 task와 service를 삭제하고 **전체 collector tree/keystore/큐를 보호된 경로에 보존**한다. purge를 명시하면 task/service 제거 확인 후 고정된 전용 경로를 보호된 retired 경로로 옮겨 삭제한다. 경로/ACL/reparse를 확인하며 원본 로그를 삭제하지 않는다. task/service 삭제나 로컬 단계 commit 실패를 완료로 숨기지 않는다. purge 재시도는 저장한 intent와 일치해야 한다. 동일 장치의 로컬 제거 재요청은 이미 완료된 결과를 표시한다.

작은 네이티브 관리 EXE와 비밀값 없는 상태 이력은 ProgramData\Cloud-SOC-Native에 남는다. 이번 작업은 자체 실행 파일까지 완전히 지우는 manager self-uninstall이나 in-place upgrade가 아니다. 보존된 설치를 새 설치로 자동 재사용하지 않는다. 로컬 제거 후 원격 키는 포털의 장치 종료로 폐기한다. 제거 완료가 원격 폐기 확인을 의미하지 않는다. 완전한 manager 제거·보존 큐 재설치/복구 UI는 후속 인수 조건이다.

## 빌드·활성화

Python 프로젝트 환경에서 `PYTHONPATH=src`를 설정하고 다음 recipe를 사용한다. 장치에서 실행할 명령이 아니다. Windows 자체 .NET Framework64 csc와 운영자가 준비한 Windows SDK SignTool을 사용한다. 새 NSIS 의존성과 PowerShell wrapper recipe는 제거했다. 기존 Ubuntu nFPM2.48.0 경로는 유지한다.

```text
python deploy/agents/packaging/build.py windows --tool C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe --output <new-release-directory> --signtool <Windows-SDK-signtool.exe> --certificate <public-certificate-thumbprint>
```

서명 키 원문/비밀번호를 인수로 받지 않는다. Authenticode SHA256 서명+timestamp 후 SignTool verify를 통과해야 production manifest를 쓴다. 장치에서도 WinVerifyTrust로 자체 EXE 신뢰/서명·폐기를 검사한다. 인증서 발급/보호/교체, CI 승인, 재현 가능한 빌드, 조직의 WDAC/EDR 배포 승인은 후속 release 운영 조건이다. 여기서 실제 운영 인증서를 발급하거나 서명했다고 주장하지 않는다.

새 격리 시험에서만 `--lab` 빌드 옵션을 사용한다. 별도 컴파일된 unsigned artifact이며 실행 때도 `--lab`을 명시해야 한다. Endpoint/Portal은 private/loopback IPv4만 허용한다. production 컴파일에는 lab 우회가 없다. lab 빌드는 기존 보안 정책 예외나 운영 배포 완료가 아니다.

Portal 운영 설정:

- SOC_WINDOWS_INSTALLER_DIR: 공통 EXE와 release.json만 있는 검토된 read-only release 폴더.
- SOC_WINDOWS_INSTALLER_SHA256: release.json과 별도로 배포 설정에 고정한 EXE SHA256. 폴더의 metadata만 변조해 새 EXE를 허용하지 않는다.
- SOC_WINDOWS_INSTALLER_ALLOW_LAB=1: 새 격리 시험 전용. 기본 false.

`deploy/server/windows-native.compose.yaml`은 명시적 활성화용 override다. 기존 서버 설정이나 running container에는 적용하지 않았다. native 소스 fingerprint는 Git CRLF/LF 차이만 정규화한다. 버전이 다른 서버 소스와 release를 조합하면 fail closed다. 원본 package archive 해시의 의미는 바꾸지 않는다.

## 공식 근거·라이선스

- [PowerShell 실행 정책](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies): Restricted의 script 차단을 정책 변경으로 우회하지 않고 네이티브 실행 경계로 대체한다.
- [Service functions](https://learn.microsoft.com/en-us/windows/win32/services/service-functions): 서비스 등록/제어/삭제.
- [TaskFolder.RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition): TASK_CREATE만 사용하고 보호된 task ACL을 지정한다.
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [WINTRUST_DATA](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data): 성공값0과 Authenticode trust/폐기 검증.
- [CERT_CHAIN_ENGINE_CONFIG](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_engine_config), [CertGetCertificateChain](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain): 애플리케이션 전용 trust anchors와 온라인 폐기 검사. 기존 전역 신뢰 설정을 바꾸지 않는다.
- [ProtectedData](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata), [install .NET Framework](https://learn.microsoft.com/en-us/dotnet/framework/install/on-windows-and-server): OS에 이미 있는 .NET4.8 API를 사용한다. .NET/Windows SDK를 새 OSS 라이선스라고 표시하거나 redistributable을 묶지 않는다. 추가 NuGet/NSIS runtime 의존성은 없다.
- [Filebeat 설치](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-installation-configuration), [Elastic 라이선스](https://www.elastic.co/legal/elastic-license): 기존 기본 배포판9.5.2를 별도 공식 다운로드하고 기존 notice/상업 배포 검토를 유지한다. EXE 전환이 Elastic 배포판을 Apache로 바꾸거나 임의 재판매 권한을 부여하지 않는다.

## 필수 마감 검사와 미확인 범위

작성100% 이후 한 번 집중하여 native production/lab 컴파일 경계, 실행 가능한 계약 harness, Portal 등록/다운로드·키·조직 격리와 기존 Linux 회귀를 확인한다. unsigned lab build 통과를 signed production release나 실제 Windows 설치로 간주하지 않는다. 실제 Windows VM의 기본 Restricted에서 설치→receipt→일반 합성 로그→경보→stop/start→보존 제거/purge, 중단·재시도, 잘못된 CA/CRL과 ACL 차단은 별도 실제 인수다. 재부팅과 운영 배포는 실행하지 않는다.

### 실제 결과(2026-10-25)

- 작성100% 이후 직접 영향 고유40항목(네이티브 계약/장치 관리/등록/TLS24, 사이트16)을 통과했다. 마지막 native TLS 변경 후 영향24항목을 다시 통과했다. Ruff·장치 JS 구문·변경 공백도 통과했다. 전체 suite/CI 반복 결과는 아니다.
- Windows inbox csc4.8.9221.0으로 x64 WinForms lab EXE와 실제 .NET 계약 harness를 컴파일했다. 조직/장치/등록·키 scope·만료·HTTPS origin·lab IP·ZIP 경로 이탈/중복/용량·unsigned 서명 거부를 검사했다. production 분기도 컴파일됐지만 운영 인증서로 서명한 릴리스는 만들지 않았다. 호스트에 제품을 설치하지 않았다.
- 사용자가 공개 지문을 확인한 Windows10 build19045/.NET4.8/Restricted VM에서 **제품 EXE**가 ACL·DPAPI·Filebeat9.5.2 keystore/service·SYSTEM native Discovery task를 만들고 새 TLS ES/Portal에 실제 receipt를 확인했다. 별도 수집기 실행으로 설치를 대신하지 않았다. 실제 GUI 클릭/시각 검수는 하지 않았고 같은 설치·관리 엔진의 CLI를 실행했다.
- 실제 stop/start 후 합성 SQLi2+비SQLi3 → 정규화5/경보0, SQLi3번째 → 정규화6/WEB-SITE-WAF-001 경보1, 재처리 existing1/신규0을 확인했다. Portal 상세 API와 근거3건의 raw/normalized index/id·기존 event_hash·조직/host/site/package를 대조하고 privacy canary 미전송을 확인했다. 설치 probe1건은 미지원 분석 입력으로 분리되며 웹 합성6건을 누락/성공으로 숨기지 않았다. 실제 쇼핑몰 공격·모든 규칙의 인수는 아니다.
- 기본 uninstall로 service/task 제거·큐 보존, 명시적 purge 재호출로 collector root 삭제, 별도 Portal 장치 종료로 원격 키 폐기를 확인했다. 시험 manager/상태의 완전 삭제는 제품 self-uninstall이 아니라 정확한 새 소유권을 대조한 시험 controller의 정리다.
- `tests/manual/windows_native_tls_live.py`가 동일 TlsChain/tls-probe 소스로 실제 VM에서 정상 CA만 통과, 다른 CA·호스트 이름 불일치·폐기·CRL503·만료 거부의 6개 경계를 통과했다. OS CA 설치나 전역 CRL 캐시 삭제는 하지 않았다. `device_windows_native_live.py`는 실제 설치·수집·경보 경로다. 두 도구는 명시적 --run 전용이다.

### 발견·수정한 오류

1. .NET Framework의 폐기 검사 속성 차이로 최초 빌드가 실패해 공식 ServicePointManager 설정으로 수정했다. Windows 파일의 POSIX mode 표현/새 다운로드 fixture, 공유 pytest 임시 폴더 접근 거부도 각각 플랫폼 조건/전용 basetemp로 해결했다.
2. Task Scheduler의 작업 부재 0x80070002가 VM에서 COMException 대신 FileNotFoundException으로 반환됐다. 정확한 부재 HRESULT만 빈 결과로 처리하고 권한/다른 오류는 계속 실패하게 했다.
3. ExtraStore의 자체 CA는 Windows에서 leaf OfflineRevocation/RevocationStatusUnknown을 발생시켰다. 공식 exclusive chain engine에서 실제 CryptoAPI CRL 요청과 오류0을 확인한 후 새 EXE에만 적용했다. unknown/offline를 허용하지 않았다. 시험 CA 이름/CRL URL을 키별로 분리하고 CRLNumber를 추가했다. 한 certutil 다운로드 진단은 host 프로세스 생성 접근 거부로 실행되지 않아 중단했으며 그 명령을 우회하지 않았다.
4. 최종 ACL을 포함한 독점 CreateDirectory와 같은 bounded snapshot의 ZIP 해시/파싱으로 생성·읽기 경쟁 조건을 막았다. purge rename 전후와 보존 제거 뒤 명시 purge를 구분했다. 일부 초기 준비 중단은 자동 채택하지 않는 제한을 유지한다.
5. 시험 SSH 정리의 긴 원격 명령은 Windows 명령줄 한도로 실행되지 않아 보호된 자료 전달 뒤 일회성 정리 task로 복원했다. 이는 제품 설치 경로가 아니며 실행 정책을 바꾸지 않았다.

### 정리와 남은 인수

VM의 수집기/service/task/root/시험 manager·상태0을 확인했다. 시험 공개키·방화벽·정리 task·준비 폴더를 제거하고 OpenSSH.Server를 원래 NotPresent로 복원했다. Restricted·restart_needed=false를 받았으며 재부팅하지 않았다. 기존 여부를 단정할 수 없는 일반 SSH host key/config는 보존했다.

호스트의 새 ES 컨테이너/전용 TLS 볼륨, 개인키·비밀번호·Portal DB/전달 키·분석 체크포인트·SSH 개인키와 접속 창구를 정리했다. cleanup-audit.json에서 시험 포트6개 접속 불가·시험 개인키/컨테이너/볼륨0을 확인했다. Git 제외 `state/install-device-ux/windows-native-20261025`에는 공개 결과·비밀값 없는 진단과 unsigned 시험 EXE만 남긴다. 운영 설정·실제 데이터·기존 키·Git 커밋/푸시는 변경하지 않았다.

후속은 운영 서명 인증서/CI SignTool sign·verify, signed artifact의 Portal read-only mount·별도 SHA pin·조직 EXE 정책/OS 매트릭스 인수다. unsigned --lab을 운영에 연결하지 않는다. 강제 종료/모든 commit 지점 장애 재개 시험, manager self-uninstall·보존 큐 재설치 UX, GUI 시각 검수·대규모 배포·Packetbeat/Npcap은 남는다. 미검증 복구를 완료로 표시하지 않는다.

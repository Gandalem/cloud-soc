# 기존 Windows 에이전트 갱신과 복구

기존 고급 Windows 설치기의 Discovery 구조·갱신·Repair/Resume 안내를 통합했다. **새 managed EXE**의 설치/제거는 [장치 설치](device_installation.md), 토큰 재등록과 수신 확인은 [에이전트 운영](agent_management.md)을 따른다. 이 문서의 PowerShell 명령을 새 native EXE의 지원 명령으로 해석하지 않는다.

<a id="scope"></a>
## 작업 선택

| 현재 상태 | 작업 | 유지하는 자료 |
| --- | --- | --- |
| Filebeat가 정상 실행 중이며 Discovery만 갱신 | `-UpdateDiscovery` | 키·설정·최신 registry/큐·프로세스 |
| 동일 설치의 Filebeat 또는 두 Beat가 중지됨 | `-Repair` | 검증된 신원·서버/조직/CA·키·최신 큐·기존 NIC |
| 통합 Repair 자체가 중단됨 | `-Repair -ResumeRepair` | 중단 journal·백업을 재검증하고 최신 큐 유지 |
| 확인된 실패 Enrollment의 키 폐기 후 새 토큰 | [보존형 재등록](agent_management.md#reenrollment) | 같은 수집기 ID·최신 큐/registry |
| 제거 완료·출처 불명·서버/조직/NIC 변경 | 자동 채택하지 않음 | 상태/소유권 검토 필요 |

수정 코드가 반영된 **동일 서버·조직의 새 전체 패키지**를 Portal에서 받고 원본 SHA256을 확인한 뒤 새 폴더에 푼다. 기존 ZIP·실행 중 장치는 자동 갱신되지 않는다. 파일 하나 교체나 pending marker 삭제로 보호 검사를 우회하지 않는다. GPO/AllSigned/AppLocker/WDAC 차단은 승인된 배포로 해결하며 실행 정책을 변경하지 않는다.

<a id="native-discovery"></a>
## Discovery 실행 구조와 진단

기존 SYSTEM의 powershell.exe -File은 Restricted에서 차단돼2026-09-28부터 독립 C#/.NET Framework `cloud-soc-discovery.exe`를 사용한다. 이벤트 채널 메타데이터와 승인 로그 경로를 탐색하고 Filebeat 입력/agent_health를 준비하며, 이벤트 본문 전송·키 읽기·네트워크 전송은 담당하지 않는다. 디스크 전체/개인 문서 수집이 아니다.

고급 설치기의 install.ps1 진입점은 여전히 사용자/조직 실행 정책을 따른다. Windows 기본 .NET Framework4.x x64 컴파일러의 Microsoft 서명을 확인하고 보호 staging에서 빌드한다. 소스/EXE manifest 해시는 게시자 서명을 대신하지 않는다. SDK/런타임을 장치에 자동 다운로드하지 않는다. native EXE를 쓰는 주기 작업과 예전 discover-windows.ps1 사전 검사/정책 호환 경로를 구분한다.

실제 임시 SYSTEM task에서 새 보고서 생성까지 확인한 뒤 영구 action을 EXE `--root`와 명시적 작업 폴더로 설정한다. 계정/트리거는 보존한다. 활성 채널·회전/인코딩·민감 파일/사용자 프로필/링크 제외, 기존 channel/filestream ID·정책v1·agent_health 계약을 유지한다.

| 진단 | 의미 |
| --- | --- |
| discovery-report.json | 마지막 성공 소스/시각. 이전 성공을 현재 성공으로 재사용하지 않음 |
| discovery-diagnostic.json | 현재 단계·성공/실패·예외 종류/HRESULT. 본문/키/설정 값 제외 |
| settings / channels | 정책/설정 접근 또는 채널 열거/필수 채널 문제 |
| lock / files / publish | 잠금 충돌 또는 승인 경로·출력 저장 문제 |

프로세스/앱 제어 차단이면 새 진단이 없을 수 있다. task 결과와 앱 제어 기록을 함께 확인하고 오래된 오류를 현재 원인으로 단정하지 않는다.

<a id="discovery-update"></a>
## 실행 중 Discovery 갱신

관리자64비트 PowerShell의 새 패키지 폴더에서 실행한다. DryRun은 로컬 신원/해시 점검이며 SYSTEM/중앙 수신 성공이 아니다.

```powershell
.\install.ps1 -UpdateDiscovery -DryRun
.\install.ps1 -UpdateDiscovery
```

실제 갱신은 y 확인 후 수행한다. NIC 선택/Npcap/Packetbeat 설치를 건너뛰고 API key 재입력·서버 접속은 하지 않는다. Repair와 함께 쓰지 않는다. 정상 서비스를 멈춰 신규 설치로 우회하지 않는다.

갱신기는 설치/정책/Discovery 잠금을 잡고 기존 task를 비활성화한 뒤 진행 중 실행을 최대5분 기다린다. 프로세스를 강제 종료하지 않는다. ProgramData/Cloud-SOC/updates/<ID>에 소스·EXE·manifest·입력·task XML/해시를 백업하고 새 staging의 임시 SYSTEM 결과를 확인한다. 실제 위치로 교체한 뒤 새 SYSTEM 보고·Filebeat 프로세스/키/설정 불변을 검사해 원래 예약 실행을 재개한다. 이 백업은 전체 PC/큐 백업이 아니다.

일반 교체 실패는 검증된 이전 프로그램/입력을 복원하지만 큐·registry·keystore·이미 생성된 spool을 되돌리지 않는다. 외부 task/설정 변경, 백업 손상, 끝나지 않은 작업은 discovery-update-pending.json과 보호 자료를 남기고 중단한다. 자동 중단 재개는 미지원이며 task가 비활성 상태일 수 있다. 갱신 중 다른 관리자/구형 정책 도구의 병행 변경을 피한다.

로컬 완료 뒤에는 같은 수집기의 새 보고 생성/서버 수신 시각·collector_metrics와 화면 수치를 대조한다. 통계가 없으면 미측정이고 오류 미보고를 오류0으로 바꾸지 않는다. 로컬 종료0/실행 중 service만으로 중앙 수신을 완료 처리하지 않는다.

<a id="repair"></a>
## 중지된 설치 복구

P0C-02는 OS/관리자·서비스 경로/LocalSystem·공식9.5.2·endpoint/조직/CA·keystore·권한/링크·소유 manifest·Discovery 신원을 검사한다. 통합 설치는 기존 NIC/Npcap 의존성도 유지한다. 실행 중/Queued/출처 불명 task, 다른 서버/조직·수정 파일·설정은 덮어쓰지 않는다. 무관한 Filebeat나 Filebeat만 있는 PC의 Packetbeat 추가 설치가 아니다.

```powershell
.\install.ps1 -Repair -DryRun
.\install.ps1 -Repair
# 확인된 통합 Repair 중단 기록이 있을 때만
.\install.ps1 -Repair -ResumeRepair -DryRun
.\install.ps1 -Repair -ResumeRepair
```

동의 후 ProgramData/Cloud-SOC/recovery 또는 staging/<ID>의 보호 백업을 만들고 전체 파일/해시와 용량을 확인한다. SYSTEM Discovery·두 수집기 config/output·새 영구 보고를 검사한 뒤 시작 직전에 신원과 중지 상태를 다시 확인한다. 두 서비스가 Running을 유지해야 자동 시작으로 전환한다.

누락 서비스는 새 통합 설치의 최종 준비 receipt/bundle-recovery·pending journal·두 디렉터리 신원이 모두 일치할 때만 복구한다. 폴더 승격 중단·구형 기록·누락 폴더는 자동 채택하지 않는다. 기존 비활성 task는 XML/해시 백업 후 action만 고치며 삭제/재등록하지 않는다. 외부에서 시작/수정한 자원을 강제로 정지하거나 채택하지 않는다.

실패하면 이번 실행 소유 service/task/코드·시작 유형만 보상 복구하고 **최신 큐·registry·keystore를 백업으로 되감지 않는다.** 신원 불일치·백업 변조·작업 종료 실패는 자료와 pending을 남긴다. 통합 ResumeRepair는 bundle-repair-pending/repair-state를 재검증하지만 로그 전용·UpdateDiscovery와 조합하지 않는다. 일반 업그레이드·키 분실 교체·서버/조직/NIC 이전·중단 설치의 부팅 자동 Repair는 아니다.

<a id="failure-boundaries"></a>
## 신규 설치의 실패 처리

새 고급 네트워크 묶음은 bundle-windows.ps1에서 두 Beat의 다운로드·SHA512·설정·키 검사와 SYSTEM Discovery를 보호 staging에서 준비한 후 최종 경로로 승격한다. 두 경로 이동/service 시작은 OS 수준의 완전한 원자성이 아니며 Linux 네트워크 설치는 순차 흐름이다.

| 실패 시점 | 처리 |
| --- | --- |
| OS/권한/NIC/Npcap/TLS 전 | 수집기 service/설치 경로 생성 전 중단 |
| SYSTEM/다운로드/설정 검사 | 이번 소유 staging/task만 정리 |
| 경로 승격 후 service 생성 전 | 소유 최종 경로/task만 정리 |
| service 시작 시도 이후 | 소유 service 중지/비활성화, 키·큐·receipt 보존 |
| 정리 실패·링크·외부 변경·기존 부분 설치 | 보호 기록 유지, 자동 삭제/채택하지 않음 |

실제 NIC는 기본 경로의 활성 물리 NIC 후보를 보여 주고 하나여도 y/yes 동의를 요구한다. VPN/가상 NIC는 기존 InterfaceGuid를 명시한다. DryRun은 합성 NIC 미리보기일 수 있어 실제 NIC/TLS/SYSTEM 검증이 아니다. SYSTEM 사전 시험에는 임시 파일/task가 필요하므로 무파일 검사라고 안내하지 않는다.

<a id="tls"></a>
## TLS 폐기 확인 오류

Schannel/curl 오류60은 여러 인증서 문제를 포함한다. CA·주소/SAN·유효기간·온라인 CRL/OCSP부터 확인한다. 신규 native EXE는 이 문서의 호환 옵션을 지원하지 않으며 엄격 검사를 유지한다.

기존 고급 Windows 경로에서 승인된 사설 CA의 **폐기 정보 조회 불가만** 허용할 때는 다음 명시 옵션이 있다. 기본은 엄격 검사다.

```powershell
.\install.ps1 -AllowUnavailableRevocation
```

인증정보 없는 중앙 사전 검사에만 curl --ssl-revoke-best-effort를 적용한다. 알려진 폐기·다른 CA·주소/기간 불일치를 허용하지 않지만 조회 불가 때 폐기를 확정할 수 없다는 한계가 있다. OS 신뢰/전역 설정·Elastic 다운로드·Beat TLS full 설정은 변경하지 않는다. insecure/-k/ssl-no-revoke로 대체하지 않는다. IPv4 SAN/Schannel 호환은 번들의 tls-probe.cs가 기본 IP/DNS·번들 루트 bytes·용도·기간·온라인 폐기를 해당 연결에서만 검사한다.

<a id="boot"></a>
## 부팅 후 수집

10/08 보완된 고급 설치/Repair는 Filebeat·Packetbeat를 지연 자동 시작으로 설정하고 Npcap 의존성을 유지한다. 실패하면 원래 시작 유형/지연 값을 복원하며 전역 service timeout을 바꾸지 않는다. 시험 VM에서는 부팅 후 약2분10초에 시작됐지만 환경별 시간이 다르며 시작 전 패킷을 소급 수집하지 않는다. 기존 ZIP/장치는 자동 변경되지 않고 UpdateDiscovery도 시작 유형을 바꾸지 않는다. 부팅 후 service와 **새 중앙 수신 시각**을 함께 확인한다.

<a id="verification"></a>
## 검증 이력과 제한

| 날짜/작업 | 실제 결과 | 제한/후속 |
| --- | --- | --- |
|09/28 P0C-13/14 | 초기 SYSTEM 시험은 관리자 취소로 미실행. 후속 승인 후 Restricted SYSTEM 격리 통과, 의도적 오류 진단/입력 보존·정리 확인. 실제 PC 보호 Repair 뒤 Application 고유 이벤트의 구조 필드·ID/시각과 ES 참조 대조 | 당시 Packetbeat 미설치·브라우저 별도. 과거 필드1000개 한도 거절의 무손실 복구를 뜻하지 않음 |
|09/28~30 P2C-07 | 실제 Discovery 교체·새 중앙 통계, 관리자 진단13/13·HTTPS 화면/ES 수치 독립 대조·갱신 후 최신 보고 확인 | 미보고 오류 카운터·집계 범위 제한. 전체 무손실 아님 |
|10/01 P0C-02 | 시험 VM의 통합 설치·Repair·전송 장애 보상·강제 종료 후 ResumeRepair·대기 데이터 수신·재부팅 후 새 로그/통신 확인 | 모든 OS/GPO/전원 손실 시점이 아님 |
|10/04 P0C-03 | 양 OS 로그 전용/통합·중앙 장애 후 키 폐기/보존형 새 토큰 재등록·실수신 | [실제 기록](archive/README.md#record-docs-archive-validation-p0c03-validation-20261004-md), 정상 설치 키 자동 회전 별도 |
|10/08 P0C-02R-01 | 지연 자동 시작 보완과 실제 재부팅 후 두 수집기·Discovery/Npcap·새 중앙 수신 확인 | 새10/25 native 설치기의 재부팅/복구 인수를 대신하지 않음 |

당시 native/Discovery 배포는 Git 밖 소스 snapshot으로 시작했고 P2C-08의 dc3f6b3 후 Git/Portal을 맞췄다. 현재 패키지를 과거 시험 ZIP으로 대체하지 않는다. 구체 해시·기존 성공/실패·기록 ID는 [누적 이력](archive/README.md#record-docs-work-history-20261012-md)과 [작업 목록](work_tracker.md)에 보존했다. 초기 문서의 “Repair/Resume/Enrollment 미지원” 표는 위 후속 결과로 대체했다.

회귀 도구는 deploy/agents/tests의 update-discovery.test.cjs, repair.test.cjs, verify-discovery-update.test.cjs다. 모의 OS/실제 임시 파일 시험과 실제 SYSTEM/중앙 수신을 구분한다. 명시 승인된 SYSTEM 격리 명령은 아래와 같다.

```powershell
.\deploy\agents\tests\native-system-live.ps1 -RunIsolatedTest -ResultPath 'D:\cloud-soc\state\native-result-new.json'
```

이 도구는 service/출력 전송 없이 채널 메타데이터·합성 파일과 임시 task만 검사하고 전후 정책을 비교한다. 실제 기존 장치에 자동 실행하지 않는다. 과거 필드 한도 거절은 [유실 감사](windows_log_loss_audit.md), 수집 보고는 [계측](p2_collection_metrics.md)을 따른다. ignore_dynamic_beyond_limit 적용이 과거 거절 문서를 자동 복구하지는 않는다.

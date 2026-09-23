# Windows 설치 실패 예방: 1차 적용

2026-09-23 요청에 따른 **신규 설치 준비 단계 개선**입니다. 현재 구현을 Enrollment 기반 완성형 배포 제품이나 전체 자동 복구로 보지 않습니다. 기존 설치·큐·키를 보존하는 원칙은 유지합니다.

## 변경된 흐름

1. Windows x64·관리자·기존 서비스/경로 충돌·CA 파일을 확인합니다. 중앙 HTTPS에 제한 시간 20초의 자격 증명 없는 요청을 보내 CA/TLS·연결을 확인합니다. 이 단계는 API 키 권한이나 로그 쓰기 성공을 증명하지 않습니다.
2. 네트워크 묶음은 Filebeat 설치 전에 Npcap·활성 NIC·중앙 TLS를 먼저 확인합니다. NIC 미지정 시 기본 IPv4 경로가 있는 활성 물리 NIC를 표시합니다. 한 개여도 `y/yes` 확인이 필요하고, 여러 개면 번호를 선택합니다. 기본은 취소입니다. VPN/가상 NIC는 기존 `-InterfaceGuid`를 명시합니다.
3. `%ProgramData%\Cloud-SOC\staging\<random>`을 SYSTEM/Administrators 전용 ACL로 생성합니다. 기존 staging 부모의 권한이 예상과 다르면 덮어쓰지 않고 중단합니다.
4. Filebeat는 다운로드 전에 **일회성 SYSTEM Discovery 예약작업**을 실행합니다. 작업 종료 코드뿐 아니라 해당 실행의 새 `discovery-report.json` 생성 시각도 확인하고 임시 작업을 제거합니다. `Running/Queued` 상태를 완료로 간주하지 않습니다.
5. staging에서 고정 SHA-512 검증, 압축 해제, keystore 입력, `test config`와 `test output`을 수행합니다. 실패하면 이번 실행의 소유 토큰과 정확한 경로를 검사한 뒤 해당 디렉터리만 정리합니다.
6. 준비 완료 후에만 최종 Program Files 경로로 이동합니다. staging의 절대 경로를 최종 경로로 재생성하고 설정/연결 검사를 반복합니다. 디렉터리 이동은 동일 볼륨을 전제로 하며, 다른 볼륨이면 안전하게 실패합니다.
7. Filebeat의 영구 SYSTEM Discovery 작업을 다시 검사한 뒤 서비스를 생성·시작합니다. Packetbeat도 staging 검증 후 별도로 서비스를 생성합니다.

SYSTEM 작업은 임시 스크립트·설정·예약작업 없이는 검증할 수 없습니다. 따라서 사전 단계의 계약은 **'파일이 전혀 생기지 않음'이 아니라 '영구 수집 서비스를 만들기 전에 검사하고 소유 임시 자원을 정리함'**입니다. 보호된 공용 staging 부모 디렉터리는 남을 수 있습니다.

SYSTEM과 대화형 사용자의 환경은 다릅니다. 작업 디렉터리와 Discovery 루트를 명시했지만, 사용자가 보고한 `LastTaskResult=1`의 정확한 원인을 확인한 것은 아닙니다. [Microsoft 작업 액션 문서](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskaction?view=windowsserver2025-ps)에 따라 `WorkingDirectory`를 지정하며 PowerShell 실행 정책이나 인증서 검증은 우회하지 않습니다. AllSigned/GPO 환경은 보조 스크립트까지 승인된 서명이 필요합니다.

## 실패 시 동작

| 실패 지점 | 동작 |
| --- | --- |
| OS/관리자/NIC/Npcap/TLS 사전 검사 | 수집 서비스와 설치 디렉터리를 만들지 않고 중단 |
| SYSTEM Discovery/다운로드/체크섬/키·설정 검사 | 임시 작업 종료·해제 후 이번 실행의 staging 정리 |
| 최종 경로 이동 후, 서비스 생성 전 실패 | 이번 실행이 만든 작업을 정리하고 소유 최종 디렉터리만 정리 |
| 임시 작업 종료/해제 실패, 경로 링크/소유권 불일치 | 실행 중 작업이나 다른 파일을 지우지 않도록 보호 상태 유지 |
| 서비스 시작 시도 후 실패 | 서비스 중지/비활성화, 큐·registry·keystore 보존. 자동 삭제하지 않음 |
| 기존/구버전 부분 설치 발견 | 기존 상태를 바꾸지 않음. 새 staging 롤백이 과거 설치까지 정리하지 않음 |

오류 시 종료 코드는 1입니다. 모르는 디렉터리·junction·reparse point를 따라 재귀 삭제하지 않습니다. 강제 프로세스 종료·정전까지 자동 복구하는 영속 트랜잭션은 아직 아니며, 정리 실패 경로도 무조건 재사용하지 않습니다.

## 적용 방법

중앙 포털에 변경 코드가 반영된 후 **새 설치 패키지를 생성**해야 합니다. 기존 SQLite의 ZIP은 자동 업데이트하지 않습니다. `transaction-windows.ps1`을 포함한 패키지 전체를 사용합니다. 설치 스크립트 한 파일만 기존 설치 폴더에 덮어쓰지 마세요.

네트워크 묶음의 새 기본 명령:

```powershell
# 새 패키지를 해시 확인 후 압축 해제한 관리자 PowerShell에서 실행
.\install.ps1
# NIC/파일을 탐색하거나 설치하지 않는 설정 미리보기
.\install.ps1 -DryRun
```

`-DryRun`에서 NIC를 생략하면 합성 GUID로 미리보기만 출력합니다. 실제 NIC 선택·SYSTEM 테스트·TLS·키 인증을 통과했다는 의미가 아닙니다. 키는 기존처럼 호스트용/네트워크용을 각 Beat keystore에 입력합니다. 읽기 권한을 수집 키에 추가하지 않습니다.

## 남은 필수 작업

- **P0C-02:** 두 수집기를 모두 준비한 뒤 commit하는 통합 트랜잭션, 설치 중단 후 재개, 소유권 검증 기반 `-Repair`. 현재 네트워크 preflight는 빨라졌지만 Packetbeat의 키 오류 등 후기 실패 시 Filebeat만 설치되어 있을 수 있습니다.
- **P0C-03:** 단일 사용 Enrollment 토큰과 고유 설치 테스트 이벤트 수신 확인. 만료·원자적 소비·재시도·키 발급/폐기·패키지/조직 바인딩을 함께 검증해야 합니다. 현재 `-Repair`/Enrollment는 지원 옵션이 아닙니다.
- **P0-02/03:** 승인된 Windows에서 실제 관리자/SYSTEM·Npcap·서비스·ES 도착 시험. 현재 자동화 검증은 모의 cmdlet과 임시 파일, 생성 패키지 DryRun입니다. 사용자 PC에 실제 서비스를 설치하거나 실시간 캡처하지 않았습니다.

서비스 Running/TLS 확인은 **설치 단계 통과**일 뿐 전체 수집 E2E 성공이 아닙니다. 고유 이벤트 도착 확인 전에는 전체 `SUCCESS`를 표시하지 않습니다.

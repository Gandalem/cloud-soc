# Windows Discovery 실행 구조

## 원인과 해결 범위

사용자 관리자 계정의 `RemoteSigned`는 SYSTEM 계정에 적용되지 않습니다. 실제 실패 PC는 SYSTEM의 모든 정책 범위가 미설정이어서 유효 정책이 `Restricted`였고, 예약작업의 `powershell.exe -File` 실행이 차단됐습니다. 관리자 직접 실행 성공이나 코드의 모의 테스트만으로 SYSTEM 실행을 보장할 수 없었습니다.

주기적 Discovery를 독립 C#/.NET Framework 프로그램 `cloud-soc-discovery.exe`로 교체합니다. 이 프로그램은 PowerShell을 내장/호출하지 않고 Windows 이벤트 채널 메타데이터와 승인된 로그 디렉터리를 직접 탐색합니다. 이벤트 본문 수집과 전송은 기존 Filebeat가 담당하며, 독립 프로그램은 키를 읽거나 네트워크로 전송하지 않습니다.

`Set-ExecutionPolicy`, `-ExecutionPolicy`, 스크립트 인코딩/인라인 실행으로 기존 제한을 우회하지 않습니다. PowerShell 실행 정책과 별개인 AppLocker/WDAC 등의 앱 제어가 컴파일러나 결과 EXE를 차단하면 설치를 중단합니다. 기업 환경에서는 승인된 서명·게시 절차가 필요합니다.

## 설치와 기존 설치 복구

1. 설치기의 기존 OS/관리자·TLS·서버/조직/CA 동일성 검사를 유지합니다. 설치 진입점 `install.ps1`은 여전히 관리자 환경의 실행 정책을 따라야 합니다.
2. 신규 설치는 보호 staging, 기존 중지 설치는 검증된 전체 백업 이후에 Windows 기본 .NET Framework 4.x x64 컴파일러를 사용합니다. 컴파일러의 Microsoft 서명을 확인하고 새 임시 보호 폴더에서 소스를 컴파일합니다. 별도 SDK/런타임을 다운로드하지 않습니다.
3. 소스와 결과 EXE의 해시 manifest를 기록하고 실행 전 대조합니다. 보호 ACL은 설치기에서 적용하며 해시만으로 게시자 서명을 대체하지 않습니다. 다운로드 ZIP은 기존처럼 포털 SHA-256으로 별도 확인해야 합니다.
4. 실제 SYSTEM 임시 예약작업에서 EXE를 실행하고 최신 Discovery 보고서 생성까지 확인합니다. 실패하면 단계·예외 종류·HRESULT만 진단하며 로그 본문/키/설정 값은 진단에 넣지 않습니다.
5. 설정과 서버 연결 검사를 통과한 뒤 영구 작업의 동작을 `cloud-soc-discovery.exe --root "설치 경로"`로 변경하고 작업 폴더도 명시합니다. 기존 비활성 작업은 XML/해시 백업 후 동작만 변경하며 계정/트리거를 보존합니다.
6. 실패하면 원래 작업과 교체 파일을 복원하며 큐/registry/keystore는 되감거나 삭제하지 않습니다. 정리 실패·다른 관리자에 의한 변경이 발견되면 백업과 중단 기록을 남기고 멈춥니다.

이미 배포한 ZIP은 자동 변경되지 않습니다. 수정 코드를 중앙 서버에 반영하고 새 패키지를 생성해야 합니다. 이전 ZIP의 파일 일부만 교체하는 방식은 지원하지 않습니다.

## 수집 계약과 진단

활성 이벤트 채널, 텍스트 로그 인코딩/회전, 민감 파일·바이너리·사용자 프로필 제외, 디렉터리 링크 제외, 기존 채널/filestream ID, 정책 v1과 `agent_health` 출력 계약을 유지합니다. 디스크 전체·모든 파일·개인 문서를 수집한다는 의미가 아닙니다. 기존 `discover-windows.ps1`은 설치기 사전 검사·기존 정책 도구 호환용으로 남지만 SYSTEM의 주기적 작업에서는 실행하지 않습니다.

- `discovery-report.json`: 마지막 성공 탐색의 소스 목록과 시각. 실패했다고 이전 성공 보고를 현재 결과로 취급하지 않습니다.
- `discovery-diagnostic.json`: 마지막 실행의 성공/실패, 단계, 예외 종류, HRESULT. 보호 설치 폴더에 남으며 복구 시 과거 진단으로 되돌리지 않습니다.
- `settings`: 설정/정책 파일 형식·접근 문제입니다.
- `channels`: 채널 열거 또는 필수 채널 접근/활성 여부 문제입니다.
- `lock`: 다른 탐색/정책 갱신과 충돌했거나 잠금 파일에 접근하지 못했습니다.
- `files`/`publish`: 승인 경로 또는 결과 파일 접근·저장 문제입니다.

EXE가 앱 제어로 차단되거나 프로세스가 시작되지 못하면 새 진단 파일이 없을 수 있습니다. 이 경우 예약작업 결과와 Windows 앱 제어 기록을 확인해야 하며, 오래된 진단을 새 실행의 원인으로 단정하지 않습니다. 설치기의 SYSTEM 검사 실패 메시지는 신선한 진단만 출력하므로 staging 정리 후에도 오류 요약을 볼 수 있습니다.

## 검증과 다음 단계

2026-09-28 로컬 검증: C# 합성 탐색, PowerShell 5.1/7 빌드·해시·복구 회귀, 포털 패키지 생성 시험과 실제 Filebeat 9.5.2의 합성 로그 오프라인 시험을 통과했습니다. 실제 SYSTEM 격리 시험은 관리자 승인 창이 취소되어 미실행입니다. 기존 설치 전환·서비스 활성화·중앙 수신·서버 배포는 수행하지 않았습니다.

같은 날 후속 승인으로 실제 SYSTEM 격리 시험을 수행해 통과했습니다. 전후 정책은 모두 Restricted였고, 정상 탐색·의도적 정책 오류의 진단/기존 입력 보존·임시 자원 정리를 확인했습니다. 이는 기존 서비스 복구/중앙 수신과 별개이며, 최신 배포·운영 결과는 작업 목록 P0C-14에 기록합니다.

후속 배포에서 VMware 포털과 새 로그 전용 패키지 `test-window-native-recovery-20260928-setup.zip`을 준비했습니다. 기존 패키지/키 이력은 유지했습니다. PC 복구 승인 1회 취소 후 사용자가 재요청해 승인된 복구를 수행했고, Filebeat Running/Auto·독립 Discovery 결과 0·기존 키/설정/CA 불변·보호 백업 해시 재검사를 통과했습니다. 고유 Application 이벤트의 구조화된 문자열, 이벤트 번호, 호스트/수집기/발생 시각을 실제 ES 문서와 대조했습니다. 현황 공통 조회에서도 수집기 1개가 recent였습니다. Packetbeat는 설치하지 않았으며 브라우저 로그인 화면 확인은 별도입니다. 이전 다운로드 폴더의 ZIP에는 새 코드가 없으므로 반복 실행하지 않습니다.

최초 배포는 미커밋 소스를 별도 `state/releases/native-20260928` 빌드 문맥으로 전달했으며 당시 서버 Git 체크아웃은 변경하지 않았습니다. 후속 P2C-08에서 누적 변경을 `dc3f6b3`으로 커밋·푸시하고, 서버 Git 소스를 동기화해 포털을 다시 빌드·배포했습니다. 기존 Windows worker의 신규 통계 코드 갱신은 별도 P2C-07이며 서버 배포만으로 적용되지 않습니다. 백업·복구 이미지·패키지 해시와 남은 단계는 [작업 기록](work_tracker.md)에 있습니다.

```powershell
node --test deploy/agents/tests/*.test.cjs
# 별도 관리자 승인: 임시 SYSTEM 작업과 합성 파일만 사용
.\deploy\agents\tests\native-system-live.ps1 -RunIsolatedTest -ResultPath 'D:\cloud-soc\state\native-result-new.json'
```

SYSTEM 격리 시험은 실행 전후 유효 정책을 비교하고, 정상 결과와 의도적 잘못된 정책 파일의 실패 진단·기존 입력 보존을 검사합니다. 채널 메타데이터는 실제 API로 열거하지만 실제 이벤트 본문·실제 로그 파일은 수집하지 않으며, Filebeat/Packetbeat 서비스·네트워크 출력은 사용하지 않습니다.

아직 전체 제품형 설치 완료가 아닙니다. 서명된 사전 빌드 실행 파일과 GUI 설치기, 두 수집기의 통합 트랜잭션, 단일 Enrollment, 설치기에 내장된 자동 수신 확인, 일반 업그레이드/중단 자동 재개는 후속 범위입니다. 이번 고유 이벤트 수신은 별도 운영 검증으로 수행했습니다. 컴파일러가 없는 Windows나 EXE 허용 목록이 필요한 환경은 자동 지원으로 표시하지 않습니다. 기존 TLS 호환 옵션과 키 만료 문제도 이 변경으로 해결되었다고 간주하지 않습니다.

실제 과거 로그 초기 수신에서는 일부 호스트 인덱스가 필드 1000개 한도로 문서를 거절했습니다. P0C-15에서 기존 설정을 백업하고 호스트 템플릿/인덱스에 `index.mapping.total_fields.ignore_dynamic_beyond_limit=true`를 적용했습니다. 초과 필드는 수집기 보호 처리를 거친 `_source`에 남지만 검색/집계 대상에는 추가되지 않으며 `_ignored`로 확인합니다. 기존 거절 이벤트가 자동 복구되지는 않습니다. 임의 키가 많은 데이터의 구조화/검색 계약과 과거 거절 복구는 후속 과제입니다. [Elastic 필드 한도 문서](https://www.elastic.co/docs/reference/elasticsearch/index-settings/mapping-limit).

참고: [Microsoft 실행 정책](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies), [Windows 이벤트 채널 열거](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.getlognames), [앱 제어 정책](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules).

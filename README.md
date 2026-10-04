# Cloud SOC

Windows·Ubuntu의 로그와 네트워크 메타데이터를 모아, 웹에서 확인하고 사건을 조사하는 **Mini SIEM 보안관제 프로젝트**입니다.

```text
서버·PC 에이전트 → 중앙 Elasticsearch → Cloud SOC 대시보드
```

**처음이라면 중앙 서버를 설치한 뒤, 웹에서 에이전트 패키지를 내려받으세요.** 이미 설치된 PC는 재설치하지 않고 갱신 안내를 따릅니다.

| 지금 하려는 일 | 바로가기 |
| --- | --- |
| 중앙 서버를 처음 설치하기 | [1. 중앙 서버 설치](#1-중앙-서버-설치) |
| Windows·Ubuntu에 에이전트 설치하기 | [2. 에이전트 설치](#2-에이전트-설치) |
| 수집된 로그 확인하기 | [3. 대시보드 사용](#3-대시보드-사용) |
| 기존 Windows PC 갱신하기 | [4. 기존 PC 갱신](#4-기존-pc-갱신) |
| 설치나 조회에 문제가 생겼을 때 | [5. 문제 해결](#5-문제-해결) |

## 1. 중앙 서버 설치

**새 Ubuntu 서버의 터미널**에서 진행합니다. Windows PC에서 실행하는 명령이 아닙니다.

| 준비할 것 | 기준 |
| --- | --- |
| 운영체제 | Ubuntu 22.04·24.04·26.04 LTS + systemd |
| 서버 용량 | RAM 8GiB 이상 권장, 최소 RAM 6GiB·여유 디스크 10GiB |
| 접속 주소 | 서버에 접근할 DNS 또는 IP, 인증서와 일치하는 주소 |
| 네트워크 | SSH 22·포털 443·Kibana 5601·수신 9200을 승인된 IP에만 허용 |

Git이 준비되어 있다면 다음 순서로 시작합니다. Git 설치와 AWS 설정은 [중앙 서버 가이드](deploy/server/README.md) 또는 [AWS 설치 가이드](docs/aws_windows_e2e_test.md)를 확인하세요.

```bash
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
# 실행할 스크립트를 먼저 검토
less deploy/server/install-ubuntu.sh
# 계획만 확인하며 실제 설치 가능 여부를 검사하지 않음
sh deploy/server/install-ubuntu.sh --dry-run
```

스크립트와 설치 계획을 확인한 뒤 실행합니다.

```bash
sudo sh deploy/server/install-ubuntu.sh
```

접속 주소·서버의 로컬 IP·설치 승인·관리자 비밀번호를 입력하면 필요한 패키지와 중앙 서비스를 준비합니다. EC2의 로컬 IP는 프라이빗 IP이며, 공란이면 서버 내부에서만 접속할 수 있습니다.

설치 후 브라우저에서 `https://<중앙-서버-주소>/`를 열고 `admin`과 설치 때 정한 비밀번호로 로그인합니다. **사설 CA를 쓰는 경우 공개 인증서의 출처·해시를 확인하고 PC에 신뢰 등록**해야 합니다. [인증서 안내](docs/aws_windows_e2e_test.md#6-windows에-ca-공개-인증서-전달신뢰)

> 기존 서버에는 초기 설치기를 다시 실행하지 마세요. [기존 서버 업데이트](docs/agent_status.md#기존-중앙-서버-업데이트)와 [백업 안내](docs/portal_backup.md)를 따릅니다. 비밀번호·개인키·데이터 볼륨을 삭제하지 않습니다.

## 2. 에이전트 설치

**설치할 서버·PC마다** 진행합니다. 중앙에서 원격으로 자동 설치하는 방식은 아닙니다.

1. 대시보드의 **에이전트 설치 파일 → 설치 파일 추가**를 엽니다.
2. 운영체제·조직·로그/네트워크 수집 여부를 정하고 패키지를 생성합니다.
3. ZIP 또는 tar.gz를 다운로드하고 포털에 표시된 해시와 대조한 뒤 새 폴더에 압축을 풉니다.
4. 같은 패키지의 **수동 키 발급**에서 수집용 API 키를 발급합니다.
5. **해당 패키지의 설치 명령**을 대상 PC/서버에서 실행하고 발급한 키를 입력합니다.

| 대상 | 준비 사항 |
| --- | --- |
| Windows x64 | 64비트 관리자 PowerShell, 승인된 스크립트 실행 환경 |
| Ubuntu 22.04 | systemd·관리자 권한. 중앙 서버 지원 버전과 에이전트 지원 버전은 다름 |
| Windows 네트워크 수집 | 승인된 Npcap 필요. 표시되는 NIC를 확인하고, 가상/VPN NIC는 명시적으로 지정 |
| Ubuntu 네트워크 수집 | 설치 명령에 수집할 인터페이스를 지정. [네트워크 안내](deploy/agents/NETWORK.md) |

**패키지에는 중앙 수신 주소·조직·공개 CA가 포함되고 수집 키는 포함되지 않습니다.** 로그용과 네트워크용 키를 구분해 입력하세요. 새 Windows 네트워크 포함 패키지는 두 수집기의 준비가 끝난 뒤 서비스 등록을 진행합니다.

신규 Windows 통합 설치용 **단일 설치 토큰·자동 중앙 수신 확인**은 개발 중이며 기본 비활성화입니다. 서버에서 준비·활성화한 경우에만 ‘설치 토큰’이 표시됩니다. 기존 PC·Linux는 위 절차를 유지합니다. [지원 범위와 시험 안내](docs/agent_enrollment.md)

설치 후에는 터미널을 닫아도 수집 서비스가 백그라운드에서 동작합니다. 그러나 **설치 완료나 서비스 실행만으로 중앙 수신을 보장하지는 않습니다.** 아래 대시보드에서 확인하세요.

해시 검사·압축 해제·실행 정책·설치 오류가 궁금하면 [설치 상세 참고](docs/installation_reference.md)와 [Windows 복구 안내](docs/windows_install_recovery.md)를 확인하세요. 기존 ZIP은 서버 업데이트만으로 바뀌지 않습니다.

## 3. 대시보드 사용

중앙 서버에 로그인한 뒤 왼쪽 메뉴를 사용합니다.

| 메뉴 | 무엇을 확인하나요? |
| --- | --- |
| 관제 현황 | 기간별 실제 수신량·추이, 처리 기록과 저장된 경보 |
| 통합 로그 | 엑셀 리스트 형태의 로그 메타데이터, 이벤트 ID·공급자·지원되는 보안 해석 |
| 사건 조사 | 저장된 사건·담당자·상태·조사 메모. 실제 경보에서 조사/등록 시작 |
| 수집 품질 | 수집 소스의 선택·제외·오류 보고, Windows 큐·전송 통계 |
| 에이전트 접속 현황 | 마지막 서버 수신 시각 기준의 수집기 활동 |
| 에이전트 설치 파일 / 발급 키 관리 | 패키지 다운로드와 키 용도·대상·만료·폐기 관리 |

<a id="7-설치-후-실제-로그-확인"></a>

### 로그가 들어오는지 확인

1. **통합 로그**에서 최근 1시간 또는 24시간을 선택하고 해당 호스트를 조회합니다.
2. **에이전트 접속 현황**에서 마지막 서버 수신 시각을 확인합니다.
3. **수집 품질**에서 보고 생성/수신 시각과 전송 표본을 확인합니다.

새로고침으로 최신 기록을 조회하세요. 원본 시험 이벤트와의 대조가 필요하면 [실제 수신 점검](docs/installation_reference.md#설치-후-실제-로그-확인)을 따릅니다.

**표시를 읽는 법**

- `미수신`은 실제 오프라인 판정이 아닙니다. 로그가 없거나 전송이 지연될 수도 있습니다.
- `인덱스 없음`은 해당 저장 대상이 없는 상태이고, `조회 실패`와 다릅니다. 경보가 없다고 안전한 것은 아닙니다.
- `메타데이터만 표시`는 로그는 조회됐지만 해당 이벤트의 행위 해석을 지원하지 않는다는 뜻입니다.
- `전송 대기`는 에이전트 큐의 표본, `수신 로그`는 중앙에 저장된 문서입니다. ACK는 해당 구간의 출력 확인이며 `미보고`는 오류 0이 아닙니다.

## 4. 기존 PC 갱신

**정상 수집 중인 Windows PC의 탐색·통계 프로그램(Discovery)만 갱신**하는 기능입니다. 전체 수집기 업그레이드나 서버·조직·인증서 변경이 아닙니다.

동일 서버·조직·CA의 새 전체 패키지를 검증하고 새 폴더에 압축을 풉니다. 관리자 PowerShell에서 읽기 전용 점검을 먼저 실행합니다.

```powershell
.\install.ps1 -UpdateDiscovery -DryRun
```

점검이 성공한 경우에만 갱신을 실행하고 확인 질문에 동의합니다.

```powershell
.\install.ps1 -UpdateDiscovery
```

기존 키·설정·전송 대기 데이터는 보존합니다. 갱신 후 수집 품질 화면의 보고 시각도 확인하세요. API 키 재입력·NIC 선택은 필요하지 않습니다. [자세한 갱신 절차](docs/windows_discovery_update.md)

> 중지된 설치는 [제한적 복구 안내](docs/windows_install_recovery.md)를 따릅니다. 실행 중인 PC에 신규 설치를 반복하거나 `-Repair`와 `-UpdateDiscovery`를 함께 사용하지 마세요.

## 5. 문제 해결

| 이런 문제가 있나요? | 먼저 확인할 안내 |
| --- | --- |
| 웹에서 인증서 경고가 나옴 | [공개 CA 확인·신뢰 등록](docs/aws_windows_e2e_test.md#6-windows에-ca-공개-인증서-전달신뢰). 경고를 무시하거나 TLS 검증을 끄지 않음 |
| ZIP이 없다고 나오거나 해시가 다름 | [다운로드 위치·해시 확인](docs/installation_reference.md#windows-zip-경로와-해시-오류) |
| PowerShell이 서명되지 않았다고 실행을 차단 | [검증한 패키지의 실행 정책 안내](docs/installation_reference.md#windows-미서명-스크립트-차단). 조직 정책을 낮추지 않음 |
| `schannel: the revocation status is unknown` | [사설 CA 폐기 정보 검사 안내](docs/windows_install_recovery.md#schannel-the-revocation-status-is-unknown). 조건 확인 없이 옵션을 추가하지 않음 |
| 기존 설치가 있다고 나옴 / 설치 중 실패 | [Windows 복구 안내](docs/windows_install_recovery.md). 기존 폴더·키·큐·중단 기록을 삭제하지 않음 |
| 서비스는 실행되지만 로그가 안 보임 | [실제 수신 점검](docs/installation_reference.md#설치-후-실제-로그-확인), [통합 로그 조회 안내](docs/log_explorer.md) |
| 키를 삭제하거나 사용 중지하고 싶음 | [키 폐기 안내](docs/agent_key_management.md). 패키지 삭제와 키 폐기는 별개이며 이력은 보존 |

전체 오류 목록과 진단 명령은 [문제 해결 상세](docs/installation_reference.md#문제-해결)에 있습니다. 오류를 공유할 때 비밀번호·API 키·개인키·실제 로그 본문은 보내지 마세요.

## 수집 범위와 현재 한계

- Windows 활성 지원 이벤트 채널과 표준 로그 폴더, Ubuntu journald와 `/var/log`의 텍스트 로그를 자동 탐색합니다. **개인문서·키 파일·전체 디스크의 모든 파일을 수집하지 않습니다.** [수집 범위](deploy/agents/COLLECTION.md)
- 네트워크는 통신 흐름·DNS·TLS 메타데이터를 수집하며 원본 PCAP·HTTP 본문·쿠키는 저장하지 않습니다. [네트워크 안내](deploy/agents/NETWORK.md)
- AWS CloudTrail과 OCI Audit은 별도 설정·권한이 필요한 선택적 수집기입니다. [AWS](docs/aws_cloudtrail.md) / [OCI](docs/oci_audit.md)
- 신규 정규화 처리기는 별도 준비가 필요하고 탐지 규칙은 승인 대기입니다. 모든 이벤트 해석·자동 공격 판정·전체 자동 업그레이드는 제공하지 않습니다.

Windows 테스트 PC의 로그/품질 보고 수신과 VMware 화면 배포는 검증했습니다. Ubuntu·Packetbeat 통합 운영 시험 등 남은 검증은 [작업 목록](docs/work_tracker.md)에서 구분합니다.

## 개발자·운영자 안내

| 필요한 내용 | 문서 |
| --- | --- |
| 로컬 Python·Elasticsearch·화면 미리보기 | [개발환경](docs/local_development.md) |
| 수동 설치·상세 오류·테스트 명령 | [설치 상세 참고](docs/installation_reference.md) |
| 정규화·관제 구조와 사건 업무 | [처리 구조](docs/processing_operations.md) / [사건 조사](docs/incident_workflow.md) |
| 수집 보호·백업·실행 구조 | [수집 보호](docs/collection_protection.md) / [포털 백업](docs/portal_backup.md) / [Windows Discovery](docs/windows_native_discovery.md) |
| 구현·배포·실제 검증 이력 | [우선순위별 작업 목록](docs/work_tracker.md) |

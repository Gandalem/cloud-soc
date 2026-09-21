# 네트워크 보안 수집 설치 가이드

## 수집 범위

기존 Filebeat(OS 로그) 옆에 **Packetbeat 9.5.2를 별도 서비스로 설치**합니다. 패킷을 메모리에서 분석하고 허용된 통신 메타데이터만 Elasticsearch의 `soc-network-*`로 전송합니다. 실제 설치 명령은 선택한 인터페이스의 상시 수집을 시작하므로, 관리 권한과 수집 승인을 받은 서버에서 실행합니다.

| 항목 | 저장하는 정보 | 제한 |
| --- | --- | --- |
| 네트워크 흐름 | 양쪽 IP·포트·MAC, TCP/UDP 등 전송 프로토콜, 패킷 수·바이트 수, 시작·종료·지속 시간, 흐름 ID | 지원되는 패킷에서 분석 가능한 흐름. 패킷 원문/개별 패킷 목록 아님 |
| DNS | 질의 도메인·타입, 응답 코드, 해석된 IP | 기본 TCP/UDP 53. TXT 응답 본문·원문·추가 레코드 제외 |
| TLS | 관찰 가능한 서버명(SNI), 버전·암호군, 연결 상태 | 443/465/636/853/993/995/8443/8883/9243. 복호화·인증서 원문 저장 없음 |
| HTTP·SSH·DB 등 | 해당 연결의 IP·포트·통신량 | 요청 URL·쿠키·본문·명령·SQL 등 응용 내용은 수집하지 않음 |

**원본 PCAP 저장은 구현하지 않았습니다.** `packetbeat.interfaces.type: pcap`은 Windows 캡처 방식 이름이며 PCAP 파일 저장을 뜻하지 않습니다. 처리 전에 원본 패킷은 메모리에 들어오므로 수집기 관리자 권한·메모리 덤프 접근도 보호해야 합니다. DNS 이름·IP·SNI 자체에도 민감정보가 포함될 수 있습니다.

`packetbeat.base.json`의 마지막 `include_fields` 프로세서가 공통 전송 허용 목록입니다. 새 프로토콜 추가 시 이 목록과 `network-index-template.json`을 함께 검토합니다. 운영 환경에서 디버그 로깅이나 `--dump` 옵션을 켜지 않습니다.

## 중앙 서버 준비

1. 기존 원격 로그 설치와 동일하게 HTTPS Elasticsearch·일치하는 인증서 SAN·신뢰 CA를 준비합니다. HTTP·인증 비활성 개발용 Compose를 외부에 공개하지 않습니다.
2. 관리자가 `network-index-template.json` 본문을 `PUT /_index_template/cloud-soc-network`에 등록합니다. 설치기는 템플릿·수명 주기 정책을 변경하지 않습니다. 단일 노드 개발환경에서는 복제본 1개 때문에 yellow가 될 수 있으며 관리자가 환경에 맞게 조정합니다.
3. `network-publisher-role.json`을 역할 설명자로 사용하는 **서버별 별도 API 키**를 발급합니다. `soc-network-*`에만 `auto_configure`·`create_doc`, 클러스터 `monitor` 권한이 필요합니다. 기존 `soc-host-raw-*` 전용 키는 네트워크 인덱스에 쓸 수 없습니다.
4. 인덱스 보존 기간·삭제 정책·디스크 경보를 관리자가 설정합니다. 일별 인덱스 생성은 자동 삭제를 의미하지 않습니다. 로컬 큐 최대 1GB도 중앙 저장량 제한이 아닙니다.
5. 검토한 `deploy/agents` 폴더와 CA 공개 인증서를 서버에 전달합니다. 설치기 옆에 `packetbeat.base.json`이 반드시 있어야 합니다.

API 키는 설치 중 keystore 프롬프트에 `id:api_key` 형식으로 입력합니다. `encoded` 값이 아닙니다. 키를 명령 인자·설정 파일·Git에 넣지 않습니다. `organization.id`는 분류 정보이지 조직 간 접근 제어가 아닙니다.

## Ubuntu 22.04 설치

지원: Ubuntu 22.04 + systemd, x86_64/ARM64. 필수 도구: Bash, curl, tar, sha512sum, systemctl, pgrep, timeout, sed. `af_packet` 방식을 사용합니다. 필요한 라이브러리가 없는 환경에서는 공식 설치 문서의 `libpcap0.8` 등 사전 조건을 관리자가 확인합니다.

먼저 `ip -brief link`로 수집할 인터페이스를 확인합니다. 아래 `ens3`과 예시 서버 주소·CA 경로는 실제 환경으로 바꿉니다.

```bash
sudo bash deploy/agents/install-network-ubuntu.sh --endpoint https://soc.example.invalid:9200 --ca /etc/cloud-soc-ca.crt --organization school --interface ens3
```

명령 끝에 `--dry-run`을 붙이면 관리자 권한 없이 설정만 출력하고, 다운로드·파일 생성·실제 인터페이스 접근·캡처·네트워크 전송을 하지 않습니다. 모든 **로컬** 인터페이스가 의도한 범위라면 `--interface any`를 명시할 수 있습니다. 브리지·가상 NIC·루프백의 동일 트래픽 중복 관찰 가능성을 검토하세요.

설치 위치: `/opt/cloud-soc-network`. 서비스: `cloud-soc-packetbeat`. 기존 `/opt/cloud-soc-agent`와 Filebeat 서비스는 변경하지 않습니다. root로 실행하되 systemd capability 범위를 `CAP_NET_RAW`, `CAP_NET_ADMIN`으로 제한하고 설정은 읽기 전용, data/logs만 쓰도록 구성합니다.

## Windows 설치

지원: x86_64 Windows, 64비트 관리자 PowerShell. 기존 실행 정책을 따르며 우회하지 않습니다. **승인된 x64 Npcap을 먼저 설치**하고 필요 시 공식 안내의 WinPcap API 호환 옵션을 확인합니다. Npcap 라이선스·배포 조건은 별도 검토합니다. 이 설치기는 Npcap 설치·시작·업그레이드를 수행하지 않습니다.

수집 NIC의 GUID를 확인합니다. 인덱스 번호 대신 GUID를 저장하여 NIC 나열 순서 변경으로 수집 대상이 바뀌는 것을 방지합니다.

```powershell
Get-NetAdapter -IncludeHidden | Select-Object Name, Status, InterfaceGuid
```

실제 GUID를 중괄호 없이 입력합니다. 아래 GUID는 실행 예시입니다.

```powershell
.\deploy\agents\install-network-windows.ps1 -Endpoint https://soc.example.invalid:9200 -CaPath C:\certs\cloud-soc-ca.crt -Organization school -InterfaceGuid 11111111-2222-3333-4444-555555555555
```

`-DryRun`을 붙이면 Npcap·NIC에도 접근하지 않고 설정만 출력합니다. 실제 설치는 Npcap 서비스가 실행 중인지, 실제 DLL 버전이 Npcap인지, 선택 NIC가 Up인지 확인합니다. NIC **한 개**를 명시적으로 선택하며 다른 NIC·루프백까지 모두 수집한다고 가정하지 않습니다.

설치 위치: `%ProgramFiles%\Cloud-SOC-Network`. 서비스: `cloud-soc-packetbeat` (LocalSystem, `npcap` 의존). 설정·keystore·큐·로그는 SYSTEM과 Administrators만 접근하도록 ACL을 제한합니다.

**Npcap 유지보수 주의:** upstream의 `never_install: true`는 Npcap이 아예 없으면 자동 설치를 완전히 막는 옵션이 아닙니다. 그래서 설치 전에 실제 DLL을 검증하고 서비스 의존성을 지정합니다. Npcap을 제거·변경할 때는 먼저 Packetbeat 서비스를 중지·비활성화하고, 승인된 Npcap을 복구·검증한 뒤 재시작합니다. DLL을 삭제한 채 Packetbeat 실행 파일을 직접 실행하지 않습니다.

## 설치 후 확인

```bash
sudo systemctl status cloud-soc-packetbeat --no-pager
sudo journalctl -u cloud-soc-packetbeat -n 30 --no-pager
```

```powershell
Get-Service cloud-soc-packetbeat, npcap
Get-ChildItem "$env:ProgramFiles\Cloud-SOC-Network\logs"
```

서비스 활성 상태 및 `test output` 성공은 **실제 문서 저장 성공이 아닙니다.** Kibana에서 `soc-network-*`, 시간 필드 `@timestamp`로 Data View를 만들고, 승인된 테스트 통신에 대해 다음을 확인합니다.

- `host.name`, `organization.id`, `labels.log_source: network_packetbeat`가 기대한 센서와 조직인지 확인합니다. `host.*`는 통신 상대가 아니라 수집 서버 정보입니다.
- `event.dataset: flow`에서 `source.ip`, `destination.ip`, 양쪽 포트, `network.bytes`, `network.packets`, `flow.final`을 확인합니다. 프로토콜 이벤트는 `type: dns` 또는 `type: tls`로 찾을 수 있습니다.
- 알려진 평문 DNS 질의와 TLS 연결을 테스트하고 원본 시각·IP와 대조합니다. 요청 본문·쿠키·DNS TXT 응답·PCAP 파일이 저장되지 않는지도 확인합니다.
- 설치기 로그의 에러, Elasticsearch 색인 거부, 큐 증가, CPU·메모리·디스크 사용량, 캡처 드롭을 관찰합니다. Windows 드라이버 및 Linux 캡처 통계 도구도 필요할 수 있습니다.

흐름은 10초마다 **누적값**을 보고하고 30초 동안 패킷이 없으면 종료 보고합니다. 중간값과 최종값을 모두 합산하면 통신량이 중복 계산됩니다. 완료된 흐름 통계는 `event.dataset: flow AND flow.final: true`를 사용합니다. 장기 연결의 실시간 통계는 센서·흐름·시작 시각별 최신값/차분을 처리해야 하며, 전체 문서 수를 연결 수로 표시하면 안 됩니다. DNS/TLS 이벤트의 통신량도 흐름 통계와 중복 합산하지 않습니다.

새 설치만 지원하며 기존 Packetbeat·Elastic Agent·부분 설치 흔적이 있으면 중단합니다. 실패 시 이번에 만든 서비스만 중지·비활성화하고 보호된 설정·큐는 보존합니다. 설치기를 다시 실행하여 자동 덮어쓰기하지 않습니다.

## 가시성 및 프로젝트 경계

- 선택 NIC에 보이는 트래픽만 수집합니다. 서버 한 대 설치로 전체 VPC/클라우드·다른 서버·컨테이너 네임스페이스가 보이는 것은 아닙니다. 별도 센서나 승인된 미러링, 클라우드 Flow Logs 연동은 후속 작업입니다.
- 흐름 수집은 DNS/TLS 포트만으로 제한하지 않습니다. 응용 분석은 위 포트에서 지원되는 평문 DNS·TLS로 한정됩니다. DoH/DoT/QUIC 내부 DNS, HTTPS 본문, ECH로 숨겨진 이름 등은 읽을 수 없습니다.
- TLS 인증서 원문을 저장하지 않으므로 인증서 상세 조사 기능도 이번 범위가 아닙니다. 패킷 손실·암호화·비표준 포트·오프로딩 등에 따라 일부 정보가 없을 수 있습니다. 모든 패킷의 무손실 수집을 보장하지 않습니다.
- 센서끼리 동일 연결을 양쪽에서 관찰할 수 있습니다. `agent.id`, `network.community_id`, 시간으로 조사하고, 중복 제거 없이 조직 전체 통신량을 합산하지 않습니다. 중앙 수신 서버로 향하는 수집기 자체 HTTPS 통신도 흐름으로 관찰됩니다.
- 네트워크가 끊겨 큐가 가득 차거나 프로세스가 중단되면 패킷을 원본 로그처럼 다시 읽을 수 없습니다. 로컬 디스크 큐는 이미 생성된 이벤트를 완충할 뿐, 무손실 캡처나 종료 직전 모든 이벤트 배출을 보장하지 않습니다.
- 기존 SSH 탐지 파이프라인은 `raw-logs-*`를 사용합니다. `soc-network-*`는 아직 자동으로 탐지 규칙이나 `security-alerts`에 연결되지 않습니다. 정적 대시보드도 실데이터 화면으로 변경하지 않았습니다. 현재 조회는 Kibana Discover로 검증하고, 이후 상관분석·조회 API·네트워크 UI를 연결합니다.

## 개발 테스트

```powershell
node --test deploy/agents/tests/network.test.cjs
```

구문·설정·HTTPS 입력·인터페이스 검증·기존 설치 보호·Npcap 누락·오류 종료·ACL·허용 필드/매핑·권한 분리를 오프라인으로 검사합니다. Windows 테스트는 Git Bash와 PowerShell 7이 필요하며 PowerShell 5.1 구문도 검사합니다. 드라이버나 서비스를 설치하지 않습니다.

SHA-512 검증을 마친 공식 Packetbeat 실행 파일과 기존 Npcap이 있는 Windows에서는 다음 합성 패킷 테스트를 선택적으로 실행합니다.

```powershell
node deploy/agents/tests/validate-packetbeat.cjs 'D:\검증용경로\packetbeat.exe'
```

문서용 IP 대역의 패킷 파일을 **코드로 생성**하고 `-I`로 재생합니다. 실시간 NIC 대신 존재하지 않는 장치명을 설정하고, Elasticsearch 출력은 제거하여 콘솔에만 기록합니다. 종료 시 비동기 출력을 기다리는 upstream 테스트용 `packetbeat.publish_timeout`은 이 테스트에만 적용합니다. HTTP 쿠키·URL/본문과 DNS TXT에 삽입한 테스트 문자열이 전송 이벤트에서 빠지는지 검사합니다. 생성된 합성 PCAP·출력·진단은 Git에서 제외된 `state/packetbeat-smoke-*`에만 남습니다. 이는 제품의 PCAP 보관 기능이 아닙니다.

Windows 공식 9.5.2에서 DNS·TLS 이벤트 포함 8건, 최종 흐름 5건 및 민감 문자열 제외를 확인했습니다. Ubuntu 실제 systemd, Windows 서비스/재부팅, 원격 CA/API 키 및 Elasticsearch 색인은 배포 환경에서 별도 검증해야 합니다.

## 공식 근거

- [Packetbeat 설치](https://www.elastic.co/docs/reference/beats/packetbeat/packetbeat-installation-configuration)
- [캡처 인터페이스·Npcap](https://www.elastic.co/docs/reference/beats/packetbeat/configuration-interfaces)
- [흐름과 누적 통계](https://www.elastic.co/docs/reference/beats/packetbeat/configuration-flows)
- [TLS 분석과 복호화 제한](https://www.elastic.co/docs/reference/beats/packetbeat/configuration-tls)
- [PCAP 오프라인 재생 명령](https://www.elastic.co/docs/reference/beats/packetbeat/command-line-options)
- [9.5.2 Npcap 설치 방지 조건](https://github.com/elastic/beats/blob/v9.5.2/packetbeat/beater/install_npcap.go)
- 고정 체크섬: [Linux x86_64](https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-9.5.2-linux-x86_64.tar.gz.sha512), [Linux ARM64](https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-9.5.2-linux-arm64.tar.gz.sha512), [Windows x86_64](https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-9.5.2-windows-x86_64.zip.sha512)

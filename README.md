# Cloud SOC

Windows·Ubuntu 로그를 중앙에 수집하고 경보의 근거 확인·사건 조사로 연결하는 Mini SIEM입니다. **Security Mall 없이 사용할 수 있습니다.** 일반 웹과 ModSecurity WAF는 사이트별 선택 수집이며 Mall 앱 감사는 별도 확장입니다.

범용 사이트·ModSecurity의 명시적 개발 프로필, 전환 시점·상태 보존, WSL 실제 요청 인수는 [운영 연결과 검증 기록](docs/operational_acceptance.md)을 확인하세요. 기존 배포의 활성 규칙은 자동 변경하지 않습니다.

처음 설치한다면 아래 순서로 진행하세요. 상세한 주소 예시·CA 등록·패키지 검증 명령은 [처음 설치 전체 안내](docs/first_install_walkthrough.md)에 보존했습니다.

## 1. 설치 전 준비

- 중앙 서버: 새 Ubuntu Server 22.04/24.04/26.04 LTS, systemd, amd64/arm64, sudo 권한.
- 자원: RAM 8GiB 이상 권장, 여유 디스크 10GiB 이상과 로그 저장 공간, 2 vCPU부터.
- 수집 대상: Windows 64비트 또는 Ubuntu 22.04/24.04. 네트워크 수집은 선택이며 Windows Npcap은 별도 준비합니다.
- 접속 주소: 관리자와 수집 대상이 실제 접속할 DNS/IP 및 서버 NIC에 실제 할당된 바인딩 IPv4.
- 방화벽: 443(Portal)·5601(Kibana)은 관리자 IP/VPN, 9200(수신)은 승인된 수집 대상/VPN에만 허용합니다. 설치기는 방화벽·클라우드 보안그룹을 자동 변경하지 않습니다.

`127.0.0.1`은 접속한 PC 자신입니다. 다른 PC에서는 실제 중앙 서버 주소를 사용하세요. AWS의 바인딩 주소는 공인 NAT 주소 대신 서버에 할당된 프라이빗 IPv4를 사용합니다.

## 2. Ubuntu 중앙 서버 최초 설치

**새 서버의 Ubuntu 터미널**에서 실행합니다. 기존 서버에는 최초 설치기를 다시 실행하지 마세요.

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
ip -4 -brief addr

# 10.0.0.10을 해당 서버의 실제 IPv4로 교체
sudo sh deploy/server/install-ubuntu.sh --host 10.0.0.10 --bind-ip 10.0.0.10
```

설치 중 Portal 관리자 비밀번호를 터미널의 보안 입력으로 설정합니다. 비밀번호·API 키를 명령 인자나 저장소에 넣지 마세요. DNS와 수집 주소를 다르게 사용하는 `--agent-host` 예시는 [설치 전체 안내](docs/first_install_walkthrough.md#3-2-중앙-서버-설치)를 참고하세요.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
```

Portal·Elasticsearch·Kibana·gateway와 필수 워커 상태를 확인합니다. 정상 종료한 bootstrap의 `Exited (0)`은 오류가 아닙니다. 기동 성공은 실제 에이전트 수신·탐지 완료를 의미하지 않습니다.

| 목적 | 접속 주소 | 인증 |
| --- | --- | --- |
| Portal | `https://중앙-서버-주소/` | admin / 설치 중 설정한 비밀번호 |
| Kibana | `https://중앙-서버-주소:5601` | cloud_soc_analyst / 생성된 분석가 비밀번호 |
| 에이전트 수신 | `https://수신-주소:9200` | 전용 수집 API Key |

사설 CA를 사용하면 공개 CA의 SHA256을 대조하고 브라우저에 신뢰 등록해야 합니다. [Windows CA 등록 명령](docs/first_install_walkthrough.md#3-4-windows-브라우저에-서버-인증서-신뢰-등록)을 사용하세요. TLS 검증을 끄거나 CA/서버 개인키를 에이전트에 전달하지 않습니다. 인증 없이 9200에 접속했을 때 HTTP 401은 정상입니다.

<a id="2-에이전트-설치"></a>

## 3. Portal에서 에이전트 패키지 생성

1. Portal에 로그인해 **에이전트 설치 파일 → 설치 파일 추가**를 엽니다.
2. OS·패키지 이름·조직·수집 항목을 선택합니다. 시스템 로그가 기본이며 웹 로그·네트워크는 선택입니다. 웹 수집에는 사이트와 로그 경로가 필요합니다.
3. ZIP(Windows) 또는 tar.gz(Ubuntu)을 받고 Portal의 SHA256과 대조합니다.
4. 대상별 로그 수집 키를 발급합니다. 네트워크 수집 키는 별도입니다. 키는 설치 도중 보안 프롬프트에 입력합니다.

패키지의 모든 파일을 같은 폴더에 풉니다. 바이너리는 설치 중 공식 배포처에서 다운로드·검증하므로 인터넷 접속이 필요합니다.

## 4. 수집할 장치에 설치

### Ubuntu

패키지를 대상 서버에 전달하고 아래 파일명을 실제 다운로드 파일명으로 바꿉니다.

```bash
PACKAGE="$HOME/설치파일명-setup.tar.gz"
sha256sum "$PACKAGE"
mkdir "$HOME/cloud-soc-agent-package"
tar -xzf "$PACKAGE" -C "$HOME/cloud-soc-agent-package"
cd "$HOME/cloud-soc-agent-package"
sha256sum -c SHA256SUMS
sudo bash install.sh
```

### Windows

다운로드한 ZIP의 SHA256을 대조하고 모든 파일을 푼 뒤 **관리자 PowerShell**에서 실행합니다.

```powershell
$package = Join-Path $env:USERPROFILE 'Downloads\실제패키지명-setup.zip'
Get-FileHash -LiteralPath $package -Algorithm SHA256
Expand-Archive -LiteralPath $package -DestinationPath 'C:\Cloud-SOC-Agent-Package'
Set-Location 'C:\Cloud-SOC-Agent-Package'
.\install.ps1
```

네트워크 수집을 선택한 경우 NIC·Npcap·추가 설치 인자는 [전체 설치 안내](docs/first_install_walkthrough.md#4-windowsubuntu-에이전트-설치)와 [네트워크 안내](deploy/agents/NETWORK.md)를 따릅니다. 기존 설치와 충돌하면 덮어쓰기 전에 [설치 복구](docs/windows_install_recovery.md)를 확인합니다.

<a id="7-설치-후-실제-로그-확인"></a>

## 5. 새 로그부터 첫 경보까지 확인

1. Portal **에이전트 수신 현황**에서 대상의 마지막 중앙 수신 시각을 확인합니다.
2. **통합 로그**에서 최근 기간·장치·조직을 선택하고 직접 생성한 승인된 시험 이벤트를 대조합니다.
3. **관제 상세 → 분석 상태 → 실제 워커의 규칙·버전 확인**에서 실행 보고·revision·마지막 성공·처리 위치를 확인합니다.
4. 새 최종 경보의 상세·정확한 원본/정규화 근거를 확인합니다. [독립 SOC 첫 경보 인수](docs/operational_acceptance.md)의 읽기 전용 검사로 저장 근거를 대조하고 실제 브라우저·Slack 채널 수신을 각각 기록합니다.

로그 재탐색은 약 1분이며 전송·정규화·탐지에는 추가 시간이 필요합니다. 초기 통지는 최종 경보와 다릅니다. 로그가 수집됐다고 모든 이벤트가 경보가 되지는 않습니다. 경보 0건은 위험 없음의 증명이 아닙니다.

## 6. 화면 사용

| 화면 | 주소 | 확인 내용 |
| --- | --- | --- |
| 홈 | `/index.html` | 최근 경보·수신·사건 요약 |
| 내 대시보드 | `/dashboard.html` | 개인 위젯·기간 |
| 통합 로그 | `/logs.html` | 수집 로그·보호된 상세 |
| 관제 상세 | `/operations.html` | 집계·규칙 실행 보고·경보 근거 |
| 사건 조사 | `/workbench.html` | 연결된 경보·조사·사건 |

홈은 최근 24시간, 관제 상세는 최근 1시간이 기본입니다. 과거 경보는 기간을 늘려 조회하세요. 경보는 공격 성공이나 WAF 차단 성공을 확정하지 않습니다.

## 7. 문제 해결·기존 설치

- 접속 실패: 주소·바인딩 IP·443/5601 허용 IP·CA 신뢰·컨테이너 상태를 확인합니다.
- 수신 없음: 대상에서 9200 도달·API Key 만료·CA·Filebeat 로그를 확인합니다.
- 설치 중단: 기존 state·큐·키를 보존하고 [설치 상세 참고](docs/installation_reference.md)와 [Windows 복구](docs/windows_install_recovery.md)를 확인합니다.
- 기존 중앙 서버는 [공통 업데이트·복구](docs/runtime_deployment.md), 기존 Windows는 [에이전트 갱신](docs/windows_discovery_update.md)을 따릅니다.

`state/server`와 에이전트 상태는 보호해야 합니다. 문제 해결을 위해 `docker compose down -v`로 저장 데이터를 삭제하지 마세요.

## 8. 선택 실습과 개발

Security Mall·ModSecurity WAF는 일반 SOC 설치에 포함되지 않습니다. 전용 계약·격리 인덱스·실험 결과는 [Mall 9-C](docs/security_mall_9c_predeployment.md), [WAF 탐지](docs/security_mall_waf_detection.md), [전용 Portal](docs/security_mall_portal.md)을 참고하세요. 별도 실험 성공을 새 중앙 서버의 상주 작동으로 해석하지 않습니다.

[로컬 개발](docs/local_development.md) · [중앙 서버 상세](deploy/server/README.md) · [전체 문서 색인](docs/README.md) · [작업 상태·남은 인수](docs/work_tracker.md)

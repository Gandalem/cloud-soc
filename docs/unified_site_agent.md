# 사이트 통합 에이전트

2026-10-14 기능 브랜치 개발 범위. Filebeat 한 개에서 시스템·웹 입력을 분리하고 선택한 경우에만 Packetbeat를 설치한다. 기존 DVWA 계약과 새 `web-access-agent-v1` 계약은 별도다. 기존 큐·키·registry·경보·사건·개인 화면 구성을 자동 교체하지 않는다.

## OS 지원

| OS | 설치 방식 | 이번 검증 범위 |
| --- | --- | --- |
| Ubuntu 22.04/24.04 · x86_64/ARM64 | 고정 SHA-512 Elastic tar.gz, Python 3·systemd·journald | 기존 VM 실제 수신, 신규 코드/격리 시험. 새 패키지 전체 설치 인수는 별도 |
| Amazon Linux 2023 · x86_64/ARM64 | 같은 Linux 설치기, amzn/2023·systemd 확인 | 실제 EC2 OS/기존 Apache 수신. 새 OS/네트워크 설치는 미인수 |
| Windows · x86_64 | Filebeat·독립 .NET 발견 프로그램, 선택 Packetbeat/Npcap | 실제 .NET 격리 발견/기존 회귀. 새 패키지 실계정 설치는 별도 |

IIS/W3C·사용자 정의 웹 JSON/CSV·컨테이너 파일 시스템 자동 탐색은 지원하지 않는다. 웹 수집은 공격 탐지나 모든 로그 해석 완료를 뜻하지 않는다. Windows 키 만료 확인은 이번 범위에서 제외한다.

## 설치 설정

관리자의 **에이전트 설치 파일 → 설치 파일 추가**에서 시스템·보안(기본 선택), 웹(선택), 네트워크(선택)를 고른다. 웹에는 사이트 이름·Apache/Nginx/Docker·절대 파일 경로·시작 범위를 입력한다. 화면은 사이트 하나, API는 최대 8개다. 중복 경로/ID·보호 경로·변수·와일드카드를 거부한다. 해시 확인과 기존 수동 키/설치 토큰 절차를 재사용한다. 네트워크에는 명시 NIC, Windows에는 승인된 Npcap이 필요하다. 미선택 패키지에 Packetbeat 설치 파일을 넣지 않는다.

Apache/Nginx는 표준 common/combined access 형식만 지원한다. Docker JSON은 `log` 안에 같은 형식이 있어야 한다. 컨테이너가 파일에만 쓰면 호스트에 연결된 access 파일을 Apache/Nginx로 선택한다. 기존 컨테이너를 자동 재시작하거나 마운트를 변경하지 않는다.

웹 로그 디렉터리는 웹을 꺼도 일반 탐색에서 제외한다. 회전 파일과 error 로그가 원문으로 다시 전송되는 것을 방지하므로 다른 서비스 로그는 별도 디렉터리에 둔다. 별도 Filebeat 인스턴스나 같은 파일의 두 입력을 만들지 않는다.

시작 시각은 고정 UTC 값으로 저장한다. 패키지 생성 시각 이후·최근 24시간/7일·직접 시각을 제공하며 재시작 때 시작점을 바꾸지 않는다. 이전 이벤트는 큐 전에 제외한다. 과거 범위는 현재 선택 파일에 남은 내용만 해당하고 압축/미선택 회전 파일·삭제 로그는 복구하지 않는다. 시스템 로그는 기존 발견/registry 동작을 유지한다.

## 개인정보와 근거

관측 peer IP·메서드·응답 상태·시각·사이트만 새 필드로 만든다. URL 전체·쿼리·쿠키·Authorization·referrer·user-agent·인증 사용자·POST 본문·알 수 없는 Docker 필드는 전송하지 않는다. 잘못된 형식/시각·초과 크기·처리 실패는 해당 이벤트를 취소하고 다른 입력/서비스를 중지하지 않는다. IP를 프록시 뒤 최종 사용자로 추정하지 않는다.

timestamp processor로 access 시각을 적용하고 정규화에는 버전·정확한 ES index/ID·호스트/에이전트·조직·사이트 참조를 유지한다. 원본 참조는 보호 메타데이터이며 비마스킹 Apache 원문이 아니다. 최초 생성에서 fingerprint 길이를 64바이트로 고정하며 이후 길이/입력 ID를 임의 변경하지 않는다. 전송 재시도·파일 삭제/회전 경쟁에 대한 절대 무중복·무손실은 보장하지 않는다.

## 개별 중지·재개

완료한 신규 통합 설치에서 다운로드 패키지의 제어 도구를 실행한다. `collection-profile.json` 원본/복구 해시는 유지하고 선택 값만 `collection-switches.json`에 저장한다. 사이트 경로·시작점·키·큐는 바꾸지 않는다. 시스템·웹은 동적 입력을 다시 읽어 Filebeat 재시작이 필요 없고 네트워크는 Packetbeat 서비스 하나만 대상으로 한다. 미설치 네트워크 기능을 자동 다운로드하지 않는다.

```bash
sudo python3 collection-controls.py system off
sudo python3 collection-controls.py web off --site <설정한-사이트-ID>
sudo python3 collection-controls.py network off
```

```powershell
.\collection-controls.ps1 -Kind system -Enabled off
.\collection-controls.ps1 -Kind web -Enabled off -Site '<설정한-사이트-ID>'
.\collection-controls.ps1 -Kind network -Enabled off
```

`off`를 `on`으로 바꾸어 재개한다. 기존 설치에 신규 설치기를 다시 실행하지 않는다. 기존 정상 설치의 범용 전환/자동 업그레이드는 별도 범위다. 구성 변경은 한 번에 하나씩 실행하고 실패 시 실제 구성·발견 결과·중앙 수신을 확인한다.

## 대시보드

**최근 웹 사이트 접근**은 웹 전용 서버 검색으로 최대 50건을 조회해 시스템 물량에 가려지지 않는다. 기존 DVWA와 새 범용 기록을 함께 표시한다. **수집 항목별 상태**는 관리자용 선택 위젯으로 최근 보고한 최대 10개 설치 표본을 구분한다. 기존 홈·사용자 저장 구성을 자동 변경하지 않는다.

정상 수신·미설정(최근 비활성 보고)·오류(명시 접근/발견 오류)·지연·데이터 없음(활성이나 문서 부재)을 구분한다. 개별 보고/호스트 참조가 없는 이전 설치는 상태 미확인으로 남긴다. 보고는 에이전트 자체 보고이며 검증된 heartbeat가 아니다. 미수신/경보 0건을 오프라인·안전으로 판단하지 않는다. 상태 API는 관리자 전용이고 웹 검색은 기존 조직/역할을 유지한다.

## AWS 안전한 경로

사용자 확인으로 실제 대상은 AWS `56.155.117.55` → VMware `192.168.235.128`다. 처음 지정한 `13.208.175.237`/`192.168.32.60` 연결은 timeout이며 이번 실수신으로 기록하지 않는다. 사설 중앙에 직접 연결되지 않으면 일반 Filebeat/Packetbeat 패키지를 성공으로 표시하지 않는다.

기존 DVWA는 고정 지문·출발지 제한·forced command·목적 전용 키의 중앙 SSH pull로 보호 메타데이터만 가져온다. 이를 시스템/네트워크 원문 전송으로 임의 확장하지 않는다. 범용 AWS 설치에는 승인된 사설 VPN/라우팅 또는 별도로 승인한 제한 경로가 필요하다. 공개 9200/새 포트·IAM/과금 자원을 만들지 않았다.

구성 근거: [Elastic script](https://www.elastic.co/guide/en/beats/filebeat/current/processor-script.html), [timestamp](https://www.elastic.co/guide/en/beats/filebeat/current/processor-timestamp.html), [파일 식별](https://www.elastic.co/docs/reference/beats/filebeat/file-identity). 실제 검증·제한은 [작업 목록](work_tracker.md)에 단계별 기록한다.

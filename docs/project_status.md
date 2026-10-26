# 현재 구현과 검증 상태

기준: 2026-10-26, Gandalem/cloud-soc `main ac64198`, 설치 기능 커밋 e4a3d65/08a99c3와 후속 CI 수정50ebce9. **사용 안내는 [문서 색인](README.md), 작업 승인/완료 이력은 [작업 목록](work_tracker.md)**을 따른다. 여기서 작업 순서나 실제 운영 상태를 새로 확정하지 않는다.

## 읽는 기준

코드 구현, 격리 검사, 실제 OS 설치, 실제 웹 요청, 상주 worker, 재부팅, Slack 수신, 운영 서명 배포는 별도 근거다. 나중의 **같은 환경/범위** 결과가 이전 실패·대기를 갱신하며 날짜가 새롭다는 이유만으로 다른 환경의 결과를 덮어쓰지 않는다. 부모 미체크는 완료된 하위 검증을 취소하지 않는다.10/12의 완료율/우선순위를 현재 제품 상태로 재사용하지 않는다.

## 확인된 완료 기록

| 날짜/환경 | 기록된 결과 | 근거/제한 |
| --- | --- | --- |
|10/01·08 기존 Windows VM | Repair/Resume·장애/강제 종료 뒤 키/큐 보존·새 수신, 재부팅 후 Filebeat/Packetbeat/Discovery 자동 시작 | [Windows 운영](windows_agents.md#verification). 새 native의 모든 복구 경계 인수는 아님 |
|10/04 양 OS 시험 VM | 로그/통합 토큰 설치·실제 수신, ES 중단 후 실패 키 폐기·동일 수집기 ID 새 토큰 재등록 | [P0C-03 결과](archive/README.md#record-docs-archive-validation-p0c03-validation-20261004-md). 정상 설치 키 자동 교체와 별도 |
|10/07~08 실장치 | Discovery의 수집기 통계/상태→ES/API→화면 수치 대조 | [계측](p2_collection_metrics.md). 별도 인증 dashboard heartbeat와 같은 경로는 아님 |
|10/14 집 서버 | 실제 SSH 실패10회→미러20/고유10→AUTH-001 경보1·근거10·HTTPS/PC·모바일, worker6 재시작/재업그레이드·키/상태 보존 | [런타임 인수](archive/README.md#record-docs-runtime-parity-validation-20261014-md). 선택7규칙 전부의 새 실공격·다른 중앙 배포를 뜻하지 않음 |
|10/14~15 집 서버 Slack | 관리자 웹 설정·시험 메시지와 신규 AUTH 경보의 실제 채널 수신 사용자 확인, 같은 ID·attempt1·중복0, 링크 로그인/상세 복귀 | 작업 목록 SLACK-LIVE-01/SLACK-MSG-02/SLACK-LINK-01. 모든 신규 규칙의 채널 인수는 아님 |
|10/19 WSL TLS ES | 실제 Nginx2사이트 요청/분리 경보2, ModSecurity/CRS DetectionOnly와On의 실제 SQLi·각 경보1, Chromium·근거 | [범용 SOC 인수](operational_acceptance.md#2026-10-19-wsl-검증-결과). 기존 중앙 배포/호스트 설치기/Slack 수신은 별도 |
|10/20 실습 VM | 폼 규칙 생성·적용, 실제 로그인2건 음성/3건 양성·401·SQLi, Filebeat/TLS ES·Portal 근거·규칙 삭제 후 경보 증가0 | [규칙 작성](rule_authoring.md#2026-10-20-후속-실제-실습-인수). 첫 임시 시험 후 다음 행의 상주 결과가 추가됨 |
|10/20 같은 실습 VM |9서비스 상주·AJAX 입력 보존·실제 soft reboot 후 자동 복구·ID/체크포인트 유지·새 요청 탐지 | [상시 실행](live_ajax_runtime.md#2026-10-20-실제-인수-결과).16.847초 단일 측정은 SLA/장기 무손실 아님 |
|10/21 Ubuntu24.04 WSL | 중앙12서비스·ES/Kibana healthy·CA/이름/관리자 인증, 보존 제거→purge/이미지 제거→재실행·전용 자원0·기존 Nginx 보존 | 작업 목록 INSTALL-FRESH-01. 빈 OS Docker APT/캐시 없는 다운로드·Docker 자체 제거·이후 새 메뉴 인수와 별도 |
|10/23 실제 ES/Filebeat | 새 관리 장치 발급·같은 요청 재시도·receipt와 일반 수신 분리·정확 참조·권한403/폐기401·원본 보존 | [장치 검증](device_installation.md#검증-이력). 컨테이너 결과만으로 OS/경보 전체 완료 아님 |
|10/25 Ubuntu24.04 WSL | 제품 설치/receipt·합성 WAF 정규화/경보·근거·stop/start·보존 제거/키 폐기 | [장치 검증](device_installation.md#검증-이력). 실제 DEB 패키지·일반 VM 부팅·실제 웹 공격은 별도 |
|10/25 Windows10 VM | Restricted 그대로 제품 native EXE 설치·service/COM/ACL/DPAPI·receipt·합성 WAF 경보/근거·보존 제거/purge·키 폐기·TLS6경계 | [장치 검증](device_installation.md#검증-이력). unsigned lab·CLI 엔진 결과이며 운영 서명/GUI/모든 중단/부팅/network 인수 아님 |
|10/26 Git/CI | PR20 main 병합17a32c4, 코드50ebce9의 Actions40204762899 Ubuntu/Windows 성공, 기록ac64198 | 운영 이미지/장치 자동 배포를 뜻하지 않음 |

10/19~20은 실제 HTTP/SQLi 요청,10/25는 파일에 넣은 합성 WAF 입력이다. 서로의 성공을 취소하거나 둘을 모두 실공격/합성으로 묶지 않는다.

## 이미 구현된 연결

- 설치 proof·일반 로그 수신·서비스 보고·분석/경보를 구분한다. managed activity는 정확한 agent/org/enrollment/key·final pipeline을 확인하고 probe를 제외한 event.ingested/원본 참조를 조회한다.10/23 실제 ES 검사에서 분리했다.
- 지속 heartbeat는 tools/device_heartbeat.py의 SCM/systemctl 관측·15~300초 HTTPS 반복/실패 후 재전송, insight_state의 인증·신선도 저장, dashboard-insights.js의 보고 중/지연/두절·collector 상태 표시까지 구현돼 있다. 특정 managed API의 unknown을 전체 heartbeat 미구현으로 해석하지 않는다.
- 키 폐기·미사용 등록 정보 갱신, 확인된 실패 설치의 새 토큰 재등록, 기존 Windows Repair/Resume는 구현/기록돼 있다. 아래 정상 설치의 수집 키 교체·제거 후 복원과 범위가 다르다.
- EXE sign/verify·Portal release mount/SHA pin, DEB 빌드, 서버 soc 메뉴는 구현돼 있다. 산출물/추가 실제 인수 증거와 기능 부재를 구분한다.

<a id="implementation-gaps"></a>
## 확인된 제한과 구현 공백

| 범위 | 코드에서 확인한 제한 | 이미 있는 범위/정책 |
| --- | --- | --- |
| 정상 등록 장치의 수집 키 교체 | device_management.prepare는 issued/complete를409로 거부하고 managed 수동 키 발급도 금지. 로컬 keystore 교체/구키 종료의 통합 절차 없음 | 미사용 토큰 갱신·실패 재등록·별도 heartbeat credential rotate는 있음 |
| 제거 완료 뒤 재설치/큐 복원 | agent-manager.py의 removed는 install/start 거부. native도 removed/purged를 설치 재개 단계에 포함하지 않음 | 일부 설치 단계·제거 재시도와 기존 Repair/Resume는 있음 |
| Windows manager 완전 제거 | purge 뒤에도 ProgramData의 관리 EXE·상태/감사 보존. GUI는 보존 제거만 제공 | 수집기/큐 purge는 있음. 보존 정책 변경을 무조건 필수 버그 수정으로 단정하지 않음 |
| 종료 이력/한도 | ended 포함 managed_devices 전체200개와 packages200개 한도. managed 패키지 일반 삭제 차단, 한도 회수 절차 없음 | 종료·폐기·이력 조회는 있음. 감사 보관/참조 보존 정책을 먼저 정해야 함 |
| 새 native Windows network | require_scope와 native 계약에서 network=true 거부 | 시스템/웹 지원, 기존 고급 Packetbeat/Npcap 경로와 별도 |

근거 소스: src/cloud_soc/portal/{device_management.py,packages.py,windows_native.py,app.py}, deploy/agents/agent-manager.py, deploy/agents/native/{Installer.cs,Program.cs}.10/26 소스 읽기/원격 refs 확인 결과이며 해당 실패를 실장치에서 새로 재현한 결과가 아니다.

## 배포와 추가 인수

| 트랙 | 남은 것으로 기록된 범위 | 확대하지 않는 해석 |
| --- | --- | --- |
| 설치 릴리스 | 운영 서명 EXE 공급·Portal 연결/조직 정책, 실제 DEB 설치/제거, 새 soc 메뉴 별도 실제 인수 | 빌드/서명·메뉴 코드 부재가 아님. 기존 설치/경보/제거 재검증을 통째로 요구하지 않음 |
| native 운영 | manager 자체 제거/보존 큐 재설치, commit 중단 지점·GUI/OS 매트릭스·대규모 배포 | 기존 Windows 복구 전체가 없는 것이 아님 |
| 대시보드 추가 연결 | 정확한 원본·장치 원장 결합·평가/GeoIP/계정/실제 cloud의 명시 후속 | 기본 경보 상세·일반 로그 수신 구분·지속 heartbeat는 이미 있음 |
| 위젯 위치 이동 | 구현·실습 정적 반영 뒤 사용자 지시로 검수 생략 | 자동 재검증/브라우저 실행 허가 아님 |
| 상시 운영 | 선택 규칙 실제 유지·지속 지연/적체·키 만료/Portal guard·PC 터널 자동 연결 | 실제 재부팅/신규 요청 경보 기록은 이미 있음 |
| 클라우드/규칙 | CloudTrail/OCI의 실제 인증·수신, 공급자별 인수·모든 규칙 정상/경계/양성 | EC2 웹 수집을 CloudTrail 인수로 세지 않음 |
| 백업/DR | 독립 저장소·호스트 손실/실제 RPO/RTO·장기 무손실 | SQLite 보호 백업·격리 snapshot/복원은 이미 있음. 기존 사용자 보류 유지 |

각 트랙의 기존 계획은 [설치](device_installation.md#남은-범위), [대시보드](dashboard_capabilities.md#후속-연결-계획--2026-10-21), [상시 운영](live_ajax_runtime.md), [독립 백업](p2_capacity_backup.md)에 있다. 하나의 최신 승인된 전체 순위는 아니다. 소스 검토자의 제안과 사용자 승인 우선순위를 구분한다.

## 환경과 증거의 경계

집 서버의 보호 업그레이드와 같은 VM의 /home/kopo/soc-mall-lab은 별도 인덱스/상태/키/Portal이다. 다른 중앙 VM의10/21~22 설치/ngrok 기록은 별도이며10/14 접속 불가가 영구 현재 상태라는 뜻은 아니다. 새 AWS 웹 서버의10/22 마지막 기록은 사이트 배포/수집 통로 TLS 준비까지이고 agent_installed=false·실키 인증/수신 미검증이었다. 그 뒤 사용자 수동 설치 여부나 현재 접속 상태를 문서로 단정하지 않는다.

현재 체크아웃의 state/install-verification-20261021/result.json과 state/security-mall-aws-20261022/agent-connection.json 공개 필드는 대조했다.10/19~25 일부 원본은 다른 체크아웃/VM 기록이며 여기에는 없다. 파일 부재를 시험 미수행으로 바꾸거나 문서 대조를 새 실서버 검증으로 주장하지 않는다.

10/26 문서 대조는 당시 Git 추적141파일(MD131/TXT10)·17,467행을 전체 검색하고 핵심 보고서를 정밀 비교했다. 원래 목록/해시/추출 문구는 Git 제외 state/document-audit-20261026에 남겨 본문에141파일 표를 중복하지 않는다. 다른 원격 브랜치의 추가9문서도 관련 문구를 검색했으며, 주로 AWS 수집·중앙 복원/장애 기록으로 위 정상 설치 수명주기 완료를 추가 입증하지 않았다. 별도 상용화 저장소/개인 미추적 자료를 합치지 않았다.

## 통합 전 문서와 현재 위치

| 이전 문서 | 현재 위치 |
| --- | --- |
| install_device_experience.md / install_device_os_validation.md / windows_native_installer.md | [장치 설치와 배포](device_installation.md) |
| agent_enrollment.md / agent_key_management.md / agent_status.md | [에이전트 운영](agent_management.md) |
| windows_install_recovery.md / windows_discovery_update.md / windows_native_discovery.md | [기존 Windows 운영](windows_agents.md) |
| verification_status_audit_20261026.md / implementation_gap_audit_20261026.md | 이 문서 |

초기 NSIS/PS 설치 실패는10/25 후속 native 성공으로 갱신했다. 기존 Windows Repair/Resume/등록 미지원의 오래된 표도 후속 성공을 반영했다. 과거 실패·취소·경계와 상세 해시/완료 이력은 work_tracker/work_history 및 날짜별 검증 기록에 보존한다. 통합 전 작업 사본은 Git 제외 state/document-consolidation-20261026/original에 있다.

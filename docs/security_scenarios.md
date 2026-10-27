# 추가 보안 시나리오 9종

## 작성 범위

서버 인증·HTTP 401/403·Packetbeat Flow 외에 환경별 3종을 추가한다. 각 규칙은 15분 구간의 조건에 맞는 고유 원본 관측 3건 이상을 집계하고 15분 재발행 억제를 적용한다. 최소 3건은 수집 상한이 아니다. 정상 활동도 집계될 수 있으며 경보는 침해 성공 판정이 아니다.

수집 경로는 실제 로그 생산자의 구조화 감사 내보내기 → 메타데이터 수집 명령 → NDJSON 스풀 → 별도 Filebeat → 기존 중앙 원본/정규화/탐지 워커다. 새 코드는 임의의 Windows EVTX·Linux audit 원문·벤더 방화벽 텍스트를 자동 해석하지 않는다. 기존 제품의 감사 내보내기나 변환기는 아래 형식으로 실제 관측 메타데이터를 제공해야 한다. 해당 생산자 연결·감사 정책·보안장비 설치를 이번 코드 작성만으로 완료한 것으로 간주하지 않는다.

## 규칙과 입력

| 규칙 ID | kind | 실제 생산자 연결 대상 | 필수 메타데이터와 분석 조건 |
| --- | --- | --- | --- |
| SCENARIO-SERVER-FILE-001 | server_file | Windows 파일 감사 / Linux auditd 내보내기 | object_path, actor, critical_asset. 중요 자산 true인 변경·삭제·권한 변경 |
| SCENARIO-SERVER-PERSIST-001 | server_persistence | 서비스 관리자 / 작업 스케줄러 / systemd·cron 감사 | object_name, object_type, actor. 서비스·예약 작업 생성 또는 변경 |
| SCENARIO-SERVER-DEFENSE-001 | server_defense | Defender / auditd / 보안 정책 감사 | object_name, actor. 중지·비활성화·정책 변경 |
| SCENARIO-APP-ROLE-001 | app_role | 앱 권한 관리 감사 | actor, target_user, role_before, role_after. 권한 부여·회수·변경 |
| SCENARIO-APP-EXPORT-001 | app_export | 앱 데이터 조회·내보내기 감사 | actor, resource_type, record_count. 작업당 1,000건 이상 조회·내보내기·다운로드 |
| SCENARIO-APP-UPLOAD-001 | app_upload | 앱 업로드 감사 / 파일 검사 결과 | actor, object_name, risk_reason. 실행 가능 확장자·MIME 불일치·악성 판정 중 명시된 근거 |
| SCENARIO-NET-DNS-001 | network_dns | DNS 서버 / 리졸버 질의 감사 | source_ip, dns_name, dns_rcode. NXDOMAIN 3건 이상; 이름 길이도 계산해 근거 제공 |
| SCENARIO-NET-FIREWALL-001 | network_firewall | 방화벽 / 클라우드 보안장비 감사 | source_ip, destination_ip, destination_port. 거부·드롭·차단 3건 이상 |
| SCENARIO-NET-IDS-001 | network_ids | Suricata / Snort 경보 내보내기 | source_ip, destination_ip, signature_id, signature_name. 경보 3건 이상 |

앱 규칙은 조직·호스트·서비스 단위로 집계한다. 서버는 조직·호스트, 네트워크는 조직·센서 호스트·관측 출발지 단위다. 중앙 네트워크 센서의 host.id는 센서 자체를 의미하며 목적지 서버 ID로 바꿔 추정하지 않는다. 역할 변경은 관리자뿐 아니라 일반 역할도 포함한다. 대량 조회 임계값은 각 작업에 적용하며 구간 내 처리 건수의 합계를 계산하는 규칙은 아니다. DNS 장문 질의 자체의 경보와 정상 기준선 기반 탐지는 추가하지 않았다.

## 입력 계약

감사 내보내기 입력은 한 줄당 JSON 객체다. 최상위 `timestamp`에 시간대가 포함된 실제 발생 시각, `security_scenario`에 아래 메타데이터를 넣는다. 조직·호스트·앱 서비스는 수집 명령의 설정에서만 부여한다. 입력 문서의 조직·호스트·다른 최상위 필드는 결과에 복사하지 않는다.

- `schema`: `security-scenarios-v1`.
- `kind`: 위 표의 9가지 값 중 하나.
- `action`: 아래 표의 kind별 허용 값.
- `outcome`: `success`, `failure`, `unknown`; 생략 시 `unknown`.
- 문자열 메타데이터: 위 필수 필드 및 선택 `transport`, `source_ip`, `destination_ip` 등. 비밀값·제어문자·512자를 초과한 문자열은 받지 않는다.
- `record_count`, `bytes`: 0 이상의 정수. 포트는 0..65535 정수. `critical_asset`은 불리언.
- 권한 부여 전·회수 후 역할이 없는 경우 문자열 `none`으로 명시한다.
- `object_type`: `service`, `scheduled_task`, `cron`, `systemd_timer`.
- `risk_reason`: `executable_extension`, `mime_mismatch`, `malware_verdict`.
- `transport`: 선택 항목이며 `tcp`, `udp`, `icmp`.

| kind | 허용 action |
| --- | --- |
| server_file | modified, deleted, permissions_changed |
| server_persistence | created, modified |
| server_defense | stopped, disabled, policy_changed |
| app_role | granted, revoked, changed |
| app_export | queried, exported, downloaded |
| app_upload | uploaded |
| network_dns | query |
| network_firewall | denied, dropped, rejected |
| network_ids | alert |

중요 파일 지정, 보안 기능 대상, 민감 자료 분류와 업로드 위험 근거는 생산자/관리자 설정에서 제공한다. 파일 내용·원본 SQL·HTTP 본문·패킷 페이로드·명령줄·업로드 파일 본문은 새 메타데이터 경로로 복사하지 않는다. 원본 감사 자료의 보존·접근 정책은 기존 생산자 측에서 관리한다.

## 수집과 운영 연결

수집 프로그램은 `python -m cloud_soc.parsers.security_scenario_export --organization <조직> --host <등록 호스트> --service <앱 서비스>` 형식이다. 앱 외 입력은 service를 생략할 수 있다. stdin으로 실제 구조화 감사 기록을 받아 stdout으로 허용 메타데이터만 출력한다. 잘못된 입력은 민감 내용을 출력하지 않고 stderr에 거부 사유 종류를 남기며, 거부가 있으면 종료 코드 1을 반환한다. 한 레코드는 최대 64KiB다. 명령을 실행하거나 출력 스풀을 생성하지 않았다.

별도 Filebeat 예시는 [filebeat.example.yml](../filebeat/security-scenarios/filebeat.example.yml)이다. `SCENARIO_SPOOL_PATH`, `SOC_ES_URL`, `SOC_CA_FILE`과 보호된 keystore의 `SOC_SCENARIO_API_KEY` 설정이 필요하다. 운영자는 보호된 스풀 파일 접근 권한·회전·보존과 별도 Filebeat 데이터 디렉터리를 구성해야 한다. 기존 수집기 설정을 덮어쓰지 않는다.

[receipt-pipeline.json](../filebeat/security-scenarios/receipt-pipeline.json)은 중앙 수신 시각을 `_ingest.timestamp`로 덮어쓰는 별도 수신 파이프라인 정의다. 중앙 관리자가 `soc-security-scenarios-receipt-v1` 이름으로 등록하고 기존 원본 인덱스 정책과 전용 수집 키 권한을 준비해야 한다. 여기서는 등록하지 않았다. 이후 기존 processing 워커가 원본 참조를 포함해 정규화하며 Portal 통합 로그에도 9종 유형을 표시한다.

탐지 워커에는 위 표의 필요한 ID를 `--additional-rules`의 쉼표 구분 목록으로 명시한다. 별도 상태 파일과 기존 CA·권한 구성을 사용하며 기존 AUTH 상태를 재사용하지 않는다. 모든 새 규칙은 일반 기본 워커에서 자동 실행되지 않는다.

## 실행 상태

### 통합 브랜치 격리 검사 — 2026-10-27

후속 사용자 요청으로 검증 금지를 이번 검사에 한해 해제하고 코드 검사를 수행했다. 9종의 수집 명령→정규화→최소3건 탐지→Portal 유형 표시와 누락·중복·조직/호스트/서비스 격리·시간 구간·잘못된 입력 처리33건을 통과했다. 기존 처리/탐지/Portal/배포 회귀, 전체34규칙의 모의ES·SQLite 재시작/증거 조회/Flask 연결과 직접 영향 Sydney·웹사이트·SSH 검사도 통과했다. Python 구문·Ruff 및 로그 UI3파일 검사를 통과했다.

NDJSON 수집 설정은 exporter가 기록한 `@timestamp`를 Filebeat 기본 읽기 시각보다 우선하도록 수정했다. 이 환경에는 Filebeat 바이너리와 실제 Elasticsearch 실행 인스턴스가 없어 Filebeat 전송·실제 생산자 연결·실제 원본 수신·운영 경보 생성은 확인하지 못했다. 이번 결과는 합성 자료와 모의 외부 I/O를 사용하는 로컬 코드 검사이며 운영 인수 완료를 뜻하지 않는다. 아래 작성 당시 검증 미실행 기록은 과거 이력으로 보존한다.

2026-10-27: 코드·규칙·설정 예시·문서 작성만 수행했다. 사용자 명령 전까지 어떤 검증도 하지 않는 지시에 따라 테스트·시험·검수·검사·린트·빌드·구문 확인·실행 확인을 전혀 수행하지 않았다. 실제 로그 생산자 연결, 수집기 실행, 중앙 수신, 경보 생성, 운영 배포 및 게시는 수행하지 않았다.

## Ubuntu 실제 생산자 연결

Ubuntu auditd·Suricata·커널 방화벽 로그 및 기존 security-mall의 실제 업무 기능을 연결하는 명령은 [운영 연결 안내](security_scenarios_operations.md#실제-생산자-연결-명령--2026-10-28)를 따른다. 직접 HTTPS 수신 경로는 별도 Filebeat 없이 전용 create_doc 키와 수신 파이프라인을 사용한다. 기존 구조화 내보내기/Filebeat 예시는 계속 보존한다. 이 추가 코드의 테스트·운영 적용·9종 실제 경보 인수는 수행하지 않았다.

# 2026-10-16 VMware 설치·탐지·백업 복원 검증

## 근거와 범위

사용자가 Ubuntu VMware VM과 Windows 호스트에서 명령을 실행하고 이 작업 대화에 제공한 JSON·화면·확인 결과를 정리했다. 문서 작성 에이전트가 서버에 직접 접속하거나 원본 증거 파일을 독립 수집한 결과는 아니다. 검증 대상 소스는 main `9d97ee2f2090992697eeaaaf1ceef1986a121268`이며 런타임 source SHA-256은 `80be5525b5a7d13bb90191b2dd50fdc5b79716a2c2240ed8679310bd69b0488f`였다.

이 기록은 해당 VM의 실제 인수 범위에 한정한다. 다른 중앙 서버·Windows 에이전트·클라우드 수집·전체 탐지 룰의 인수를 대신하지 않는다. 제품 소스 수정이나 과거 상위 작업의 일괄 완료 처리는 하지 않는다.

## 설치 중단 복구와 Ubuntu 에이전트

- 최초 설치가 Compose 단계에서 중단됐고 데이터·인증서·기존 상태를 보존했다.
- Elasticsearch는 healthy였지만 여섯 처리 워커가 `runtime_contract_invalid`, 알림 워커가 보호된 중단 메시지를 출력했다.
- 계약 version 2와 정책 hash가 일치했으나 `prepared=false`, install 영수증 존재/current 영수증 부재로 관리 설치 미완료를 확인했다.
- 관리자의 계획은 자원·이미지/소스 검증을 통과했다. 적용은 migration 단계에서 실패했고 ledger는 `001-permissions-and-indices / IsADirectoryError`를 기록했다.
- 사전 Compose 기동이 키 파일 위치를 디렉터리로 만든 상황을 확인했다. 처리·알림 워커를 중지하고, 일곱 키 경로가 심볼릭 링크가 아닌 빈 디렉터리인지 검사한 후 해당 빈 디렉터리만 제거했다. 기존 키 파일·운영 데이터 삭제나 계약 prepared 수동 변경은 하지 않았다.
- `manage.py install --build` 재실행에서 001-permissions-and-indices, 002-independent-workers, 003-slack-notifications가 완료됐고 runtime_ready=true, existing_keys_replaced=false를 확인했다.
- Ubuntu 패키지 해시 검증 후 dry-run을 진행했다. 한글 다운로드 경로가 CA 경로 검증식에 거부되어 전체 패키지를 ASCII 경로로 옮긴 뒤 진행했다.
- 실제 에이전트 설치에서 Filebeat keystore 생성, Config OK, TLS 1.3 및 인증 연결 성공, Filebeat 서비스와 Discovery 타이머 등록을 확인했다.
- 포털에 실제 Linux Filebeat/syslog 문서가 수신됐다. 일반 로그의 해석 미지원/메타데이터 표시와 수집 성공은 구분했다.

설치기·경로 검증·오류 표시의 제품 수정은 이번에 하지 않았다. 위 복구를 일반 자동 복구 기능 완료로 해석하지 않는다.

## 실제 SSH 탐지·Slack 인수

공식 `cloud_soc.deployment.probe`로 VM 로컬 SSH에 존재하지 않는 시험 사용자의 로그인 실패 10회를 발생시켰다. 시험 준비 과정에서 없는 SSH 서버 서비스를 확인하고 OpenSSH 서버를 설치·시작했다. 공개 포트 개방·방화벽/SSH 인증 정책 변경은 하지 않았다.

2026-10-16 14:56:08 KST 자동 검증 결과:

| 항목 | 결과 |
| --- | --- |
| 전체 결과 | verified=true, issues=[] |
| 처리 워커 | 여섯 워커 모두 verified=true |
| 신규 정규화 | 20,337건 |
| 원본 참조 재현 표본 | 20건 |
| 시험 원본/정규화 문서 | 10건 |
| 중복 구분 후 시험 시도 | 10회 |
| 최종 시험 경보 | AUTH-001, generated_for_probe=true |
| 정확한 경보 근거 | 10건 |
| 포털 | 인증·TLS·API 10개·대시보드·알림 워커 검증 통과 |

사용자가 직접 생성한 Slack 앱의 Incoming Webhook을 포털에 등록하고 실제 채널에 시험 경보가 정상 도착했음을 확인했다. 자동 출력의 `actual_slack_channel_receipt=not_verified_by_http_acceptance`는 그대로 보존한다. 채널 수신은 사용자 확인이며 HTTP 검사만으로 증명한 것이 아니다. 메시지의 전체 ID와 포털 ID를 별도로 대조한 결과까지 추가로 주장하지 않는다.

## 사건과 재인증·재부팅

- 사용자가 해당 SSH 경보의 근거 10건 확인과 사건 생성 흐름을 완료했다고 보고했다.
- 현재 포털은 Basic 인증 모드다. 로그아웃 버튼 부재를 확인했고 세션 로그아웃 시험으로 완료 처리하지 않았다.
- 새 사생활 보호 창의 재인증 후 저장 내용·화면 정상 표시를 사용자 확인으로 기록했다.
- VM 재부팅 후 기존 사건·메모·판정·대시보드 화면/설정 유지 확인을 사용자로부터 받았다.
- 16:06:45 KST 후속 자동 검증은 verified=true, issues=[]였다. 여섯 워커·포털이 통과했고 신규 정규화 27,175건, 원본 참조 20건, 기존 동일 AUTH 경보와 정확한 근거 10건을 확인했다.
- 후속 검증은 probe를 지정하지 않아 generated_for_probe=false였다. 기존 경보의 출처 변경을 의미하지 않는다. 출력만으로 모든 중복 경보 부재를 보장하지 않는다.
- 아래 백업의 dashboards와 dashboard_collections는 모두 0행이었다. 사용자 화면 유지 확인과 실제 저장된 개인 대시보드 설정의 백업/복원 검증을 구분한다.

## 포털 DB 격리 복원

`portal-backup.py backup → verify → restore → verify`가 모두 status=ok, missing=[]로 완료됐다. 복원은 새 로컬 경로에서만 했으며 production_restored=false를 유지했다. DB별 일관된 백업이고 ES와 동일 시점의 분산 스냅샷은 아니다.

| DB | 확인한 행 수 |
| --- | --- |
| packages.sqlite3 | packages 1, issued_keys 1, enrollments 0 |
| cases.sqlite | cases 1, case_alerts 1, case_history 2, case_requests 2 |
| log-access.sqlite | source_access 0 |
| dashboards.sqlite | dashboards 0, dashboard_collections 0 |

읽기 전용 SQLite 비교로 백업본과 복원본의 cases.sqlite 스키마와 모든 테이블의 전체 행·컬럼이 일치했다. 실제 사건·메모·판정·연결 경보·이력의 저장 데이터 보존 범위이며 복원본 포털 앱의 전체 UI 구동 인수는 별도다. 빈 대시보드 설정의 복원을 성공으로 확대하지 않는다.

## ES 스냅샷과 Windows 사본 기반 격리 복원

### 스냅샷

최초 등록 저장소와 path.repo가 없었다. 기존 ES 데이터 볼륨을 유지하는 후보 Compose를 검증하고, 보호 설정 백업 후 서버별 runtime/site.json에 스냅샷 bind mount와 path.repo를 적용했다. ES만 재생성한 뒤 설정 적용과 저장소 등록/접근 검증을 확인했다. 이 상태 파일들은 Git에 포함하지 않는다.

`cloud-soc-backup / manual-20261016-01`은 ES 9.5.2에서 2026-10-16 16:28:06~16:28:09 KST에 생성됐다. SUCCESS, 인덱스 10개, 샤드 10/10 성공, 실패 0이었다.

대상은 security-alerts, soc-normalized-v1, soc-pipeline-status, 해당 이틀의 Linux 원본 인덱스, soc-processing-v1, soc-detection-exclusions-v1, soc-agent-health 일별 인덱스, soc-alert-notices-v1, soc-detection-runs-v1이다. include_global_state=true, feature_states=[]로 생성했다. ES 보안 계정/API 키·Kibana 시스템 상태는 포함하지 않았다.

### 외부 사본과 격리 복원

- 저장소를 readonly로 고정하고 저장소 전체를 tar 스트림으로 GPG 대칭 암호화했다. ES 데이터 디렉터리 직접 복사를 백업으로 사용하지 않았다.
- 약 61MiB 암호화 파일을 SSH로 Windows 호스트의 백업 전용 폴더로 전송했다. SHA-256 일치를 사용자 확인으로 기록했다.
- Windows 사본을 VM의 새 경로로 다시 가져왔다. 해시 일치·GPG 복호화 성공·406개 archive 항목의 안전 경로/종류 검사·새 폴더 추출이 통과했다.
- ES 9.5.2 별도 컨테이너를 새 볼륨, network none, 공개 포트 없음, 메모리 2GiB 조건으로 시작했다. 시험 ES만 인증 비활성 상태이며 운영 HTTPS·인증은 유지했다.
- Windows 사본 저장소를 읽기 전용으로 등록하고 업무 인덱스 10개를 복원했다. include_global_state=false, feature_states=none이므로 전역 설정 복원은 이번에 검증하지 않았다.
- 복원 응답 샤드 10/10 성공·실패 0, 업무 인덱스 10개 조회를 확인했다.
- 운영 포털과 같은 이미지의 별도 읽기 전용 검증 컨테이너가 격리 ES의 네트워크만 공유해 검사했다. 운영 ES/Slack 접속이나 쓰기를 하지 않았다.
- 최종 결과 PASS: 기존 시험 경보 ID·AUTH-001·시험 출발지 일치, 정확한 근거/정규화 hash 10건, 원본 기반 정규화 재현 표본 20건, 미할당 primary shard 0개였다.

복원 문서 수는 스냅샷 전의 실시간 목록보다 일부 증가했다. 수집이 계속된 서로 다른 조회 시점을 단순 일치 기준으로 사용하지 않았다. 전 인덱스의 모든 문서/매핑을 운영 원본과 전수 hash 대조했다고 주장하지 않는다.

## 남은 범위와 후속 순서

- Windows 백업 폴더는 VM 파일과 **같은 물리 디스크**다. VM 외부 사본 복원은 검증했지만 물리 디스크 장애 대비의 독립 DR은 미완료다.
- ES 전역 설정·보안 feature state·Kibana 상태의 실제 복원은 미검증이다.
- CA/개인키·서비스 비밀/설정·런타임 체크포인트·Slack DB와 암호화 키·에이전트 registry/미전송 큐의 일관된 보호 백업/복구는 남는다.
- 포털 DB는 로컬 격리 복원까지이며 ES 사본과 묶은 전체 서비스 전환·동일 시점 복구를 검증하지 않았다.
- 별도 물리 저장소, 자동 백업/만료, RPO/RTO 실측, 보존/삭제 정책 및 장기 부하 검증은 남는다. P2-02와 상위 P0~P7을 일괄 완료로 바꾸지 않는다.
- Windows/웹/네트워크·AWS 룰·추가 조직/역할의 현재 VM 인수는 이번 AUTH 시험으로 대체하지 않는다.
- 격리 컨테이너 중지 명령은 안내했지만 실제 중지 출력은 받지 않았다. 시험 자원 정리 완료를 기록하지 않는다.
- 제품 후속 결함 후보: 준비 전 Compose 기동의 키 디렉터리 생성, 보호된 일반 오류에서 원인 위치를 찾기 어려운 점, 한글 CA 경로 거부. 이번에는 운영 우회/복구만 수행했고 제품 수정·회귀 시험은 별도다.

## 저장소 반영

사용자의 최신 요청으로 앞선 커밋 금지를 이번 문서 반영 범위에서 해제했다. JEONGRIM-SEO는 main보다 58커밋 뒤에 있고 독자 커밋이 없어 fast-forward로 main에 동기화한 후 이 기록을 추가한다. 사용자 VM의 체크아웃/미커밋 파일에 직접 접근하지 않았으며 이번 변경은 검증 보고서와 작업 목록뿐이다.

문서의 수치·범위·상대 링크·민감정보 제외를 검토한다. 제품 코드 변경이 없어 제품 전체 회귀는 재실행하지 않으며 새 원격 CI 성공을 미리 주장하지 않는다. DB·스냅샷·암호화 archive·인증정보·웹훅·운영 로그·화면 캡처는 커밋하지 않는다.

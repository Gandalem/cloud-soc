# 에이전트 운영

등록 토큰·발급 키·수신 현황을 통합했다. 새 `devices.html` 설치/관리는 [장치 설치](device_installation.md), 기존 Windows Discovery 갱신/Repair는 [Windows 운영](windows_agents.md)을 따른다. 아래 고급 수동 패키지 계약과 새 managed 장치 계약을 구분한다.

<a id="enrollment"></a>
## 등록 토큰

단일 토큰 기능은 기본 비활성이며 SOC_ENROLLMENT_ENABLED=1과 enrollment 정리 서비스를 명시 활성화한다. 새 Windows/Ubuntu 로그 전용·로그+네트워크 패키지를 지원한다. 기존 ZIP은 자동 갱신되지 않는다. 새 managed Windows는 native 시스템·웹 범위이며 기존 고급 설치기의 네트워크 지원과 다르다.

1. Portal에서 패키지의 대상 별칭·수집 키 유효 기간을 정하고 토큰을 받는다. 미사용 토큰의 최초 사용 기한은15분이다.
2. 다운로드한 원본의 Portal SHA256을 대조하고 새 폴더에 전체 압축을 푼다.
3. 고급 설치기는 아래 명령을 실행하고, 사전 검사를 통과한 뒤 숨김 입력에 토큰 하나를 넣는다. network 포함 Linux는 실제 `--interface`가 필요하다. 새 managed 설치는 이 수동 입력 대신 설치 묶음을 사용한다.

```bash
sudo bash install.sh --enroll --package-sha256 '<SHA256>'
# 네트워크 포함 패키지
sudo bash install.sh --enroll --package-sha256 '<SHA256>' --interface ens33
```

```powershell
.\install.ps1 -Enroll -PackageSha256 '<SHA256>'
# NIC를 명시해야 하는 기존 네트워크 패키지
.\install.ps1 -Enroll -PackageSha256 '<SHA256>' -InterfaceGuid '<GUID>'
```

로그/네트워크 키는 각각 keystore stdin으로 저장한다. 설정·출력 검증 후 service/Discovery를 시작한다. Filebeat의 약1.3KiB 비민감 probe와, 네트워크 포함이면 해당 ES endpoint로 만든 TCP 흐름의 고유 표식·조직·패키지·인증 키·수집기 ID·서버 수신 시각을 중앙이 조회해야 완료다. 설치기의 직접 ES 쓰기로 대체하지 않는다. 완료 receipt는 과거 전송 시험이며 현재 online/무손실/모든 로그 정상의 보장이 아니다.

토큰을 argv·로그·공유 파일에 넣지 않는다. CA·호스트 이름·기간·폐기 검증 실패를 먼저 해결한다. Linux 토큰 경로는 서명된 CRL을 요구하며 검증 완화 옵션이 없다. 기존 Windows의 명시적 사설 CA 호환 옵션은 기본이 아니고 native EXE에는 적용하지 않는다. 토큰 기능은 실행 정책·관리자·Npcap 요구를 우회하지 않는다.

### 서버 준비

기존 DB·데이터·CA·키 이력을 백업/검증한 뒤 현재 상태의 [공통 업데이트](runtime_deployment.md)를 우선 사용한다. 수동 구성은 다음 구조다. 기존 암호와 CA를 보존하며 bootstrap 성공 뒤에만 Portal을 교체한다.

```bash
sudo docker compose --env-file state/server/compose.env \
  -f deploy/server/compose.yaml --profile enrollment build bootstrap portal enrollment-cleanup
sudo docker compose --env-file state/server/compose.env \
  -f deploy/server/compose.yaml run --rm bootstrap
# compose 설정의 SOC_ENROLLMENT_ENABLED=1 확인 후
sudo docker compose --env-file state/server/compose.env \
  -f deploy/server/compose.yaml --profile enrollment up -d --no-deps portal enrollment-cleanup
```

bootstrap은 인증 metadata final pipeline/매핑을 준비하며 기존 문서를 재작성하지 않는다. 충돌 매핑/기존 사용자 pipeline은 검토 없이 덮어쓰지 않는다. 정리 서비스는 발급 계정과 공개 CA로 매분 만료 미완료 세션·폐기 대기 키를 처리한다. 완료 설치의 유효 키는 폐기하지 않는다. 중단되면 자동 폐기 재시도도 멈추므로 비활성화 전에 미완료 세션을 정리한다. Portal 내부 HTTP를 외부에 직접 공개하지 않는다.

### 실패와 재시도

| 상태 | 동작 |
| --- | --- |
| 미사용 토큰 만료 | 새 토큰 준비. 사용 전이면 발급 키 없음 |
| 응답 유실 | 같은 attempt로 최대3회 재전달. 다른 attempt는 거부 |
| 고급 설치 프로세스 종료/토큰 분실 | attempt를 다음 프로세스가 자동 채택하지 않음. 서버 이력/폐기와 로컬 보호 상태 확인 |
| 부분 발급/중단 | 고정 키 이름·패키지/조직/세션으로 폐기. 미확인은 pending으로 유지 |
| 중앙 미수신 | 약3분 제한 뒤 실패, 소유 서비스 중지/비활성화·큐/키/기록 보존. 실패 키 폐기 후 확인된 실패 재등록 사용 |
| 전달 후30분 미완료 | cleanup이 미완료 키 폐기. 정리 장애 동안 실제 만료일까지 유효할 수 있음 |

새 managed native 설치의 DPAPI stable attempt 재개는 [장치 설치](device_installation.md#등록-상태와-복구-경계)의 별도 계약이다. 고급 경로의 프로세스 종료 제한을 제품 전체에 확대하지 않는다.

<a id="reenrollment"></a>
### 확인된 실패 설치의 재등록

같은 서버·조직·OS·범위·CA·소유 기록/파일 해시의 **확인된 실패 Enrollment**만 대상이다. service/Discovery/Beat 프로세스를 중지한 상태에서 새 전체 패키지를 검증한다. 정상 완료·수동·출처 불명·변경된 NIC/설정/키를 자동 채택하지 않는다.

```bash
sudo bash install.sh --enroll --reenroll --package-sha256 '<SHA256>' --dry-run
sudo bash install.sh --enroll --reenroll --package-sha256 '<SHA256>'
```

```powershell
.\install.ps1 -Enroll -ReEnroll -PackageSha256 '<SHA256>' -DryRun
.\install.ps1 -Enroll -ReEnroll -PackageSha256 '<SHA256>'
```

network 포함 Linux는 기존 NIC도 동일하게 지정한다. DryRun은 토큰/키 발급·네트워크·파일/service 변경이 없다. 실제 재등록은 이전 실패 키 폐기를 재확인하고 새 키를 전달한다. 준비 전 실패는 소유 디렉터리/기록을 보호 보관하며, 시작 후 실패는 최신 큐·registry·수집기 ID를 유지한다. 큐를 과거 백업으로 되감지 않는다. 새 probe의 실제 중앙 수신까지 확인해야 완료다. 보호 기록 불일치·모든 전원 손실·서버/CA 이전·Beat 업그레이드는 자동 지원하지 않는다. Windows 로그 전용 재등록 중 Repair가 중단된 경우의 ResumeRepair는 미지원이다.

### 인증과 검증 기록

토큰/attempt는256비트 난수이고 DB에는 해시, 재전달 응답에는 attempt에서 유도한 Fernet 암호화를 사용한다. 완료/취소 시 응답은 비운다. 원자적 예약·고정 키 이름으로 중단/복원 후 중복 발급을 막고 host/network 역할을 분리한다. 수집 키는 create_doc/auto_configure와 필요한 monitor·network pipeline 읽기만 가진다. 읽기/삭제/키 관리 권한을 추가하지 않는다.

final pipeline은 클라이언트 검증 신원을 제거하고 실제 API key metadata의 조직/패키지로 고정한다. receipt는 부분 샤드·timeout·매핑 누락을 성공 처리하지 않는다. 설치 API3개만 토큰 인증이며 관리자 API의 인증/CSRF는 유지한다. TCP5-tuple 전체 일치나 장치 원격 attestation은 아니다.

10/04 지정 Windows/Ubuntu VM에서 로그 전용/통합 설치, 실제 수신, ES 중단→실패 키 폐기→보존형 새 토큰 재등록, 경합·만료·권한·브라우저를 검증했다. 정상 설치 키 자동 교체·모든 정전 지점·일반 업그레이드의 인수가 아니다. 자세한 ID/실패·권한 결과는 [P0C-03 실제 기록](archive/README.md#record-docs-archive-validation-p0c03-validation-20261004-md)에 보존한다.

<a id="key-management"></a>
## 발급 키 관리

### 정상 장치의 수동 유효기간 연장

INSTALL-DEVICE-UX-03-KEY-EXTEND는 기존 키의 만료일에1·7·30·90일을 더하는 기능이다. 키 원문·장치 keystore·수집기 ID·등록/증거 참조는 유지한다. 새 비밀값으로 교체하는 키 회전이나 유출된 키의 복구 수단은 아니다. 현재 개발 체크아웃의 구현이며 기존 서버에 자동 배포되지 않는다.

장치 관리 → 장치 상세 → 수집 키 유효기간 연장에서 키와 기간을 선택한다. 서버에서 확인한 기존/예정 만료일을 보고 적용한다. 최종 화면은 서버 재조회로 확정한 실제 만료일을 표시한다. 일반 로그 수신은 기존 수신 조회에서 별도로 확인한다. 조용한 장치를 연장 실패로 판단하지 않는다.

대상은 설치 완료 receipt가 있고 조직·장치·패키지·등록 세션·host 키의 정확한 연결이 확인된 로그 전용 managed Windows/Ubuntu/Amazon Linux 장치다. network 포함·수동/연결 불명 키·만료/폐기 키·종료/차단 중 장치는 지원하지 않는다. 미사용 등록 토큰 갱신이나 실패 재등록과 혼용하지 않는다. 관리자 권한·기존 로그인/CSRF/Origin 경계를 유지하고 발급 소유자 계정만 서버에서 사용한다. 장치 키에 관리 권한을 추가하지 않는다.

#### 권한·시각·중복 계약

- 미리보기 `POST /api/managed-devices/<device>/key-extension/preview`: key_id/days와32자리 요청 ID를 받아 기존 device_operations에 예약한다. 같은 사용자/ID/내용은 같은 예약이며 다른 내용/사용자는 충돌이다. 장치별 미확정 예약은 하나만 허용한다. 미제출 예약은 취소할 수 있고10분 뒤에는 새 확인 화면이 필요하다.
- 적용 `POST .../key-extension/<operation>`: confirm=true는 적용/결과 재확인, false는 미제출 예약 취소다. actor/device/action을 대조한다. 제출 전에 attempted 상태를 영속화하고 원격 변경은 최초 호출의 한 번만 허용한다. 프로세스 중단 후 attempted 요청은 원격 조회만 한다. 클라이언트의 자동 재시도도 끈다.
- 원격 metadata의 기존 조직/패키지/등록/용도와 나머지 metadata를 보존하고, cloud_soc_expiry_extension의 요청 ID/고정 목표 시각을 추가한다. 변경 전 원격 스냅샷 해시와 변경 후 metadata 해시·목표 만료 허용 오차를 예약에 보관한다. 비밀값은 저장하거나 조회하지 않는다. 이 표식은 해당 키의 소유 관리자에게 위변조 불가능한 서명이 아니다.
- Elasticsearch update는 소유자 권한 스냅샷도 갱신한다. 기존 할당 role이 정확한 제품 host 최소 권한인지 확인하고, limited_by의 모든 교집합이 그 전체 권한을 원래 허용했는지 보수적으로 증명한다. 정확 패턴/단순 끝별표 접두 범위와 명시 권한 또는 all만 인정한다. 제한 쿼리/필드/조건부 역할이나 복잡한 동등성은 추정하지 않는다. 현재 소유자 has_privileges 확인과 갱신 뒤 동일 정책/전체 스냅샷 확인을 모두 통과해야 완료다. 소유자의 다른 권한이 늘어도 명시 host 역할 상한은 유지한다. 조직별 인덱스 권한까지 새로 보장하는 변경은 아니다.
- ES는 상대 기간을 받으므로 미리보기에서 기존 만료일+선택 일수의 목표를 고정한다. 적용 직전 남은 밀리초를 한 번 계산한다. 원격 Nodes Stats의 모든 노드 timestamp와 Portal 시각 차이는5초 이내만 허용하고 부분 노드 응답도 거부하며 재조회 만료일도 목표±5초 안이어야 한다. 화면의 예정 시각과 최종 확정 시각을 구분한다. 시각 차이를 자동 보정하거나 재시도 때 목표를 다시 더하지 않는다.
- 키 ID·기간·변경 전/예정/확정 만료·상태는 기존 작업 결과에, 행위자/장치/작업 ID/시각은 기존 감사 기록에 남긴다. 별도 자격 증명 원장을 만들지 않는다. 백업에는 기존 작업/감사 테이블과 attempted 장벽이 함께 포함된다.

#### 실패·경합·복구 한계

원격 확인 실패는 연장 성공이 아니다. 응답 유실 또는 원격 성공 뒤 로컬 완료 저장 실패는 같은 작업 ID로 원격 표식/만료/권한을 다시 확인한다. 키 캐시·완료 작업·감사 기록은 한 로컬 transaction으로 저장한 뒤에만 완료를 반환한다. 조회도 실패하면 미확정 상태를 유지한다. 미확정 예약이 있으면 새 연장 예약을 막고, 원래 유효한 키를 자동 폐기하거나 수집기를 정지하지 않는다.

attempted 기록 뒤 실제 전송 전에 중단되면 원격 표식이 없으므로 자동 재전송하지 않는다. 관리자 확인이 필요한 요청으로 남으며 현재 화면에는 재확인만 제공한다. 자동 취소/강제 재연장으로 불확정을 숨기지 않는다. DB와 원격 엔진 사이의 원자적 exactly-once, 사이트 손실/오래된 백업 복원 후 자동 조정, 권한 관리자와 동시 정책 변경을 원천 차단하는 기능은 없다. 외부 관리자가 바인딩/권한/표식을 바꾼 경우에도 명시적으로 거부한다.

장치 종료와 연장 변경 구간은 같은 DB 쓰기 잠금으로 직렬화한다. 종료가 먼저면 적용을 거부하고, 연장이 먼저면 종료가 같은 키를 이어서 폐기한다. 폐기된 키는 update로 복구하지 않는다. Portal 밖의 동시 변경은 재조회로 확인하되 다른 관리자의 모든 경합을 전역 잠그지는 않는다. 새 비밀값 교체·자동 연장·단말 관리 채널·설치기 변경·운영 키 변경은 범위 밖이다.

공식 근거: [API key update](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-update-api-key), [소유 키와 limited_by 조회](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-get-api-key), [현재 권한 확인](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-has-privileges), [노드 시각 조회](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-nodes-stats). 2026-10-26 새 TLS ES9.5.2에서 같은 키 연장/합성 API 수집·권한 차단·응답 유실/완료 저장 실패 조정·폐기/만료·TLS 신뢰/이름 실패를 통과했다. 그 후 새 Ubuntu24.04.5 WSL의 제품 Filebeat 설치/receipt·연장 전후 실제 수집·같은 키/수집기 ID/서비스 PID·설정/keystore/receipt 해시 유지·제거/폐기까지 확인했다. 후속 사용자의 실제 브라우저 연장 클릭 성공 보고를 원격/로컬 만료 일치·같은 Filebeat/키/권한·연장 뒤 정확 원본 수신과 대조하고 시험 환경을 정리했다. 모델 직접 화면 시각 확인은 연결 도구 시작 오류로 미수행이며 기존 만료 경과·Windows 추가 인수·운영 단말 배포와 구분한다. 기존 Python client9.5.1과 시험 ES9.5.2를 유지하며 새 의존성/라이선스를 추가하지 않는다. 공식 최신 문서의 지원 설명과 고정 버전의 실제 실행 결과는 구분한다.

구현/검사 파일은 src/cloud_soc/portal/key_extension.py·device_management.py·app.py, prototype/devices.{html,js}, tests/test_device_key_extension.py·test_device_key_extension_live.py와 prototype/tests/devices.test.cjs다. 실제 고정 버전 결과와 정리 여부는 [작업 목록](work_tracker.md)의 해당 ID에 기록한다. opt-in 실제 시험은 SOC_TEST_KEY_EXTENSION_ES=1과 SOC_TEST_DOCKER 지정 후 해당 live 검사만 실행하며, 새 loopback TLS 컨테이너/볼륨/합성 키만 만들고 정리한다. 실제 Windows/WSL 수집기를 재설치하거나 운영 서비스/키에 접속하지 않는다.

| 작업 | 의미 |
| --- | --- |
| 고급 패키지 삭제 | 다운로드 파일/링크만 삭제. 설치된 수집기·키는 유지 |
| 키 폐기 | 정확한 대상/용도/ID의 서버 인증 차단. 로컬 서비스/큐는 별도로 처리 |
| 장치 종료 | managed 장치의 등록/관련 키 접근 차단. 로컬 프로그램 제거와 별도 |
| 이력 필터 | 목록만 정리. 감사 이력 영구 삭제가 아님 |

managed 패키지는 일반 삭제/별도 수동 키 발급을 막고 장치 상세에서 관리한다. host/network 키는 서로 다르다. 키 원문은 발급 때 한 번만 표시하며 목록/DB에 보관하지 않는다. 대상 별칭·패키지·OS·조직·용도·발급/만료/확인/폐기 시각을 확인한다. 별칭은 수정 가능하지만 호스트 자동 매칭이나 실제 수신 증거가 아니다.

기존 고급 목록은 최근500개, 새 장치 화면의 `/api/key-history`는 서버 검색·필터·페이지를 사용한다. `서버 확인 전`, `유효(마지막 조회)`, `만료`, `폐기 완료`, `조회 실패/찾지 못함`을 구분한다. 구버전 이력의 누락 범위/만료·삭제된 패키지/미기록 호스트는 추측하지 않는다. Portal 밖에서 발급한 키를 자동 추가하지 않는다.

폐기는 manage_own_api_key/owner=True와 정확한 ID로 수행한다. 응답 ID가 맞거나, 오류 없는 빈 응답 뒤 같은 소유자·정확 ID의 invalidated=true를 확인해야 완료다. 미조회·다른 ID·활성·권한/응답 오류는 성공이 아니다. 원격 성공 후 로컬 저장 실패도 같은 키로 재시도한다. 2026-09-30 `6b5c7aa`의 지정 VMware 적용에서 실제 폐기·재시도·화면 결과를 확인한 기록이 있다(P0C-17).

키 UI만 기존 서버에 적용할 때는 코드를 반영하고 [백업](portal_backup.md) 후 Portal만 교체한다. 신규 설치기/인증서 재생성은 필요 없다.

```bash
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml build portal
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --no-deps portal
```

앱/DB 다운그레이드는 함께 검토하며 DB 복원으로 ES의 폐기 키가 되살아나지 않는다. 정보/권한·응답·UI·백업 검사는 tests/test_key_management.py와 prototype/tests/key-management.test.cjs, 합성 화면 검사는 tests/key_management_preview.py에 있다. 실행 명령을 운영 인수 완료로 해석하지 않는다.

<a id="received-activity"></a>
## 수신 현황과 heartbeat

`agent-status.html`은 관리자 전용으로 실제 ES 수신 데이터를 조회한다. 다음 세 경로는 각각 별도다.

| 경로 | 확인하는 것 | 보장하지 않는 것 |
| --- | --- | --- |
| `/api/agents/status` | Filebeat/Packetbeat의 서버 수신 활동 | 설치 자산 전체·현재 서비스 실행·장치 신원 인증 |
| managed 장치 receipt/activity | 최초 probe와 정확한 장치 바인딩의 일반 로그 수신을 분리 | 서비스/분석 상태는 직접 관측하지 않으면 unknown |
| dashboard heartbeat | 별도 인증정보·generation/sequence로 주기 보고, 실제 SCM/systemctl 수집기 상태 | 로그 수신·경보 성공·장치 전원/신뢰 실행 |

**지속 heartbeat와 장치 등록은 이미 구현돼 있다.** [대시보드 계약](dashboard_capabilities.md#장치-상태)과 tools/device_heartbeat.py를 따른다. `/api/agents/status`가 heartbeat를 사용하지 않는다는 사실을 제품 전체의 기능 부재로 표현하지 않는다.

수신 현황은 마지막 event.ingested 기준으로5분 이내 최근 수신,15분 이내 수신 지연,그 이후 장기 미수신이다. 시각 누락 또는 서버보다1분 넘게 미래이면 판단 불가다. 장기 미수신은 서비스 중지 외에도 조용한 입력·큐/네트워크·키 만료가 원인일 수 있다.

organization.id+agent.id+agent.type별로 최근30일을 조회한다. 수신 시각이 없는 기존 문서는 최근 원본 시각으로 표시하되 판단 불가다. 오래 조용한 수집기는 사라질 수 있으며 agent.id 누락은 행에서 제외하고 경고한다. 최대50개·cursor 페이지, 카드/필터/검색은 현재 페이지,30초 갱신/숨김 탭 중지다. 장애면 정상 표를 지우고 조회 실패와 마지막 성공 시각을 표시한다. 호스트 메타데이터를 인증된 자산 식별로 해석하지 않는다.

### 기존 중앙의 수신 조회 준비

새 설치는 monitor와 수신 시각 pipeline을 함께 준비한다. 기존 상태에는 아래 도구로 monitor 비밀 파일만 추가한다. 보호된 state/server/secrets와 정상 기존 비밀번호/CA를 유지하며 잘못된 파일은 덮어쓰지 않는다.

```bash
sudo python3 deploy/server/prepare-monitor.py
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml build bootstrap portal &&
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml run --rm --no-deps bootstrap &&
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml up -d --no-deps portal
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml ps -a
sudo docker compose --env-file state/server/compose.env -f deploy/server/compose.yaml logs --since 5m --tail 80 portal
```

monitor는 soc-host-raw-*/soc-network-*에 read/view_index_metadata만 가진다. cloud-soc-received-at-v1 final pipeline이 서버 `_ingest.timestamp`로 event.ingested를 기록한다. 기존 대상의 매핑/pipeline만 준비하고 과거 시각을 재작성하지 않는다. 사용자 pipeline/매핑 충돌은 중단한다. 작업 전체는 원자적이지 않으므로 중간 실패를 확인한 뒤 재시도한다. firewall·인증서·에이전트 키 권한을 바꾸는 절차가 아니다.

### 실제 수신 확인

승인된 새 테스트 입력 후 자신의 host/agent ID·종류·조직과 새 event.ingested, 정확한 원본 참조를 확인한다. 오래된 @timestamp가 지금 도착하면 최근 수신으로 표시돼야 한다. network 수신은 해당 NIC에서 관측 가능한 통신이 별도로 필요하다. API는 cursor 외 조건을 거부하고 본문/키를 반환하지 않는다. timeout·샤드/권한 오류는503이며 일부 결과를 정상으로 표시하지 않는다.

오프라인 API/UI 검사는 tests/test_agent_status.py와 prototype/tests/agent-status.test.cjs, 선택적 실제 ES 검사는 SOC_TEST_AGENT_STATUS_ES=1의 tests/test_agent_status_live.py다. 후자는 명시된 루프백 합성 컨테이너만 만들고 정리하며 실제 AWS/PC를 변경하지 않는다.10/23 managed 실제 ES/Beat 시험은 proof만으로 일반 활동을 표시하지 않았고 일반 로그 뒤 정확 참조를 확인했다.10/07~08 기존 Discovery 통계의 실장치→ES/API→화면 검증은 [계측 기록](p2_collection_metrics.md)을 따른다.

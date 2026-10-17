# Security Mall 9-C — 배포 전 연결

2026-10-18, main `18ad348` 기반. **로컬 코드·합성/모의 ES 검증만 수행**했다. SSH, VM 배포, 실제 ES/SQLi/브라우저 검증, 키 발급 및 서비스 변경은 하지 않았다. PR #14 Runtime-v2는 포함하지 않는다.

## A. Portal 범위 계약

`config/security-mall-portal-lab.example.json`은 기존 ACCESS 원본/정규화와 상주 앱·Edge 원본/정규화를 함께 명시한다. `alerts`는 기존 단일 문자열이다. `raw`/`normalized`는 기존 문자열 또는 중복 없는 1~8개 정확한 인덱스 목록을 받는다. 검증 후 문자열은 그대로, 목록은 tuple로 유지하며 반복 검증도 가능하다. 빈 목록/중복/비문자열/와일드카드/콤마/다른 prefix/합성 인덱스는 오류다.

`scope_indices()`를 Operations.get/evidence/intake 및 LogReader가 함께 사용한다. exact-index resolver는 alias/data stream/예상 외 인덱스를 거부한다. 브라우저 파라미터로 설정을 확대할 수 없다. 기존 조직 검사·정규화 SHA-256·원본 identity·원문 역할 검사를 보존했다. 키 권한은 자동 변경하지 않는다.

`app.py`의 기존 `validate_scope` 및 reader/Operations 전달을 그대로 재사용한다. 서버가 `create_app(settings)`를 호출하면 실제 `portal_wsgi.py` settings에 수정된 `MALL_LAB_SCOPE`가 전달되어야 한다. 기본 환경 로딩의 `SOC_MALL_LAB_SCOPE_FILE`만 변경해도 명시적 settings에 자동 병합되는 것은 아니다.

기존 `MALL_TRIAGE_SNAPSHOT_FILE`은 고정 스냅샷이며 동일 alert index 바인딩과 현재 증거 재검증을 유지한다. ACCESS 조사 결과는 유지한다. 새 WAF 경보가 스냅샷에 없으면 분석 미확인으로 표시하고 분석 결과/DB를 생성하지 않는다.

## B. 기존 엔진의 일회성 실습 실행

4-C의 기존 `approved_rules → detect_events → build_security_alert/make_alert_id → save_security_alert` 경로를 재사용하는 `python -m cloud_soc.detection.mall_lab`을 추가했다. 일반 AUTH-001 Worker의 인덱스/설정/체크포인트/초기 통지/Slack/status 경로는 변경하거나 호출하지 않는다.

관리자는 `config/security-mall-lab-detection.example.json`을 비공개 설정으로 복사하여 CA·키 파일 경로와 정확한 인덱스·organization·host·규칙 ID를 승인한다. 예시 경로는 미생성 자리표시자다. 한 host/service는 기존 실습의 한 사이트 범위를 전제로 하며 여러 사이트 공유 범위로 확대하지 않는다. 시간은 UTC가 포함된 최대 24시간, 문서는 전체 최대 10,000건(기본 1,000건)이다. 한정된 각 concrete 정규화 인덱스의 PIT 조회를 사용한다.

기본 실행은 dry-run이다. 다음은 **별도 9-D 승인 후** 사용자 환경에서 실행할 예시이며 이번 작업에서는 실행하지 않았다.

```bash
python -m cloud_soc.detection.mall_lab \
  --config /home/kopo/soc-mall-lab/detection-9d/config.json \
  --start 2026-10-17T00:00:00Z --end 2026-10-18T00:00:00Z
# 별도 경보 저장 승인 및 writer 키 확인 후에만 위 명령에 --write-alerts 추가
```

설정/키는 절대 경로이며 소유 사용자 전용 디렉터리0700/파일0600(Windows는 비공개 ACL)로 관리한다. 기존 private_bytes의 owner/mode/크기/hardlink/symlink·상위 reparse 검사를 재사용한다. 키 JSON은 보호된 `encoded`와 미래의 epoch-millisecond `expiration` 또는 `expires_at`을 요구한다. 둘이 있으면 일치해야 한다. 키 원문/Authorization/ES 오류 본문을 출력하지 않는다. 비밀값을 명령 인자나 저장소에 넣지 않는다.

TLS는 CA chain 및 `127.0.0.1` SAN/hostname을 검증하며 엔드포인트는 `https://127.0.0.1:19200`만 받는다. 만료/401/403/권한 불일치에서는 중단한다. 자동 키 발급·확대·폐기 기능은 없다.

- reader: 설정의 정확한 alerts/raw/normalized에 `read`, `view_index_metadata`.
- writer(명시적 저장 시에만 로드): 정확한 alerts에 `create_doc`, `view_index_metadata`만. 원본/정규화 권한 없음.
- `_has_privileges`로 지정 인덱스의 필요 권한과 create/index/write/delete/manage/create_index 및 주요 cluster 관리 권한 부재를 확인한다. 이는 **임의의 다른 인덱스/미조회 권한까지 열거하는 증명은 아니다**. 관리자에게 발급 역할이 정확한 범위인지 확인받아야 한다. 기존 키를 확대하지 않는다.
- alert index와 기존 provenance `enabled:false` 매핑이 미리 있어야 한다. `ensure_provenance_mapping(apply=False)`로 확인만 하며 인덱스/매핑을 생성·변경하지 않는다.
- 모든 입력의 조직/host/service/시간/정규화 index-id/원본 scope/provenance와 기존 Operations의 SHA-256 및 raw identity를 검사하고 전체 탐지/경보 구성을 완료한 뒤에만 create를 시작한다. 검증 실패 시 저장0건이다.
- 명시적 저장은 기존 create-only API를 사용한다. 같은 입력의 경보 ID는 고정이며 409 충돌은 기존 문서 보존/추가0건이다. 여러 경보 create는 ES 트랜잭션이 아니다. 도중 통신 실패 시 일부만 저장될 수 있으므로 원인을 해결한 뒤 같은 스냅샷을 재처리하여 create 충돌로 대조한다. 자동 재시도/수정/덮어쓰기는 없다.
- 출력은 mode/events/detections/rules/created/existing 또는 고정 오류 코드뿐이다. 실제 원문과 개인정보는 출력하지 않는다.

## WAF 판정 불변

CRS3.3.5의 기존 SQLi 8ID, 300초, 동일 조직/host/service/관측IP/request_id 중복 제거, 1요청부터 경보/3요청부터 반복, 위험도45/55 및 medium severity는 변경하지 않았다. DetectionOnly의 선언 block/deny는 실제 차단이 아니며 blocked=false다. request_id/관측IP를 출처 인증·공격 성공으로 해석하지 않는다. 기존 AUTH/ACCESS 규칙 및 위험도는 변경하지 않았다.

## 배포 전 체크리스트 — 현재 실제 상태는 모두 미검증

| 확인 대상 | 이번 확인 범위와 9-D 확인 필요 사항 |
|---|---|
| Portal 실행 코드/portal_wsgi.py | 소스의 settings 전달 계약만 확인. 실제 실행 파일/반영 SHA/부팅 설정은 **미검증** |
| ACCESS/상주/Edge exact 인덱스 | 예시 JSON에 과거 검증 이름5개+alert1개 명시. 실제 존재·alias 아님·문서/매핑은 **미검증** |
| Portal 읽기 키 | 앱/Edge/정규화/alert 각각 read/view metadata 보유·만료·파일 권한 **미검증**. 자동 확대 금지 |
| 탐지 reader/writer | 정확한 역할·만료·create-only 권한 및 실제 API 응답 **미검증**. 새 키 발급 없음 |
| Elasticsearch | 과거9.5.2 기록, 기존9.x client API 재사용. 실제9.5.x resolve/PIT/privilege/mapping/create 호출 **미검증** |
| Apache/ModSecurity/CRS | 과거2.4.58/2.9.7/3.3.5 기록만 사용. 현 버전·900990/335·901001 없음 **미검증** |
| DetectionOnly | parser/합성 계약만 검증. 현재 WAF 설정 **미검증** |
| CA/인증서 | full TLS context 호출 로컬 검증. 실제 CA·만료·SAN/hostname **미검증** |
| 보존/백업 | 기존 로컬/제외 파일 보존. VM 원본·정규화·경보 백업 및 Portal SQLite Online Backup·코드/설정 복구본 **미검증** |
| 기존 7-C 조사 화면 | 합성 pinned snapshot과 ACCESS/WAF 동시 API 검사. 실제 ACCESS20/low·limited 및 브라우저 증거 링크 **미검증** |

## 9-D 최소 승인 및 중단 조건

1. 실습 Portal의 정확한 코드/설정/키 범위 점검과 일관성 백업·복구 수단 확인 후 필요한 파일 반영 및 Portal 한 서비스의 1회 재시작 승인.
2. 정확한 실습 인덱스/CA/키 역할 읽기 확인. 기존 키가 부족하면 별도의 최소 권한 키 발급을 사용자에게 승인받되 이번 코드가 발급/확대하지 않는다. 인덱스/매핑 준비가 없다면 별도 승인 전 중단한다.
3. 지정 범위의 일회성 dry-run 후 실제 경보 create-only 저장은 별도 명시 승인. 기존 ACCESS 및 고정 조사 스냅샷을 유지한다.
4. 실제 SQLi 시연 요청·WAF 경보 생성 및 브라우저 인수는 승인된 실습 범위에서만 수행한다. 이번 합성 결과를 실제 공격/ES/배포 완료로 표시하지 않는다.

검사 실패/권한 부족/증거 불일치에서는 보안 검사를 완화하지 않고 중단한다. VM/ES/키/서비스 변경, UI 재설계, 신규 규칙/AI/상주 탐지 엔진 추가는 이번 범위 밖이다.

## 이번 실행의 로컬 검증

- 신규/확장 Python 고유40건 통과(최초34건, 추가6건 및 변경된 중복 사례 재검증). 기존 단일 범위/ACCESS/7-C/보호 원문/AUTH-001 직접 회귀7건 통과, 합계 고유47건이다. mock ES의 실제 기존 엔진/Portal API/저장 함수와 CLI 함수 및 subprocess 진입을 검사했으며 실제 ES/공격 검증이 아니다.
- Ruff 변경 Python5파일 통과, Bandit medium/high 동일 범위 통과(발견0건). 공유 Mall DOM12건 통과. 전체 pytest/UI/Docker/기존7-A/B 실검증은 실행하지 않았다.
- Linux 배포 예시는 `/home/...` 경로이므로 Windows의 `Path.is_absolute()`로 직접 로드하면 거부된다. 이는 실행 OS에서의 절대 경로 보호이며 Linux 예시의 Windows 실행을 주장하지 않는다. 예시 필드/인덱스는 로컬에서 경로만 현재 OS의 절대 경로로 대체하여 검증했다.
- 실제 VM 배포·ES9.5.x·브라우저·Linux 파일 권한·키 권한은 미검증이다. 새 PR의 Ubuntu/Windows CI 상태는 별도로 보고한다.

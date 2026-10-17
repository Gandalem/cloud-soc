# 7-A/B 검증 CLI 인증 준비

2026-10-17. 로컬 구현과 합성 자격 증명/모의 ES 테스트만 수행한다. 신규 키 발급·폐기·실제 ES 조회·서비스 변경은 이번 단계에서 수행하지 않는다. 기존 부분 검증을 전체 7-A/B 통합 성공으로 바꾸지 않는다.

## 명시적인 전용 키 선택

`deploy/security-mall/validate_correlation_triage.py`는 필수 `--api-key-file` 인자로 파일 경로만 받는다. Portal 키 기본값/환경변수 대체/수집 키 fallback은 없다.

- 허용 경로: `/home/kopo/soc-mall-lab/validation-7ab/secrets/reader-<run>.json`. `<run>`은 영숫자로 시작하는 최대96자 영숫자/하이픈/밑줄이다. 상대 경로, `..`, 다른 파일명·디렉터리·서비스 키는 거부한다.
- Linux 실행 UID 소유의 디렉터리 **0700**, 일반 파일 **0600**, hardlink 수1, 최대8192바이트를 검사한다. CLI가 잘못된 권한을 자동 수정하지 않는다.
- 모든 상위 디렉터리를 descriptor-relative `O_DIRECTORY|O_NOFOLLOW`로 열고 마지막 파일도 `O_NOFOLLOW`로 연다. 심볼릭 링크 및 파일 종류 바꿔치기를 통한 임의 경로 읽기를 막는다. Windows에서 POSIX 권한 검사를 생략해 실제 키를 사용하는 경로는 없으며 안전하게 거부한다.
- 파일에는 `id`, `encoded`, `expiration` 세 필드만 저장한다. `expiration`은 ES 발급 응답의 epoch milliseconds이며 `encoded`는 ES의 base64 `id:api_key`다. 파싱·ID 일치·길이·문자 및 매 요청 전 만료를 검사한다. 실제 비밀 예시는 문서/테스트에 넣지 않는다.
- TLS는 `https://127.0.0.1:19200`와 기존 `portal-lab/config/ca.crt`로 고정한다. CA/호스트 검증 활성화, 자동 redirect/외부 proxy 비활성화다. 인증·TLS 우회 옵션은 없다.

## 범위와 권한 검사

승인 계획의 정확한6개 이름을 CLI 상수와 실제 `collection.json`/`mall-scope.json` 양쪽에서 대조한다. 변경되면 자동 수용하지 않고 중단한다. 인덱스 목록은 [발급 계획](security_mall_validation_reader_plan.md), 요청 본문은 [요청 예시](../deploy/security-mall/validation-read-key.request.example.json)를 따른다.

최초에 `GET /_security/api_key?id=<이 키의 ID>`로 **자기 키 하나의 할당 역할**을 읽어 ID/만료/폐기 여부와 역할 상한을 검사한다. cluster/global/applications/run_as/remote/data_source 추가 권한, wildcard/허용 밖 인덱스, read/view_index_metadata 외 권한을 거부하고 역할 생략을 통한 소유자 권한 상속도 거부한다. API Key ID는 보호 파일의 encoded 값과 대조된 ID만 쓰며 다른 키 조회·with_limited_by 조회는 허용하지 않는다. 추가 관리 권한은 부여하지 않는다. 9.5.2의 자기 키 조회 허용은 [RBACEngine의 동일ID 검사](https://github.com/elastic/elasticsearch/blob/v9.5.2/x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authz/RBACEngine.java#L246-L255)를 따른다.

이후 기존 `_has_privileges`로 **6개 모두** read/view_index_metadata가 실제로 유효한지와 쓰기·관리 권한이 없는지 확인한다. 할당 역할은 권한의 상한이고 소유자 권한과의 교집합은 이 유효 권한 검사로 확인한다. profile=history도 이 계약은 유지한다. 정보 조회가 지원되지 않거나403이면 권한 확대 없이 중단한다. 수정된 경로의 실제9.5.2 응답은 다음 별도 승인 실행에서 검증해야 한다.

이전 `GET /_security/user/_privileges` 호출은 할당 역할이 있는 API Key에서 지원되지 않는 계약 오류였다. [9.5.2 공식 소스](https://github.com/elastic/elasticsearch/blob/v9.5.2/x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authz/RBACEngine.java#L699-L724)가 자기 키 정보 API 사용을 안내한다. 미지원 오류를 무시하거나 빈 권한으로 성공 처리하지 않고 지원되는 자기 키 조회로 대체했다.

데이터 전송기는 exact6 인덱스의 `_search`/`_mget`만 허용한다. `_mget`은 해당 인덱스의 `ids` 형식만 허용하며 문서별 다른 `_index` 지정을 막는다. 반환 `_index`도 요청 이름과 일치해야 한다. 전체 인덱스 조회·쓰기·삭제·키 발급/폐기 API는 이 CLI에 없다.

검색은 조직 `mall-isolated`, 호스트 `mall-host-isolated`, 서비스 `security-mall`, 서버 사이트 binding과 시간 구간/수신 cutoff 및 인덱스당500건 상한을 유지한다. 경보는 기존 계약의 조직/규칙/시간 필터 및 실제 증거 scope 검사를 사용한다. 이는 새 ES 문서 수준 DLS를 구성한 것이 아니다.

## 오류와 종료 코드

| 결과 | reason / 종료 코드 |
|---|---|
| 파일 없음 | `reader_file_missing` / 1 |
| 경로·소유자·권한·링크·파일 형식 거부 | 고정된 `reader_*` 사유 / 1 |
| 파일에 기록된 TTL 만료 | `reader_expired` / 1 |
| 서버401 | `reader_authentication_failed` / 1 |
| 서버403 | `reader_permission_denied` / 1 |
| 필요한 유효 권한 부족 | `reader_scope_missing` / 4, 데이터 조회 중단 |
| 과도한 권한/허용 밖 인덱스 | `reader_excess_*` / 1 |
| CA 로딩/서버 인증서 검증 실패 | `reader_ca_invalid` / `es_tls_verification_failed` / 1 |
| 연결 실패/시간 초과 | `es_connection_failed` / `es_connection_timeout` / 1 |
| 조회·엔진 검증 실패 | 1 |
| 잘못된 CLI 인자 | 2 |
| 예기치 못한 도구 오류 | 고정 사유 / 3 |
| 읽기는 성공했지만3종 연결 조건 미충족 | 4, `integration_complete=false` |
| 실제3종 연결·증거 조건 통과 | 0 |

서버401만으로 폐기·잘못된 값·서버 만료를 구분할 수 없으므로 만료로 단정하지 않는다. 예외 본문·서버 오류 응답·Authorization·encoded·계정 가명·원문을 보고서에 복사하지 않는다. summary 저장 실패도 안전한 사유와 비0 종료 코드로 반환한다.

오류 진단에는 `failed_stage`, `exception_type`, HTTP 오류 시 숫자 `http_status`와 고정된 `failed_operation`만 추가한다. 키 ID나 원문 URL/오류 본문은 기록하지 않는다. `index_queries`는 승인된 인덱스별 시도/성공/실패와 건수(미확인null)를 남기고 `counts`는 성공한 조회만 즉시 기록한다. `correlation_triage_started/completed`로 엔진 진입 여부를 구분한다. 실제 엔진 실행 도중의 세부 내부 단계까지 기록하는 기능은 이번 최소 수정에 포함하지 않았다.

## 별도 승인 후 발급·검증·폐기 순서

1. VM 콘솔에서 kopo 사용자와 보호된 기존 사용자 인증/CA 경로를 확인한다. 비밀번호를 대화·명령 인자·환경 출력으로 전달하지 않는다. 발급 사용자는 `manage_own_api_key`와 요청 인덱스 권한이 필요하다. 권한 부족 시 기존 키 확대 없이 중단한다.
2. 보호된 사용자 인증을 VM 프로세스 내부에서만 읽는 승인된 발급 절차로 요청 예시의 정확한6개·read/view·cluster없음·2시간TTL 키1개를 발급한다. 일반 `curl` 출력으로 키 응답을 터미널에 노출하지 않는다. 이번 단계에서는 발급 도구를 실행하거나 새 키를 생성하지 않았다.
3. 응답 중 세 필드만 새0600 파일로 exclusive 생성하고 fsync한다. 부모0700·UID·symlink·nlink를 확인한다. 키 이름과 파일은 run마다 새로 정하고 기존 파일을 덮어쓰지 않는다. 저장 실패 시 이번 신규 ID만 폐기하고, 폐기까지 실패하면 추가 발급을 중단한다.
4. 최신 CLI/엔진 staging 해시를 대조한다. 발급 및 실제 읽기 승인이 있는 경우에만 아래 형식으로 실행한다. `<run>`과 종료 UTC는 실제 검증 범위로 치환하며 미래 시각/정책 최대 범위를 넘기지 않는다.

```bash
STAGING=/home/kopo/soc-mall-lab/validation-7ab/auth-ready-20261017-62c894
READER_FILE='/home/kopo/soc-mall-lab/validation-7ab/secrets/reader-<run>.json'
RESULT='/home/kopo/soc-mall-lab/validation-7ab/results-<run>'
END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PYTHONPATH="$STAGING/src" \
 /home/kopo/soc-mall-lab/portal-lab/venv/bin/python \
 "$STAGING/deploy/security-mall/validate_correlation_triage.py" \
 --profile continuous --start 2026-10-16T00:00:00Z --end "$END_UTC" \
 --api-key-file "$READER_FILE" --output-dir "$RESULT"
```

`<run>`은 그대로 실행하지 않고 승인된 영숫자 run으로 치환한다. 결과 디렉터리는 기존 경로와 겹치지 않는 새 경로를 사용한다. 명령에는 키 파일 경로만 포함한다.

5. CLI가 자기 권한 검사 후 제한 검색·원본 대조·실제7-A/7-B 처리·격리SQLite의 revision/중복 방지/rollback 검증을 수행한다. 기존Portal/사건DB는 열지 않는다. 읽은 ES 문서의 source/seq/term/version을 재조회해 비교한다. 기존 전체 ES 문서를 모두 감사했다고 표현하지 않는다.
6. 종료 시 발급 사용자 인증으로 **이번 단일ID**만 invalidate한다. 폐기 결과와 새 키의401을 확인한 뒤 해당 비밀 파일만 제거한다. 폐기 실패·대상 불명확 시0600 상태로 보존하고, 재발급·기존 키 폐기·무조건 삭제 없이 오류 코드와 비밀 없는 메타데이터만 보고하고 중단한다. TTL 만료를 명시적 폐기 성공으로 간주하지 않는다.

## 준비 상태와 검증 한계

테스트는 합성 키와 메모리상의 ES 응답만 사용한다. subprocess는 실제 main/Reader/urllib Request 구성/정규화/7-A·7-B/SQLite를 실행하며 ES transport만 대역으로 바꾼다. Windows subprocess에서는 POSIX 보호 파일 로더만 대체하되 Linux에서는 그 대체 없이 실제 openat/UID/mode/링크 검사를 수행한다. 실제 ES 인증, 키 발급·폐기, TLS 핸드셰이크, 현재3종 증거 연결은 이번 테스트의 성공에 포함하지 않는다.

2026-10-17 결과: 신규 고유15개 테스트 메서드와 영향받은 기존4개가 통과했다. Windows에서 실행할 수 없는 POSIX 전용4개는 VM에서 실제 파일로 검증했다. VM에서는 POSIX 로더를 대체하지 않은 CLI 정상/인증 오류도 실행했다(고유6메서드, 변경된 소유권 검사1개만 추가 재확인). 새 의존성 설치 없이 표준 unittest를 사용했다. Pyflakes 기존 wheel로 변경 Python3파일 진단0이다.

최초 실행의 합성 로그인 account_id=null은 기존 로그인 계약에 맞게 합성 가명으로 수정했고, Windows pytest 임시 경로 권한 오류는 새 workspace 임시 경로로 고쳐 실패 항목만 재확인했다. 실제 앱/파서 정책은 바꾸지 않았다. 최종 VM staging40파일 SHA-256이 로컬과 일치하며 별도 디렉터리만 추가했다. 실키·ES·기존 서비스·사건DB에는 접근하지 않았다.

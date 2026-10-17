# Security Mall 7-A/B 검증 전용 읽기 키 발급 계획

2026-10-17. **계획만 준비했다. 신규 키 발급·폐기·기존 키 수정·권한 확대는 미실행**이며 별도 승인 후 수행한다. 신규 키를 Portal/수집 서비스에 배포하지 않고 일회성 검증 프로세스에서만 사용한다.

후속 승인 반영: 사용자가2h 신규 키 발급·읽기 검증·이번 키 폐기를 승인하되 **사용자 인증은 VM 콘솔에서 직접 입력**하도록 지정했다. 따라서 아래의 저장된 관리자 암호 파일을 읽는 이전 계획은 이번 실행에 사용하지 않는다. [승인된 콘솔 실행 절차](security_mall_ab_approved_console.md)를 우선하며, 실제 발급/검증/폐기 완료는 lifecycle과 실제 summary 확인 후 별도 기록한다.

## 실제 확인한 범위

VM `collection-services/config/collection.json`과 `portal-lab/config/mall-scope.json`의 실제 값으로 다음6개 정확한 이름을 정했다. wildcard/운영/합성 인덱스를 추가하지 않는다.

| 인덱스 | 필요 이유 |
|---|---|
| `soc-host-raw-mall-isolated-continuous-20261017-42062f13` | 현재 앱 감사 원본 |
| `soc-host-raw-mall-edge-isolated-continuous-20261017-42062f13` | 현재 웹 접근·WAF 정제 원본 |
| `soc-normalized-mall-continuous-20261017-42062f13` | 현재 세 로그의 정규화 이벤트 |
| `soc-host-raw-mall-isolated-20261016-8a070063` | 기존 실제 ACCESS 경보가 참조하는 원본 |
| `soc-normalized-mall-isolated-20261016-8a070063` | 기존 ACCESS 경보가 참조하는 정규화 문서/해시 |
| `soc-mall-alerts-lab-live-20261016-f56deb49` | 기존 실제 탐지 경보 |

앞3개만 읽으면 요청3종 연관은 시험할 수 있지만 기존 ACCESS 경보의 exact provenance/해시까지 검사할 수 없으므로 뒤3개도 필요하다. processing/status·별도 합성 AUTH·다른 서비스 인덱스는 제외한다.

2026-10-17T08:54:07Z의 실제 `_has_privileges` 결과에서 기존 Portal 키는 뒤3개 read/view만 허용하고 앞3개는 거부했다. 기존 검증용 키는 UTC2026-10-16 17:51:24.397(KST10/17 02:51:24) 만료다. 사용자도 대체 읽기 키가 없다고 확인했다. normalizer의 쓰기 가능한 키나 관리자 인증으로 데이터를 읽어 우회하지 않는다.

## 부여할 최소 권한

신규 키의 cluster 권한은 `[]`, 정확한6개 인덱스에만 `read`, `view_index_metadata`를 준다. read는 search/get/mget, view_index_metadata는 정확한 인덱스의 매핑/필드/alias 여부 점검에 사용한다. write/index/create_doc/delete/manage·auto_configure·템플릿/파이프라인/사용자·키 관리 권한을 주지 않는다. [공식 권한 정의](https://www.elastic.co/docs/reference/elasticsearch/security-privileges).

검토용 요청 본문은 [validation-read-key.request.example.json](../deploy/security-mall/validation-read-key.request.example.json)이다. **비밀값은 없으며 전송하지 않았다.** 승인 시 name에 고유 run 접미사를 붙이고 explicit role_descriptors를 유지한다. 빈/생략 role_descriptors로 발급하지 않는다. 기본 TTL은2시간이며 자동 연장/재발급하지 않는다.

이 키는 인덱스 단위 권한이다. 조직·사이트 문서 수준의 DLS 권한을 새로 구성한 것이 아니다. 검증 CLI와 엔진에서 기존 organization=`mall-isolated`, host=`mall-host-isolated`, service=`security-mall`, 서버 사이트 binding·시간 범위를 별도로 강제한다. 전용 사이트 인덱스라는 전제가 맞지 않으면 중단한다.

## 발급 주체와 인증

발급 주체는 소유 키 생성이 가능한 `manage_own_api_key`와 해당 인덱스 읽기 권한을 가진 **사용자 인증**이 필요하다. 발급 권한과 신규 키의 사용 권한은 다르며 새 키에는 키 관리 권한을 넣지 않는다. 기존 API Key로 권한 있는 자식 키를 만들려 하지 않는다. [공식 Create API key 문서](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key).

이 실습에서는 기존 보호된 ES 초기화의 사용자 인증을 단발 발급/폐기에만 사용하는 계획이다. 현재 다음 두 파일은 UID1000·0600·일반파일·symlink아님을 stat으로 확인했으며, 이번 계획 조사에서는 관리자 암호 내용을 읽지 않았다.

- 관리자 비밀번호 파일: `/home/kopo/soc-mall-lab/es-lab/runtime/elastic-password`
- CA: `/home/kopo/soc-mall-lab/es-lab/runtime/certs/ca.crt`

인증 값은 승인 후 VM 프로세스 내부에서 읽어 HTTPS 요청에만 넣는다. 터미널 인자·shell history·환경 출력·디버그 로그·소스코드에 넣지 않는다. 연결은 `https://127.0.0.1:19200` 고정, CA·호스트 검증 활성화, 프록시/자동redirect 차단이다. sudo·서비스 변경은 필요하지 않으며 권한 문제가 생기면 우회하지 않고 중단한다.

## 승인 후 안전한 순서 — 현재 실행하지 않음

1. 정확한6개 인덱스 설정·CA·기존 키 파일 해시를 재확인한다. 기존 Portal 및 collection 키는 읽기/비교 외에 쓰지 않는다.
2. 사용자 소유 `/home/kopo/soc-mall-lab/validation-7ab/secrets`를0700으로 준비하고 소유자·상위 경로·symlink를 확인한다. `umask 077`을 적용한다.
3. 보호 파일에서만 관리자 사용자 인증을 읽어 `POST /_security/api_key`로 **위 요청1건**을 보낸다. 이름은 고유 run 단위로 하고 무조건 재시도하지 않는다. 이는 신규 보안 키 메타데이터 생성이며 원본·정규화·경보 문서에는 쓰지 않는다.
4. 응답을 stdout으로 출력하지 않고 VM의 `reader-<run>.json`에 id/encoded/expiration을0600으로 저장한다. 새 파일 exclusive 생성, nlink/UID/mode 확인·flush/fsync를 적용하며 기존 파일을 덮어쓰지 않는다. Windows/Git/보고서로 키 파일을 복사하지 않는다. 요약에는 권한·만료 시각·저장 성공 여부만 남긴다.
5. 저장 실패 시 캡처한 **이번 신규 id 하나만** 발급 주체로 invalidate한다. 폐기 확인도 실패하면 추가 발급을 멈추고 상태를 보고한다. 이름만으로 다른 키를 일괄 폐기하지 않는다.
6. 새 키로 `_has_privileges`를 조회해 정확한6개 read/view=true·쓰기/삭제/관리=false를 확인한다. 허용 밖 인덱스 권한도 false인지 확인한다. 실제 문서 쓰기/삭제를 시도하는 부정 시험은 하지 않는다. 부족한 권한을 자동으로 확대하지 않는다.
7. 필요 매핑 조회와 제한된 `_search`/`_mget`를 새 키로 수행한다. 클러스터 root/health/전체cat 조회를 위해 monitor 권한을 추가하지 않는다. 기존 실제 CLI도 불필요한 root 조회를 제거한 상태다.
8. 검증 CLI에는 필수 `--api-key-file`로 새 보호 파일 **경로만** 연결한다. [CLI 인증 준비 절차](security_mall_validation_reader_cli.md)에 따라 소유권·0700/0600·링크·만료·유효 권한 및 정확한6인덱스를 검증한다. Portal 키 기본값은 제거했으며 기존 Portal 설정/파일을 교체해서 우회하지 않는다. 실제 발급/읽기는 여전히 별도 승인 대상이다.
9. 결과는 기존처럼 새 private SQLite에만 저장하고 실ES 문서의 ID/source/seq/term/version을 전후 대조한다. 실제 AUTH가 없거나 반복 요청이 부족하면 생성하지 않는다. 원문/가명/키를 결과에 출력하지 않는다.

## 만료·폐기

- TTL2시간, 시작 시 서버 발급 expiration을 확인하고 잔여 시간이 부족하면 검증을 시작하지 않는다. 진행 중401/만료면 중단하고 부분 결과만 기록한다. 자동 연장·새 키 발급은 없다.
- 검증 종료 또는 승인 철회 시, 발급 주체 사용자 인증으로 `DELETE /_security/api_key`에 **저장한 이번id 하나**를 `ids`로 전달한다. 키 이름 wildcard/전체폐기는 금지한다. [공식 Invalidate API keys 문서](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-invalidate-api-key).
- 대상id의 invalidated 결과와 폐기 후 인증401을 확인한 뒤 새 키 비밀 파일만 제거한다. 기존 Portal/수집 키와 보호 파일은 그대로 둔다. 권한/보존 계획과 비밀 없는 만료·폐기 결과는 남긴다. TTL 만료만 기다리는 것을 명시적 폐기 성공으로 보고하지 않는다.
- 새 읽기 키에는 폐기 권한이 없으므로 스스로 관리 작업을 하도록 권한을 추가하지 않는다. 발급 때 확인한 소유 사용자 절차로만 폐기한다. 키 폐기는 ES 이벤트/기존 경보 삭제와 다르다.

## 현재 중단 상태

기존 키의 허용 범위에서는 실제raw4/norm4/ACCESS1·hash1·우선순위20/low·격리revision방어와 기존9문서 불변을 확인했다. 과거4건은request_id가 없어unlinked이며 현재3종연관은 미완료다. 신규 키를 발급하거나 권한을 바꾸지 않았다. **다음에는 새 임시 읽기 키 발급과 지정 경로 사용을 별도로 승인받은 뒤 재개한다.**

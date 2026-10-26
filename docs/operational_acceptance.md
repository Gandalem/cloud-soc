# 독립 SOC 첫 경보 인수

2026-10-19 개발 범위: 실제 워커의 선택 규칙/revision 보고, Portal 표시, 지정 경보의 읽기 전용 근거 대조와 범용 사이트·ModSecurity 연결. 초기 합성 SSH 시험에 이어 WSL의 격리 TLS ES에서 **실제 Nginx HTTP→Filebeat→상주 정규화/탐지→경보/근거**, ModSecurity·CRS의 탐지 전용/활성 모드를 추가 시험했다. **호스트용 설치 프로그램을 통한 새 장치 설치·기존 중앙 서버 배포·Mall 로그인/SQLi·Slack 채널 수신 인수는 수행하지 않았다.** 격리 검증을 운영 성공으로 사용하지 않는다.

## 제품 경계

2026-10-19 사용자 재확인: 이번 개발의 목표는 특정 앱 없이 사용하는 범용 SOC다. 아래 기본 흐름과 다중 사이트 범위·운영 복구가 우선이며, Mall 전용 연결은 기본 제품의 필수 인수 조건에서 제외한다.

- 기본 제품은 Windows/Ubuntu 시스템 로그와 선택한 일반 웹/네트워크 로그를 수집하는 SOC다. Security Mall 설치는 필요하지 않다.
- 일반 Apache/Nginx 접근 기록은 HTTP 상태·경로·관측 IP를 설명한다. 로그인 성공 여부·주문 소유권을 증명하지 않는다.
- `WEB-ACCESS-01`, `WEB-AUTH-01`은 선택 앱 감사, `WEB-WAF-01`은 선택 앱 WAF 계약을 요구한다. 현재는 Security Mall 전용이다. 범용 탐지라고 표시하거나 다른 서비스에 자동 적용하지 않는다.
- `organization.id`는 수집 분류이며 단독으로 조직 격리를 보장하지 않는다. 기존 서버 계정/조회 정책/인덱스 권한 검사를 함께 유지한다. 사이트를 합쳐 기존 Mall 단일 host/service 상관 범위로 조회하지 않는다.

## 범용 다중 사이트 개발 프로필

`web-access-agent-v1` 수집 패키지 계약은 유지한다. 새 정규화 버전 `web-access-site-v2`는 설정된 `service.id`와 호스트·HTTP 메서드/상태를 최상위 공통 이벤트에 보존한다. URL/Host 헤더로 사이트를 추정하지 않는다. 수집 설정에서 사이트마다 다른 ID와 전용 접근 로그 파일을 지정해야 한다. 같은 ID를 같은 호스트의 서로 다른 사이트에 재사용하면 그 경계는 구분할 수 없다.

새 `WEB-SITE-404-001`은 조직·호스트·사이트·관측 출발지별 300초 동안 고유 접근 기록 20건을 집계한다. 기존 호스트 단위 `WEB-404-001`의 revision과 배포 인수 이력을 유지하며 새 버전 이벤트는 기존 규칙에 중복 입력하지 않는다. 앱 로그인/주문 권한·SQLi 탐지가 아니다. 쇼핑몰 YAML이 없는 설치에서도 기본 명시 선택·지정 경보 인수·운영 상태 조회를 사용할 수 있다. 앱 규칙을 명시 선택하면 해당 확장 파일은 필요하다.

기존 워커는 자동 전환하지 않는다. 전환 시 기존 상태 파일을 보존하고 새 적용 시점과 별도 상태를 지정한다. 적용 시점 이전은 기존 ID/버전, 이후는 새 ID/버전을 사용하며 같은 상태에서 적용 시점 변경/해제를 거부한다. 기존 체크포인트에 옵션을 덧붙여 사용하면 거부한다. 과거 데이터 자동 재정규화·기존 경보 삭제는 수행하지 않는다. 별도 워커를 도입할 때 기존 워커와 원본 기간이 겹치지 않게 종료/시작 범위를 계획한다.

```bash
# 기존 processing bootstrap으로 service/http 매핑을 먼저 명시 준비한다.
# START는 동일하게 보존할 UTC 수신 기준 시각이다. 검토한 전환 시점을 지정한다.
python -m cloud_soc.processing --run --start "$START" \
  --web-site-v2-start "$START" --state state/site-normalizer.sqlite \
  --es-url "$SOC_ES_URL" --ca-file "$SOC_CA" --api-key-file "$SOC_NORMALIZER_KEY_FILE"
python -m cloud_soc.detection --run --start "$START" \
  --additional-rules WEB-SITE-404-001 --state state/site-detector.sqlite \
  --es-url "$SOC_ES_URL" --ca-file "$SOC_CA" --api-key-file "$SOC_DETECTOR_KEY_FILE"
```

이것은 명시적으로 선택하는 개발/인수 프로필이다. 고정 `runtime-policy.json`의 운영 검증 규칙·일반 배포 명령은 자동 확대하지 않는다. 실제 적용 전에 새 규칙 revision/시점/매핑/상태·인수를 포함한 배포 정책을 검토해야 한다.

Portal 통합 로그의 **사이트 ID** 필터는 조직 권한과 함께 완전 일치로 적용하며 페이지 이동에도 범위를 유지한다. 새 경보에는 사이트/호스트 ID가 저장된다. 경보 상세의 **사이트 주변 로그**는 저장된 SHA 근거로 범위를 확인한 뒤 같은 조직·호스트·사이트·출발지의 정규화 로그를 매번 다시 조회한다. 경보 구간부터 이후 5분, 최신 50건까지이며 창을 열어 둔 동안 15초마다 갱신한다. 조회 실패 시 이전 결과를 지운다. 주변 관측은 원래 탐지 근거에 추가되지 않으며 동일 요청·앱 내부 감사·침해 성공을 증명하지 않는다. 이전 경보는 사이트를 추정하지 않는다.

재현 도구: `tools/validate_generic_web.py prepare`로 별도 디렉터리/짧은 시험 키/원본 인덱스·수신 파이프라인을 만든 뒤 `tests/fixtures/generic-web.compose.yaml`의 독립 Nginx 2사이트와 실제 Filebeat9.5.2를 시험 ES 전용 Docker 네트워크에 시작한다. `exercise`는 실제 HTTP 요청·각 사이트 10건의 합산 차단·각20건의 별도 경보·원본 URL 제거·범위 조회·읽기 전용 근거 인수·상주 CLI 재시작을 수행한다. 운영 클러스터에는 실행을 거부한다. 시험 키는 종료 시 폐기하고 실제 호스트 설치/브라우저/Slack 수신은 별도 인수로 남긴다. `SOC_GENERIC_FIXTURE`/`SOC_TEST_NETWORK`에는 생성한 독립 시험 경로/네트워크만 지정한다.

## 범용 ModSecurity 선택 수집

패키지의 웹 사이트 설정에 **ModSecurity 감사 로그**와 **로그 시각의 UTC 오프셋**을 지정하면 같은 사이트에 독립 WAF 입력이 추가된다. API 설정에서는 사이트 객체에 `modsecurity: {log_path: "/var/log/modsecurity/audit.json", timezone: "+00:00"}`를 선택 추가한다. 현재 지원하는 입력은 **ModSecurity v3의 한 줄 JSON 감사 로그**다. v2 native/multipart 형식을 이 입력에 넣으면 전송하지 않는다. 기존 Mall의 native AKZ 수집 계약은 보존하며 이를 범용 지원으로 표시하지 않는다.

수집기는 큐에 넣기 전에 URI·본문·헤더·쿠키·메시지·매칭 값·규칙 파일 경로를 제거한다. 서버에서 설정한 사이트 ID, 감사 시각, 관측 IP, HTTP 메서드/상태, 불투명 요청 ID, 규칙 ID/CRS 버전, 엔진 모드와 엔진 개입 관측만 남긴다. ModSecurity v3의 지역 시각에는 시간대가 없으므로 수집 설정의 명시 오프셋으로 UTC를 계산한다. 일반 파일/journal/Docker 경로를 통한 감사 JSON 우회 전송도 차단한다. 사이트 수집을 끄면 접근/WAF 입력을 함께 끄며 Filebeat 상태·큐·키를 초기화하지 않는다.

`WEB-SITE-WAF-001`을 별도 추가 규칙으로 선택한다. 같은 조직·호스트·사이트·관측 IP에서 300초 동안 서로 다른 요청 ID 3개가 CRS SQLi 8개 ID allowlist 중 하나를 보고할 때 경보를 만든다. 같은 요청의 여러 규칙·재정규화 문서는 여러 요청으로 세지 않는다. 진단/점수 집계 전용 ID와 CRS 버전이 없는 사용자 규칙은 SQLi로 분류하지 않는다. 기존 `WEB-WAF-01`은 별도 앱 확장으로 유지한다.

`DetectionOnly`는 탐지 전용으로 표시한다. `On`에서도 HTTP403만으로 차단 성공을 선언하지 않으며, 감사 로그의 `is_interrupted` 유무에 따라 엔진 개입 관측/미관측을 표시한다. 오래된 엔진에서 이 값이 없으면 `unknown`이다. 앱 인증·인가·주문 처리·침해 성공은 별도 감사 증거가 필요하다. Portal은 모드와 관측을 경보 상세에 표시하고 사이트 주변 로그와 원래 탐지 근거를 구분한다.

JSON/모드 해석 근거: [ModSecurity 공식 JSON 직렬화](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/transaction.cc), [공식 CRS 컨테이너의 감사·엔진 설정](https://github.com/coreruleset/modsecurity-crs-docker#modsecurity-configuration-options). 실제 시험 도구는 `tools/validate_generic_waf.py`이며, `generic-web.compose.yaml --profile waf`에는 시험에 기록한 `SOC_TEST_WAF_IMAGE` digest와 `SOC_TEST_WAF_MODE=DetectionOnly` 또는 `On`을 지정한다. 두 모드는 서로 다른 디렉터리/조직/원본 인덱스/SQLite로 시험한다. 현재 배포 정책의 검증 규칙과 기존 서비스는 자동 변경하지 않는다.

## 실제 실행 규칙 확인 (화면 표시)

관리자 또는 기존 정책에서 전체 운영 상태 조회가 가능한 계정으로 **관제 상세 → 분석 상태 → 실제 워커의 규칙·버전 확인**을 연다. 조직 제한 사용자는 전역 워커 정보를 받지 않는다.

| 표시 | 의미 |
| --- | --- |
| 상주 실행 관측 | 300초 안에 보고한 연속 워커가 현재 Portal 코드와 같은 revision/엔진의 규칙을 선택함 |
| 선택 보고만 확인 | 스냅샷/과거 검토 모드 등의 선택 보고이며 상주 실행 증거는 아님 |
| 보고 만료 / 실행 실패 | 이전 선택 기록은 있지만 현재 작동을 인정할 수 없음 |
| 현재 코드와 버전 다름 | 보고한 revision 또는 엔진이 Portal의 현재 카탈로그와 다름 |
| 실행 보고 없음 | 조회한 워커에서 해당 규칙의 선택 기록을 관측하지 못함 |
| 미확인 | 워커 조회 실패 또는 revision 보고가 없는 이전 워커가 있어 판단 불가 |

각 관측 워커의 전체 revision·마지막 성공·처리 위치를 펼쳐 확인할 수 있다. 목록은 **화면 조회/새로고침 시점의 보고**이며 자동 갱신되지 않는다. 상태는 입력의 존재, 모든 입력의 평가 완료, 특정 경보 생성, 서비스 자동 재시작 또는 Slack 전달을 증명하지 않는다. 실제 평가의 입력 수/제외/생성 경보는 기존 **분석 중단·지연 확인** 화면의 committed 규칙 실행 이력과 경보의 근거에서 확인한다.

워커는 `soc-pipeline-status`의 기존 문서에 `runtime` 메타데이터를 추가한다. 기존 인덱스에 필요한 비색인 `enabled:false` 매핑은 공통 정규화 준비 단계에서 추가한다. source-only 보관이므로 상태 API도 이 필드를 `_source`로 읽는다. 이전 워커에 대해서는 문자열 `detection`이나 YAML `enabled:true`로 revision을 추정하지 않는다. 공통 배포 정책의 검증된 7개 ID/revision과 기존 상태 identity는 그대로 유지한다.

## 최소 인수 시나리오

기존 [처음 설치 안내](../README.md), [공통 배포·복구](runtime_deployment.md), [실제 시험 절차](installation_reference.md)를 사용한다. 새 설치와 기존 설치 복구를 별개로 수행한다.

1. 새 Ubuntu 서버에서 공통 설치기를 실행하고 Portal 관리자 로그인·CA 검증·필수 워커 상태를 확인한다. 기동 성공만으로 인수를 마치지 않는다.
2. Portal에서 대상 Windows 또는 Ubuntu용 새 패키지를 생성하고 SHA256을 대조한 뒤 대상 장치에 설치한다. 수집 항목과 조직을 기록한다.
3. 시험 시작 시각을 UTC로 기록하고 본인 소유의 시험 대상에서 승인된 인증 실패 시나리오를 실행한다. 이벤트 수/시각/호스트를 기록하고, 운영 계정을 잠그지 않는 기존 실습 절차를 사용한다.
4. 새 원본 → 정규화 → 상주 탐지 → 새 `AUTH-001` 최종 경보의 **정확한 ID**를 Portal에서 확인한다. 현재 기본 규칙은 5분 내 실패 10건이다. 초기 통지는 최종 경보와 구분한다. 정규화 지연과 기본 lateness 900초를 고려하고, 오래된 경보를 새 시험의 결과로 쓰지 않는다.
5. 아래 도구로 해당 경보의 모든 근거를 대조한다. Portal의 실제 로그인·경보 상세·근거 버튼도 브라우저에서 확인하고, 다른 조직/보호 원문 차단을 확인한다.
6. Slack 연동을 사용하는 경우 테스트 메시지와 신규 최종 경보의 수신을 따로 확인한다. 실제 채널의 경보 ID를 Portal ID와 대조한다. HTTP 성공/outbox 상태만으로 채널 수신을 대신하지 않는다.
7. 승인된 재시작 후 같은 시험 범위의 기존 ID·근거·체크포인트가 보존되고 중복 경보가 생성되지 않는지 확인한다. 기존 큐·키·DB를 삭제하지 않는다.

## 지정 경보 근거 대조 CLI

새 `python -m cloud_soc.acceptance`는 명시한 조직·규칙·시각·원본 인덱스와 저장된 경보 하나를 읽는다. 일반 공통 인덱스(`soc-normalized-v1`, `soc-processing-v1`, `security-alerts`)용이며 Mall 격리 인덱스 계약은 기존 [9-C 도구](archive/README.md#record-docs-security-mall-9c-predeployment-md)를 사용한다.

프로젝트 의존성이 설치된 환경에서 실행한다. 아래 주소/경로/ID/시각은 자리표시자다. 별도 관리자에 의해 준비된 **읽기 전용 키 파일**과 신뢰할 CA를 사용한다. 키 값은 인자에 넣지 않는다. 키에는 선택한 정확한 원본 인덱스, 공통 정규화/처리/경보/상태 인덱스의 `read`, `view_index_metadata`가 필요하다. 도구는 키 발급·권한 변경을 하지 않는다. `soc-pipeline-status`는 전역 메타데이터이므로 전체 운영 상태를 조회할 수 있는 관리자 환경에서 실행한다.

```bash
PYTHONPATH=src python -m cloud_soc.acceptance \
  --es-url https://soc.example.com:9200 \
  --ca-file /secure/cloud-soc/ca.crt \
  --api-key-file /secure/cloud-soc/acceptance-reader.key \
  --organization team-a --rule-id AUTH-001 \
  --alert-id PORTAL_FINAL_ALERT_ID \
  --since 2026-10-19T00:00:00Z \
  --raw-index soc-host-raw-ACTUAL_INDEX \
  --report /secure/cloud-soc/acceptance-UNIQUE_RUN.json
```

원본 인덱스는 실제 소문자 concrete 이름으로 바꾸고 필요하면 `--raw-index`를 반복한다(최대 32개). 와일드카드·alias·data stream으로 범위를 확대하지 않는다. 새 경보 ID는 Portal 상세에서 얻는다. 도구는 새 이벤트를 만들거나 경보를 저장하지 않는다.

검사 항목:

- 선택 조직에서 경보를 볼 수 있고 규칙 ID·전체 snapshot·revision·엔진이 현재 코드와 일치한다.
- 근거가 비어 있지 않고 1,000건 이내이며 지정한 정확한 원본 인덱스에 속한다.
- 모든 정규화 문서의 탐지 당시 SHA256, 원본 참조, 조직이 일치한다. 모든 정규화 처리 기록도 같은 원본/정규화 참조를 가리킨다.
- 현재 원본을 기존 정규화기로 다시 계산한 ID/내용이 저장된 정규화와 일치한다. 원본 전체에 대한 탐지 당시 해시는 없으므로 `raw_integrity=not_hashed_at_detection`을 유지한다.
- 모든 원본 발생/수신 시각과 정규화 처리 시각이 시험 시작 이후이며 미래가 아니다. 증거 중복과 경보 이벤트 수 불일치를 거부한다.
- 현재 신선한 연속 탐지 워커가 해당 revision을 보고하고 마지막 성공·체크포인트가 해당 정규화 수신을 지났다. 스냅샷/만료/미래 성공 시각을 인정하지 않는다.

종료 코드 `0`은 저장 근거 검사 통과, `2`는 근거 부족/불일치, `1`은 설정·TLS·권한·조회·보고서 쓰기 실패다. 조회 실패를 0건이나 통과로 변환하지 않는다. 보고서에는 선택 규칙/revision·검사 결과·건수만 담고 원문·사용자·IP·키·예외 본문을 넣지 않는다. 보고서는 새 파일로만 생성하며 기존 결과를 덮어쓰지 않는다.

`pipeline_evidence=passed`도 전체 E2E 완료가 아니다. 경보 문서와 현재 워커를 대조한 것이며 특정 프로세스가 그 경보를 만들었다는 추적 증명, 실제 새 OS 설치, 브라우저 인수, 재부팅 및 Slack 채널 수신을 자동 증명하지 않는다. `full_acceptance`, `browser`, `slack_channel_receipt`는 항상 `unverified`로 남긴다. 일반 공통 배포의 기존 `manage.py verify`도 함께 사용한다. 이 검증의 AUTH 조회에는 이제 인수 시작~현재 시각 범위를 강제하여 과거 경보 재사용을 막는다.

## 실제 연결이 필요한 후속 작업

| 작업 | 완료 기준 | 현재 상태 |
| --- | --- | --- |
| 최신 범용 패키지 설치 | 새 Windows/Ubuntu 패키지의 설치·새 원본·정규화·새 경보 ID | 실환경 미검증 |
| 일반 웹 로그 | 특정 앱 없이 Apache/Nginx/Docker 접근 로그→정규화→범용 웹 규칙→경보 근거 | 새 경로의 실수신 인수 필요 |
| 다중 사이트/조직 | 같은 호스트의 여러 service.id 보존·탐지 분리·타 조직 접근 차단 | 일반 정규화 service.id 보존 및 웹 규칙의 사이트 범위 보완 필요 |
| 범용 요청 연관 갱신 | 조직/사이트/호스트/요청 범위별 checkpoint·원자 발행·누락/지연·재시작·권한 인수 | 범용 상주 발행 미구현; 기존 Mall 고정 snapshot을 일반화 완료로 보지 않음 |
| 설치 복구 | 기존 키/큐/상태 보존, 부분 설치·중복 설치·재등록·재시도 실환경 대조 | 기존 복구 경로 유지, 신규 실환경 인수 없음 |
| Slack 범용 신규 경보 | 시험 시작 이후 일반 규칙의 최종 경보 ID와 실제 채널 수신 대조 | 실수신 미검증 |

이 항목들은 UI·합성 테스트가 통과했다고 완료 표시하지 않는다. 현재 중앙 서버 주소·접속 계정과 승인된 시험 대상이 제공되면 단계별로 근거를 보존하며 진행한다.

Mall의 ACCESS/AUTH/WAF와 실제 로그인/SQLi 시험은 선택 앱 확장의 별도 인수 항목이다. 기존 코드를 보존하며 범용 SOC의 설치·운영·검증에 요구하지 않는다. 일반 웹 로그만으로 로그인 성공이나 주문 소유권을 판단하는 기능으로 바꾸지 않는다.

## 2026-10-19 WSL 검증 결과

### 범용 사이트·ModSecurity 추가 인수

기존 합성 SSH 시험 이후, 독립 Nginx 2사이트와 실제 Filebeat9.5.2를 사용한 추가 인수를 완료했다. 원본/정규화 입력은 HTTP 요청이 실제 생성한 로그이며 관리자가 ES에 탐지 이벤트를 직접 주입하지 않았다. 기존 서버 상태 대신 전용 디렉터리/짧은 키/원본 인덱스·조직/SQLite를 사용했다.

| 검증 | 실제 결과 |
| --- | --- |
| 일반 웹 2사이트 | 54검사 통과. 각 사이트 10건은 합쳐 경보를 만들지 않고 각20건에서 각각1경보. 추가 정상 요청 포함 원본41·정규화41·경보2. 상주 CLI·같은 상태 재시작·중복0·시간/범위/근거 인수·주변 로그 갱신 확인. |
| ModSecurity DetectionOnly | 실제 CRS SQLi 요청3건, 백엔드200/WAF경유200, 엔진 개입 미관측, 사이트 경보1·SHA/원본/워커 인수12검사 통과. |
| ModSecurity On | 별도 조직/상태에서 실제 CRS SQLi 요청3건, 백엔드200/WAF경유403, 엔진 개입 관측, 사이트 경보1·SHA/원본/워커 인수12검사 통과. SOC의 앱 결과 판정은 여전히 미확정. |
| 실제 Chromium/Portal | 19규칙·실제 WAF 경보/모드/SHA·15초 갱신·사이트 필터·패키지 WAF 설정·타 조직404·390px/데스크톱 확인. pageerror0/API실패0. 시험 워커 종료 후 보고 만료는 그대로 표시한다. |

시험 WAF 이미지 digest는 `owasp/modsecurity-crs@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d`로 기록했다. 결과 요약은 Git 제외 `state/generic-e2e-summary.json`, 브라우저 근거는 `state/generic-browser-evidence.json`와 `state/generic-waf-browser-{desktop,mobile}.png`, 개별 private 원본/SQLite/모드별 보고서는 `state/generic-*-root.txt`가 가리키는 WSL 전용 캐시에 보존한다. 비밀 파일은 저장소에 넣지 않는다.

추가 전체 Python은 1934pass/1fail/17skip·하위348pass였다. 실패는 웹 조회 소스 기대 목록에 새 WAF를 넣지 않은 테스트였으며 수정 후 해당1건 통과. 조직별 새 경로·IPv6/시간 근거·범용 Slack 메시지 계약을 추가해 후속 회귀를 수행했다. 최종 고유1939사례 통과는 전체 실행+영향 사례 재검증의 합계이며 마지막 전체 재실행 수치가 아니다. Windows 영향 회귀78·조직/권한 WSL45 통과, JS 수집/화면54검사·Ruff·src/변경 도구 Bandit medium/high 통과다. 전체 tools 스캔의 기존 `verify_p5_disposable.py` 임시 디렉터리3건은 변경하지 않았다. Windows C# 새 소스 컴파일은 통과했지만 이 환경에서 실행 시 기존 .NET 예외가 발생해 Windows 실제 설치/재시작 인수를 대신하지 않는다.

호스트 설치 프로그램을 통한 새 장치 설치·부분 설치 복구 인수·ModSecurity v2 native의 범용 수집·실제 Slack 채널 수신·기존 중앙 배포는 미완료다. Slack은 실제 새 범용 경보가 기존 메시지 계약에 진입하는 격리 검증까지만 완료했다. `runtime-policy.json`의 검증7개와 기존 규칙 revision/상태는 유지한다.

### 초기 합성 SSH 인수 이력

사용자 요청으로 WSL2 Ubuntu 24.04.3에 전용 작업 사본·가상환경을 만들고, 기존 컨테이너가 없는 것을 확인한 뒤 별도 Docker 프로젝트·볼륨·CA·만료 키를 사용했다. 실제 장치/중앙 서버의 상태·키·로그를 사용하지 않았다. OS/방화벽/시스템 Python·Node·실행 정책은 변경하지 않았다.

| 검증 | 결과와 한계 |
| --- | --- |
| Linux Python 전체 회귀 | 최초 1,837 passed / 7 failed / 17 skipped, 하위 348 passed. 실패는 기존 Slack 기대값 2곳의 문자 `\\n` 오기였다. 실제 줄바꿈 계약으로 수정한 해당 7사례가 Linux/Windows 모두 통과했다. 합산 고유 1,844개 통과이며 최종 전체 재실행을 주장하지 않는다. |
| 실제 TLS ES/HTTP | Elasticsearch 9.5.2, 28개 검사 통과. 원본 16·정규화 14·처리 기록 16·AUTH 최종 경보 1, 최소 권한 거부·원문 감사·조직/역할·CSRF·새 지정 경보 근거 검사 포함. 원본은 관리자가 생성한 합성 시험 자료다. |
| 실제 연속 워커 | 정규화/탐지 CLI를 각각 별도 최소 권한 1h 키·SQLite·UID/GID 1000으로 실제 반복 실행. `runtime` revision과 새 체크포인트를 Portal에서 확인했다. 상주 배포의 OS 부팅/자동 복구 인수는 아니다. |
| 실제 브라우저 | WSL 격리 Chromium 156에서 로그인·17규칙 카탈로그·연속 AUTH revision·미실행 Mall WAF·경보 상세·SHA256/원본 참조·390px 화면 통과. JavaScript 오류/API 실패 0. 모바일 표는 가로 스크롤로 규칙 ID를 보존한다. |
| 실제 재시작 | 두 시험 CLI를 정상 종료 후 같은 키·시작점·SQLite로 다시 실행. 원본 16/정규화 14/처리 16/경보 1 유지, 동일 detector identity·체크포인트 진행·SQLite integrity ok. |
| 배포 이미지·권한 | 실제 이미지 빌드, 네트워크/호스트 마운트 없는 별도 Linux root 시험 컨테이너에서 실제 UID/GID/mode 19개 및 WAL·키·설정·outbox 보존 통과. `os.chown` 모의 없음. |
| 직접 UI/문서 회귀 | 변경 화면 DOM 18개, 최종 빠른 시작·상세 안내·로컬 링크/코드 구문 16개 통과. Ruff 전체·Bandit medium/high·pip check 통과. |

초기 WSL `/tmp` 재시작 유실과 배포판 종료에 따른 ES 중단, 호스트 루프백의 간헐 TLS/브라우저 시간 초과는 실패 결과로 보존했다. 사용자 캐시의 전용 사본과 유지 세션을 사용하고 브라우저·Portal을 같은 시험 컨테이너에서 실행하여 최종 인수했다. 타임아웃을 성공으로 무시하거나 TLS/호스트·권한 검사를 해제하지 않았다.

추가로 넓힌 스크립트 시험은 모든 플랫폼에서 통과한 것이 아니다. WSL Node 18.19.1은 CI의 Node 22 `v` 정규식을 지원하지 않고 Linux PowerShell이 없어 실패했으며, Windows 5.1의 스크립트 실행 정책·.NET 시험 환경에서도 실패가 있었다. 문서 길이/이전 링크 문제는 기존 상세를 `first_install_walkthrough.md`로 보존하고 125행 빠른 시작과 호환 앵커로 고쳤으며 최종 16개 문서 검사는 통과했다. Windows 실행 정책을 우회하거나 이 실패를 통과 수에 포함하지 않았다.

로컬 Git 제외 근거는 `state/wsl-pytest.xml`, `state/wsl-slack-delta.log`, `state/wsl-integration-passed.json`, `state/wsl-permissions.json`, `state/wsl-browser-passed.json`, `state/wsl-restart-passed.json`, `state/windows-guide-final.log`와 `output/playwright/runtime-browser-{desktop,mobile}.png`다. 초기 실패 로그도 별도로 남겼다. 실제 키/CA 개인키/SQLite는 WSL 사용자 전용 시험 캐시에 보관하며 저장소에 넣지 않는다.

인수 후 시험 CLI·Portal·ES와 전용 브라우저를 종료하고 남아 있던 시험 API 키 5개를 폐기했다. 증거·SQLite·시험 데이터 볼륨은 보존했다. 모바일 수정까지 포함한 최종 배포 이미지 빌드도 통과했으며 운영 서비스로 배포하지 않았다.

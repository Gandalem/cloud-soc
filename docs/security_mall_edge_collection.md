# Security Mall 6-C 웹/WAF 실제 수집·정규화

2026-10-16, 복제 VM `kopo@192.168.235.131`. **6-C 실습 인수 완료**.
기존 Apache/ModSecurity/CRS와 Filebeat9.5.2, Elasticsearch9.5.2를 재사용했다.
일회성 보호 추출과 독립 Filebeat/정규화 프로세스의 실제 검증이며 상주 수집기 배포는 아니다.

## 실제 결과와 범위

| 단계 | 접근 | WAF | 합계 |
| --- | --- | --- | --- |
| 기존6-B 입력 | 11줄 | 완전한 AKZ11개 | 22 |
| 최종 정제 | 11 | 11 | 22, 최종 거부0 |
| 실제 Filebeat→ES 원본 | 11 | 11 | 22 |
| 기존 normalize()→새 정규화 인덱스 | 11 | 11 | 22 |

- 원본: `soc-host-raw-mall-edge-isolated-20261016-faa605ec`
- 정규화: `soc-normalized-mall-edge-isolated-20261016-faa605ec`
- final pipeline: `security-mall-edge-final-20261016-faa605ec`
- 별도 합성 회전: `soc-host-raw-mall-edge-isolated-20261016-faa605ec-rotation`,4건.
- 신규 VM 작업 경로: `/home/kopo/soc-mall-lab/waf-collection-6c-20261016`.

초기 보수적 파서는 실제 Native의 마이크로초·선택적 action 인용부호·인자 없는 연산자의
구분 공백·action 없는 체인 하위 규칙을 거부했다. 관련 형식만 보완하고 설치된 규칙 대조를
유지했다. 실패한 WAF 부분만 재처리했으며 원본을 바꾸거나 수를 맞추기 위한 이벤트를 만들지 않았다.

## 코드 및 신뢰 경계

| 파일 | 역할 |
| --- | --- |
| src/cloud_soc/parsers/security_mall_edge.py | 버전 security-mall-edge-v1, TSV/Native/허용 필드 검증 |
| src/cloud_soc/web/mall_edge_projection.py | 비공개 원본 읽기→명시적 허용 필드 JSONL, 일회성 CLI |
| src/cloud_soc/portal/security_detail.py | 기존 어댑터 디스패치와 worker 필드 선택 계약 확장 |
| src/cloud_soc/processing/contract.py | 기존 normalize()의 제한된 edge 분기, 원본 참조 보존 |
| filebeat/security-mall-edge/ | 정제 전용 JS 및 독립 filestream/TLS/create-only 예시 |
| deploy/security-mall/waf-lab/edge-* | exact-index final pipeline/strict 매핑/최소 writer 역할 예시 |
| tests/test_security_mall_edge.py | 합성 개인정보·형식·체인·시각·중복 ID·provenance 시험 |

신규 어댑터를 기존 엔진에 연결했으며 별도 정규화/탐지 프레임워크는 만들지 않았다.
Portal UI/실행 코드 배포나 worker/Detector/알림 실행은 없다. 공유 모듈의 소스 변경이
현재 실행 중인 Portal에 배포되었다고 주장하지 않는다.

원본은 kopo 소유0600이며 읽기 가능함을 먼저 확인했다. chmod/실행 사용자 변경/root
Filebeat 없이 처리했다. 추출기는 일반 파일·동일 소유자·group/world 접근 없음·leaf symlink 금지,
16MiB 파일 상한/1MiB 트랜잭션 상한을 검사한다. 파일을 읽을 때 확인한 크기만 snapshot으로 읽고,
축소·읽기 실패·인코딩 오류는 원문 없는 고정 코드로 실패한다.
행/트랜잭션 거부는 고정 사유별 건수로 반환하고 유효 레코드만 별도 출력한다.
출력 디렉터리0700/새 JSONL0600, 기존 출력 파일은 덮어쓰지 않으며 원자적으로 인계한다.

Native A/K/Z 순서·동일 경계·완전한 끝을 요구한다. 잘못된/추가 섹션·URI가 붙은 A·미완성
체인은 거부한다. K의 규칙 선택자/연산자/변환/메시지 등은 설치된 CRS 소스와 대조하되 메시지,
logdata, 규칙 소스는 출력하지 않는다. ModSecurity가 덧붙이는 기본 phase/logging과 선택적
인용부호/인자 없는 연산자 구분만 정규화한다. 부분 체인(`#`)은 탐지 매치로 만들지 않는다.
심각도가 없는 제어/초기화 규칙·SecAction은 매치 목록에서 제외한다.
기존10002는 명시적 실습 옵션으로만 manifest에 포함하며 Apache에 새 규칙을 등록하지 않는다.

요청 ID는 알려진 Apache 설정과 사용자 소유 로그라는 신뢰 경계에서만 인정한다.
27자 형식 검증 자체는 Apache 생성의 암호학적 증명이 아니다. 임의 외부 로그를 신뢰 입력으로
사용하지 않으며 현재 Apache 설정의 SHA256이6-B와 같음을 확인했다.

## 정제/정규화 필드

원본 ES는 원시 요청 로그가 아닌 **보호된 메타데이터 투영본**이다.
root는 @timestamp/organization/host/labels/event/security_mall_edge만 허용한다.
organization.id=`mall-isolated`, host.id=`mall-host-isolated`는 수집 설정과 수신 pipeline에서
고정하고 애플리케이션/클라이언트 주장으로 정하지 않는다.

| 입력/투영 | 정규화 |
| --- | --- |
| TSV 발생 시각 / Native A 시각 | @timestamp, 원래 정제 시각은 cloud_soc.security_mall_edge.timestamp에도 보존 |
| Apache 생성 request_id | http.request.id, cloud_soc.security_mall_edge.request_id |
| 관측 peer | source.ip; 최종 사용자 IP를 추정하지 않음 |
| stream=access | event.kind=event, category=[web], action=http_access, HTTP 상태 기반 outcome |
| method / status_code | http.request.method / http.response.status_code |
| 고정 path 템플릿 | url.path; 임의 경로/쿼리는 허용하지 않음 |
| duration_us | event.duration=duration_us×1000(ns) |
| stream=waf | event.kind=event, category=[web], action=waf_rule_match, outcome=unknown |
| 규칙 ID/심각도/선언 동작 | cloud_soc.security_mall_edge.rules, severity 미기록은 생략 |
| 진단10002 | rules[].diagnostic=true, 공격/차단/경보로 간주하지 않음 |
| 신뢰 설정 DetectionOnly | engine_mode=DetectionOnly, blocked=false |
| scope+service+stream+request_id의 SHA256 | 원본 _id와 event.id, 정규화 event.id 유지 |
| 실제 원본 index/_id | cloud_soc.provenance.raw.index/id |
| 중앙 _ingest.timestamp | event.ingested; 클라이언트 값을 덮어씀 |

`rules[].action=block/deny`는 **설정에 선언된 동작**이며 실행된 차단을 뜻하지 않는다.
DetectionOnly에서 blocked=false를 유지한다. event.outcome=unknown은 공격 성공/실패 판단이 아니다.
실제 WAF11건 중 진단 포함2건/미포함9건이다. 모든11건에서 숫자 Host의920350도 관측되어
이번 자료에는 WAF 매치가 전혀 없는 실제 요청 사례가 없다. 초기화만 있는 가상 레코드는
매치 이벤트로 만들지 않는 것을 별도 시험했다.

**후속 설정 검토:** Native에서 CRS901001/critical도 관측했다. 설치된 규칙의 조건은
crs_setup_version marker 부재이며,6-A 최소 setup에는 해당 marker가 없다. 이는 설정 경고로
분리해서 검토해야 하며 공격으로 집계하지 않는다. 이번에는 Apache 변경/재시작 금지에 따라
고치지 않았다.920350도 정상 loopback 숫자 Host의 오탐 검토 항목이다. 임계값/예외는 불변이다.

11개 request_id를 각각 ES에서 조회해 access/waf 정확히2건·동일 조직/호스트를 대조했다.
다른/존재하지 않는 request_id와 결합하지 않았다. 정규화22건 모두 실제 원본 index/id·event.id를
확인했다. 앱 감사에는 request_id가 없어 **웹/WAF↔앱의 정확한 연결은 미구현**이다.
Native/접근 시각은 서로 다른 관측 지점/정밀도이므로 ID 연관을 시각 문자열 동일성으로 대체하지 않는다.
중앙 나노초 수신 시각은 원본에 보존하며 기존 정규화 datetime의 마이크로초 정밀도도 유지했다.

## 개인정보·수신 보안

쿼리/임의 경로·헤더/Cookie/Authorization/본문·매칭 문자열·규칙 메시지·원문 전체·
message/event.original을 정제 결과와 ES에 넣지 않는다. Native B/C/E/H 등 추가 섹션,
민감 표식을 붙인 규칙/A, 미지원 필드·중복 JSON 키·잘못된 JSON/타입을 거부했다.
JS는 새 객체와 허용 필드만 queue에 남기고 예외는 Cancel하며 입력 원문을 오류로 출력하지 않는다.
Apache error-private.log는 읽거나 Filebeat 입력에 포함하지 않았다.

실제 Filebeat 최초 added/done25건 중22건만 output/acked: 잘못된 JSON·message 필드·
중복 키3건은 전송 전 취소됐다. 최종 타입 가드의 배열 ID2건도 별도 실행에서 입력2/출력0으로
확인했다. 가상 표식이 ES 원본/정규화·Filebeat 진단에 없고 실제 API Key 값이 config/results/logs에
없음을 값 자체를 출력하지 않고 검사했다. 운영 비밀/HMAC/기존 DB는 읽지 않았다.

TLS CA/IP SAN 검증·프록시/리다이렉트 비활성화·고정 localhost19200만 사용했다.
관리자 인증은 설정/키 등록에만 사용하고 Filebeat는 정확한 신규 원본 인덱스1개의 create_doc와
연결 점검용 cluster monitor만 갖는2시간 키를 사용했다. 일반 index/write/delete/manage/read/
auto_configure, 기존 인덱스 접근, cluster manage/manage_security는 거부됐다.
키는 VM 보호 파일 및 전용 keystore에만 존재하며 정규화 키는 새 원본 read와 새 정규화
read/create_doc로 분리했다. 무결성 검사 전용 이전6인덱스 읽기 키는 검사 후 폐기했다.

실제 Painless 등록·simulate·strict/date_nanos/IP/nested 매핑과 고정 final pipeline을 확인했다.
위조 event.ingested는 서버 시각으로 바뀌었고 비허용 필드/잘못된 타입 simulate는 거부됐다.
클라이언트 pipeline=_none에 의존하지 않고 index.final_pipeline으로 필수 검증을 고정한다.

## 재전송·재시작·회전

- create_doc 키의 명시적 `index` Bulk는403, 실제 Filebeat create-only22건은 성공했다.
- 원본22건+내용 변경 동일 ID1건을 다른 registry로 전송: duplicates23, 최초 _source/seq_no/term 불변.
- 정규화22건 create 재전송:409 전부, 최초 문서 불변.
- 같은 원래 registry 재시작: 신규 added0, 원본22건 그대로.
- 별도 합성 인덱스에서 파일 append→rename .1→새 활성 파일→부분 JSON 보류/완성→immutable GZIP을
  실제 Filebeat로 확인했다. 총4건, 나머지 LF 전에는 부분 이벤트가 저장되지 않았다.
- fingerprint/growing/64바이트와 compression:auto를 사용했다. 파일별 앞64바이트가 달라야 하며,
  동일 앞부분 파일의 지문 충돌·registry 손실/copytruncate/갑작스러운 장애의 exactly-once는 보장하지 않는다.

설정 의미는 [Filebeat filestream 공식 문서](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream),
정제 guard는 [Script Processor 공식 문서](https://www.elastic.co/docs/reference/beats/filebeat/processor-script)를
참고했다. 문서 지원 여부와 위 실제9.5.2 실행 결과를 구분한다.

Apache 원본은 회전/수정하지 않았다. Native 파일별 완전 레코드/서로 다른 파일의 부분 조각을
결합하지 않는 것은 격리 시험했다. 실제 source Native rotation/copytruncate/원본 GZIP 추출은
미검증/미지원이며 압축 원본을 정제기 입력으로 지정하지 않는다. GZIP 성공은 **정제된 spool**에 한정한다.
일회성 추출은 지속 checkpoint가 없으므로 다음 실행 전 원본 보존/회전 손실을 검토해야 한다.

## 실행·운영 범위

기존 런타임/소스 경로를 준비한 뒤 사용자 kopo에서만 수행하는 추출 예:

```sh
LAB=/home/kopo/soc-mall-lab/waf-collection-6c-20261016
umask 077
PYTHONPATH="$LAB/src" /home/kopo/soc-mall-lab/portal-lab/venv/bin/python \
  -m cloud_soc.web.mall_edge_projection \
  --access /home/kopo/soc-mall-lab/waf-lab/logs/access.tsv \
  --native /home/kopo/soc-mall-lab/waf-lab/logs/waf-audit.native \
  --crs-directory /usr/share/modsecurity-crs/rules --allow-lab-diagnostic-10002 \
  --organization mall-isolated --host mall-host-isolated \
  --output "$LAB/input/NEW-PRIVATE-PROJECTION.jsonl"
```

새 출력 이름을 사용하고 정제 보고의 거부 사유를 검토한 뒤에만 Filebeat로 인계한다.
재실행 시 단기 키 만료·정확한 인덱스/manifest·권한을 확인해야 하며 기존 registry 삭제/원본 glob 확대를 하지 않는다.
수신 예시는 배포 파일 EDGE_* 자리표시자를 정확한 새 경로/인덱스로 지정하고 API Key는 keystore에 넣는다.
6-C의 모든 임시 Filebeat는 SIGINT/exit0으로 종료했다. 상주 서비스·원본/ES 회전·자동 재시작은 구성하지 않았다.

관련 단위32사례와 기존 웹/앱/Linux 정규화 회귀3사례가 모두 통과했다. 첫 Windows 파일 fixture의
CRLF 실패1건은 fixture를 LF로 수정해 해당 사례만 재검증했다. Native/타입 변경의 영향 사례만
추가 검사했고 전체 Python/UI·기존 성공 쇼핑몰/Filebeat 시험은 반복하지 않았다.
초기 Filebeat 메트릭 검증 경로가9.5.2에 없어 added/done/output/acked 수치로 바로잡았다.

기존6개 인덱스84문서의 source/version/seq_no/term은5-B 보호 baseline과 같았다.
앱 감사6건/쇼핑몰55637·Portal214366·Apache250530 PID와 기존 설정을 유지했고 기존 두 에이전트는
inactive다. ES/Docker/Apache/Portal 재시작·새 패키지·운영 서버·탐지/위험도/Slack/UI/Git 원격 변경은 없다.
안전한 근거는 VM results/{prepare,integration,replay-rotation,final,mapping}.json과 Git 제외
state/security-mall-waf-6c-20261016/에 보관했다. 다음 단계 개발은 시작하지 않는다.

# Security Mall 6-D-3 실제 요청 ID 통합 인수

2026-10-17 KST(최종 검증 00:22:22, 2026-10-16 15:22:22 UTC). **6-D-3 완료**: 실습 VM의 실제 Apache→앱 요청 3개에서 웹/WAF/앱 9이벤트를 Filebeat로 저장하고, 기존 normalize()로 정규화 9건을 저장·재조회했다. 기존 인덱스나 문서는 변경하지 않았다. 상주 수집·사건 연관 엔진·추가 탐지 개발은 수행하지 않았다.

## 빌드·배포·보존

- Windows 기존 Gradle Wrapper로 `bootJar --offline`만 실행했다. 로컬 기존 JDK21 + Git 제외 init-script의 `release=17`을 사용했고 앱 클래스 15개의 major≤61 및 새 로거의 request_id 구현을 검사했다. 기존 38건 단위 테스트는 반복하지 않았다.
- VM 실제 런타임은 OpenJDK **17.0.20.1**이고 새 프로세스 exe도 java-17 경로다. 기존 쇼핑몰 PID55637만 SIGTERM 정상 종료 후 PID**349259**로 실행했다. HTTP200 및 실제 로그인/권한 요청이 성공했다. 강제 종료는 없다.
- 기존 JAR SHA256: `249e8dd98590ce41c5e4992f0e966dff36670e23001860d1d9363c384c1a0d9d`.
- 신규 JAR SHA256: `7dddb416b370a939a4c78afcb6ac221bd14ad611625731cf79e5497f4c6de241` (57,488,586 bytes, 전송 전후 일치).
- 실행 JAR는 기존 `/home/kopo/soc-mall-lab/app/securitymall-lab.jar`다. 기존 JAR와 정상 종료 후 파일형 H2는 `/home/kopo/soc-mall-lab/request-id-6d3-20261017/backup/`에 각각 `securitymall-lab.jar`, `mall-lab.mv.db`로0600 보관했다. 백업 디렉터리는0700이다.
- 기존 application-lab.properties·secrets.properties·start.sh·stop.sh와 HMAC를 보존했다. 설정의 `spring.sql.init.mode=always`가 기존 실습 데이터를 재MERGE하지 않도록 새 실행에 **`--spring.sql.init.mode=never`**만 추가했다. 기존 DB 경로·로그 경로·127.0.0.1:18080은 그대로다. VM의 동작 중 H2 물리 해시 불변이나 전체 테이블의 논리 동등성까지 주장하지 않는다. 기존 가상 계정 로그인과 기존 타인 주문403을 확인했고 데이터 변경/결제 API는 호출하지 않았다.

## 실제 요청과 3종 연결

| 요청 | HTTP | Apache 생성/응답/웹/WAF/앱 공통 request_id | 원본/정규화 |
| --- | --- | --- | --- |
| 로그인 실패 | 302 | `atI-hSuokZgOiD33Gh3LygAAAAY` | 각3건 |
| 로그인 성공 | 302 | `atI-hSuokZgOiD33Gh3LywAAAAc` | 각3건 |
| 타인 주문 조회 거부 | 403 | `atI-hSuokZgOiD33Gh3LzAAAAAg` | 각3건 |

주문 접근 거부 검증용 세션을 얻기 위해 성공 로그인1건을 추가했고 모두 실제 앱 요청이다. 클라이언트 `X-Request-ID`는 Apache의 새 ID로 덮어써졌다. 선택된 모든 신규 WAF 기록에는 실제 CRS920350(숫자 Host) 매치가 있고901001은0건이다. 신규 진단 규칙을 추가하지 않았고 DetectionOnly/blocked=false를 유지했다. 공격 성공이나 WAF 차단으로 분류하지 않는다.

별도의 직접18080 검사4건(헤더 누락·잘못된 값·중복·형식상 유효한 위조)은 모두 비로그인 관리자401이다. 앞3건은 request_id가 없고, 마지막은 위조 ID가 참고값으로만 남았다. 이4건은 실제 수집 대상에서 제외했다. 기존 앱 감사6건의 바이트 prefix를 보존했으며 신규7건이 추가되어 총13건이다. 성공 세션은 로그아웃으로 폐기했다. 로그아웃 및 사전 상태 확인의 웹/WAF 기록도 선택된3개 요청의 수집 대상에 포함하지 않았다.

## 실제 Filebeat·Elasticsearch·정규화

별도 런타임: `/home/kopo/soc-mall-lab/request-id-6d3-20261017/`.

| 인덱스 | 실제 건수 |
| --- | --- |
| `soc-host-raw-mall-isolated-6d3-20261017-e8eabfc6` | 앱3 |
| `soc-host-raw-mall-edge-isolated-6d3-20261017-e8eabfc6` | 웹3 + WAF3 |
| `soc-normalized-mall-request-id-isolated-6d3-20261017-e8eabfc6` | 정규화9 |

- 기존 앱 JS/allowlist·6-C Native AKZ/TSV 정제 경로를 재사용했다. 새 요청만 메모리에서 선택·정제하여 보호된 input/app.jsonl·edge.jsonl에 기록했다. Native 원문·비공개 Apache 오류 로그를 전송하거나 로컬 PC로 복사하지 않았다. 정제 거부0건이다.
- 실제 Filebeat9.5.2의 앱/edge 설정 검사와 JS 실행, 별도 입력ID·registry/data/log/keystore를 사용했다. ES 출력만 실행했고 두 임시 프로세스는 모두 SIGINT/exit0으로 종료했다. 기존 output.file 시험과 시스템 에이전트는 실행하지 않았다.
- ES9.5.2 `soc-mall-es-lab`, `https://127.0.0.1:19200`에서 CA/full TLS 검증을 유지했다. 이번 시험 전용 exact-index 템플릿2개/final pipeline2개와 정규화 인덱스만 생성했다. 실제 Painless 등록/정상 simulate2종, 잘못된 ID/미허용 message 거부4사례, request_id 없는 과거 앱 입력 허용, keyword 매핑, 외부 event.ingested 덮어쓰기를 확인했다.
- 관리자 인증은 설정·검증 준비/정리에만 사용했다. Filebeat는 각 원본 단일 인덱스의 create_doc + 연결 monitor만 가진 키를 사용했다. index/write/delete/manage/read/auto_configure는 부여하지 않았으며 유효한 원본 ID의 명시적 index Bulk는403이다. 정규화는 두 신규 원본 read와 신규 정규화 인덱스 read/create_doc만 사용했다.
- 실제 Filebeat가 create_doc 키로3+6건 저장했다. create Bulk 재전송은 앱3+변조 동일ID1, edge6 모두409이며 원본9건의 `_source`/seq_no/primary_term이 동일하다. 정규화9건 재create도 전부409·불변이다. 문서 ID에 request_id를 추가하지 않았으며 event_id 기반 기존 산정을 유지한다.
- 9개 정규화 이벤트가 실제 원본 index/id를 참조하고 event.id를 보존한다. 각 요청에는 app/access/waf 이벤트가1개씩 있으며 event.id3개는 각각 다르다. organization=`mall-isolated`, host=`mall-host-isolated`, service=`security-mall`, `http.request.id`가 일치한다. 다른 요청 ID/다른 조직 필터 조회는0건이다.
- 이벤트 발생 시각과 중앙 event.ingested를 구분했고 수신 시각이 실제 Filebeat 실행 구간에 속한다. source.ip는 관측 peer127.0.0.1로 보존하며 최종 클라이언트 IP로 해석하지 않는다.
- 앱의 가명/키 버전은 기존 HMAC 이벤트와 연속성이 있다. 원본·정규화9건에서 가상 계정 이름/비밀번호/소유자 개인정보·쿠키·인증 헤더·API 비밀·무해한 민감 표식·message/event.original/매칭 원문이 없음을 검사했다. 단기 키4개는 최종 확인 후 모두 폐기했다.

## 탐지 호환과 진행 중 수정

VM 수집용 최소 Python 묶음에는 탐지 모듈이 없었다. **성공한 수집·저장·정규화는 재실행하지 않고**, 이미 검증된 비식별 정규화9건만 로컬로 읽어 기존 탐지 함수에 전달했다. 실제 자료 ACCESS1/AUTH0, ACCESS severity low/risk20을 확인했다. 별도 메모리 합성5실패→성공은 AUTH1·severity medium/risk60이며 합성 자료는 ES에 저장하지 않았다. 입력 중복은 결과를 늘리지 않았고 가명+키 버전 매칭도 유지된다. 운영 Worker/Detector·Slack·경보 저장은 실행하지 않았다.

초기 권한 음성 시험은 WAF의 event.id와 다른 `_id`를 지정해 수신 final pipeline의 fail processor가 `edge_intake_invalid`/HTTP500으로 먼저 거부했다. 최초 도구의403 전용 기대와 ES 역할 조회의 기본 필드 비교를 수정하고, 잘못된 ID의 거부와 **유효한 ID의 index403**을 분리해 확인했다. 실습 검증 도구만 보완했으며 키 권한이나 제품 코드는 바꾸지 않았다. 이를400으로 가정하지 않는다. 네이티브 검증의 실패 응답은 원문 없이 고정 코드만 기록했다.

## 기존 환경 및 한계

- 기존 ES **10인덱스/136문서**의 source/seq_no/primary_term 해시가 동일하다. 기존 Apache·앱 감사 로그 prefix도 모두 동일하다.
- Apache250530·Portal214366 PID를 유지했다. Portal/앱 최종 HTTP200, ES green, WAF DetectionOnly를 확인했다. 기존 Filebeat/Packetbeat는 inactive다. Docker/Apache/Portal/ES 재시작·운영 VM 접속·공개 포트 추가·Git 원격 작업은 없다.
- 앱의 요청 ID는 직접 loopback 접근으로 위조할 수 있는 참고값이다. ID 일치가 프록시 인증, 권한 부여, 공격 성공의 증거가 되지 않는다. 연결 후보는 조직+호스트+서비스+ID 범위를 지켜야 한다.
- 이번 신규 입력의 실회전·장기 상주 수집·장애 복구/exactly-once는 인수하지 않았다. 수동 JAR 롤백 도구는 준비했으나 실제 롤백은 실행하지 않았다. DB 백업을 자동 복원하지 않는다.

## 수동 재시작·롤백 준비 (이번 검증 후 실행하지 않음)

기존 start.sh는 SQL 초기화/로그 열기 정책이 다르므로 향후 이 실습의 DB 보존 시작에는 새 helper를 사용한다. helper는 쇼핑몰 PID가 살아 있거나18080이 사용 중이면 교체/실행을 거부한다. 현재 PID349259는 정상 실행 중이므로 아래 명령을 지금 실행할 필요는 없다.

```sh
# 쇼핑몰만 정상 종료. 실패하면 중단하고 강제 종료하지 않는다.
/home/kopo/soc-mall-lab/app/stop.sh
# 종료를 확인한 뒤 현재 JAR로 SQL 초기화 없이 시작:
python3 /home/kopo/soc-mall-lab/request-id-6d3-20261017/recover_app.py
# 또는 종료 상태에서 이전 JAR로 되돌려 시작 (둘 중 하나만):
python3 /home/kopo/soc-mall-lab/request-id-6d3-20261017/recover_app.py --rollback
```

HMAC/설정/DB를 복사하거나 덮어쓰지 않으며 애플리케이션 로그는 append한다. API Key는 폐기됐으므로 후속 수집에는 별도 승인하에 새 exact-index 최소 권한 키가 필요하다.

안전한 증거: 로컬 Git 제외 `state/security-mall-request-id-6d3-20261017/vm-results/`의 deploy-result/requests-result/plan/results/{prepare,filebeat-app,filebeat-edge,final,detection-local,stored-snapshots,old-index-baseline}.json. 기존 두 저장소 브랜치와 변경93파일의 baseline도 같은 작업 경로에 보존한다. 신규 운영 코드 변경은 없으며 문서·tracker만 갱신했다.

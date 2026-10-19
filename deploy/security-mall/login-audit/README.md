# Security Mall 로그인 감사 배포 패키지

별도 저장소 ZIYA0614/security-mall에 적용할 로그인 감사 코드와 기존 Cloud SOC에
전송하는 Filebeat 구성을 함께 보관한다. 실제 DB·로그·HMAC 키·API 키는 포함하지 않는다.
Kibana 대시보드 saved object는 포함하지 않는다.

## 1. 준비와 감사 패치

Ubuntu 실습 VM에서 Java 17 JDK, Git, Python 3.10 이상, Docker가 필요하다.
Cloud SOC 중앙 ES 컨테이너 `cloud-soc-central-elasticsearch-1`이 실행 중이어야 한다.
Docker가 정상 연결되는 일반 사용자 터미널에서 수행하며 sudo로 실행하지 않는다.

```bash
# cloud-soc 저장소 루트에서 실행
# 쇼핑몰이 없다면 먼저 복제
git clone https://github.com/ZIYA0614/security-mall.git "$HOME/security-mall"
python3 deploy/security-mall/login-audit/apply.py --mall "$HOME/security-mall"
```

쇼핑몰이 이미 있으면 clone은 생략한다. 패치는 최초 확인한 쇼핑몰 소스를 기준으로 하며
다른 로컬 변경과 충돌하면 적용을 중단한다. 동일 패치는 재실행해도 중복 적용하지 않는다.

`security-mall-login.patch`에 새 LoginAudit.java, HomeController의 성공/실패 기록 호출,
감사 파일의 Git 제외 설정이 들어 있다. 계정명은 앱 전용 HMAC-SHA256으로 가명 처리하며
입력한 비밀번호·쿠키·세션·계정 원문은 감사 JSONL에 기록하지 않는다.
관측 IP는 Servlet socket peer이며 X-Forwarded-For를 신뢰하지 않는다.

## 2. 실행과 중앙 연결

```bash
python3 deploy/security-mall/login-audit/start-and-connect.py
```

이 명령은 쇼핑몰 bootJar를 빌드하고 해당 사용자의 해당 쇼핑몰 Java 프로세스만
종료한 뒤 localhost:8080에서 JAR로 재시작한다. 기존 H2 DB는 유지한다.
실패 로그인 1건을 생성한 뒤 중앙 전송을 구성한다.

- 감사 로그: `~/security-mall/audit/security-audit.jsonl`
- 앱 HMAC 키: `~/security-mall/audit/account-hmac.key` (0600, 앱에만 필요)
- 수집기: 별도 `security-mall-login-filebeat` 컨테이너, Filebeat 9.5.2
- 원본 인덱스: `soc-host-raw-mall-isolated-local-login-v1`
- 수집 범위: organization `mall-isolated`, host `mall-host-isolated`
- 전용 final pipeline, strict mapping 및 30일 만료 create_doc API Key
- Filebeat에 감사 JSONL 파일만 읽기 전용으로 마운트하며 HMAC 키는 전달하지 않음
- 전송 자격 증명: 패키지 아래 `state/writer.json`(0600) 및 Filebeat keystore

중앙 설정을 준비할 때 기존 ES 컨테이너의 elastic 비밀번호 파일을 메모리로 읽는다.
이 값이 현재 저장 데이터의 비밀번호와 달라 401이 나면 현재 elastic 비밀번호를
터미널에서 숨김 입력받는다. Portal 비밀번호가 아니며 입력값은 저장하지 않는다.
비밀번호를 자동 재설정하지 않는다. ES 인증서와 호스트 이름을 검증한다.

기존 SOC 서비스/키/탐지 설정을 변경하지 않는다. 설치는 새 전용 인덱스·pipeline·키를
생성하는 관리 작업이다. 동명 pipeline이 다르면 덮어쓰지 않고 중단한다.
쇼핑몰 재빌드 없이 연결만 재시도할 때는 다음 명령을 쓴다.

```bash
python3 deploy/security-mall/login-audit/connect.py
```

## 3. 실제 수신 확인과 Kibana

http://localhost:8080 에서 정상/실패 로그인을 한 뒤 실행한다.

```bash
python3 deploy/security-mall/login-audit/connect.py --verify
```

`stored.value`와 `outcomes`의 success/failure 건수 및 최근 발생/수신 시각을 출력한다.
이 조회에도 현재 elastic 비밀번호가 필요할 수 있다. 수집 writer 키는 조회 권한이 없다.

Kibana의 Stack Management → Data Views에서 Index pattern을
`soc-host-raw-mall-isolated-local-login-v1`, Timestamp field를 `@timestamp`로 생성한다.
Discover에서 이 Data View와 최근 24시간을 선택하고
`security_mall.audit.event_outcome`, `security_mall.audit.source_ip`,
`security_mall.audit.account_id` 열을 추가한다.
기존 cloud_soc_analyst의 soc-host-raw-* 읽기 권한을 기준으로 한다.

Firefox 130에서 `this.requests.values().filter is not a function` 오류가 관측됐다.
최신 Chrome/Edge 또는 최신 Firefox를 사용한다. 해당 iterator helper는 Firefox131부터
지원된다: https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Releases/131

## 검증과 남은 범위

2026-10-19 Java 컴파일, 별도 localhost18080/H2 메모리 DB에서 실제 HTTP
실패→성공→실패3건, SOC 파서·HMAC 일관성·평문 배제·0600을 검증했다.
사용자 일반 터미널에서 Filebeat 시작과 중앙 ES 원본 실패1건 저장을 확인했다.
발생07:01:31.945Z, 수신07:02:55.119195950Z(시각만 기재, 원본/키 제외).
Kibana Discover는 구형 브라우저 오류가 관측됐으며 최종 화면 인수는 미완료다.
정규화 워커·WEB-AUTH-01 활성화·경보/대시보드 생성은 별도 범위다.

실습 키는 30일 후 만료되며 자동 갱신하지 않는다. JSONL은 자동 회전하지 않으므로
실습 용량을 확인한다. 파일을 교체하면 단일 파일 bind mount 수집기를 다시 생성해야 한다.
state와 감사 키는 공개 저장소에 추가하거나 공유하지 않는다.

```bash
docker logs --tail 50 security-mall-login-filebeat
docker stop security-mall-login-filebeat
```

중지해도 기존 중앙 로그·키·registry는 삭제하지 않는다.

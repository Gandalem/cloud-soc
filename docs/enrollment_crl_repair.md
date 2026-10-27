# Ubuntu 에이전트 등록용 CRL 보완

## 문제와 수정

기존 중앙 설치기는 CRL Distribution Points 없이 서버 인증서를 발급했지만 Ubuntu 등록기는 서명된 CRL을 필수로 요구했다. `Server certificate requires an available signed CRL distribution point`는 이 불일치로 신규 설치에서도 발생할 수 있었다.

새 설치는 기존 CA/서버 키 생성 이후 동일 키로 CRL 주소가 있는 서버 인증서를 발급하고 DER CRL을 공개한다. 기존 설치는 아래 명시적 도구로 보완한다. 인증서 검증·폐기 검증을 끄지 않는다.

- 보존: CA 인증서/개인키, 서버 개인키, 인증서 subject/SAN, Portal 비밀번호·키·DB, 수집 로그·에이전트 등록 상태.
- 변경: 서버 인증서의 재발급(serial/유효기간 포함), 공개 `tls/ca.crl`, 보호된 CRL 인덱스·번호.
- CRL 공개 주소: `https://포털주소/.well-known/cloud-soc/ca.crl`.
- `private/enrollment-tls-backups/`에 변경 전 자료와 파일 모드·소유권·해시 명세를 보관한다. 키는 백업/출력하지 않는다. 적용 중 예외는 이미 변경한 파일을 원복한다. 다중 파일 교체 전체가 단일 파일시스템 트랜잭션인 것은 아니며 전원 중단 시 백업 명세에 따른 명시적 복원이 필요하다.
- 기존 관리 CRL이 있으면 폐기 인덱스를 유지하고 번호를 증가시킨다. 다른 CRL 정책이나 불완전한 기존 자료가 발견되면 빈 CRL로 초기화하지 않는다. 외부 CA/기존 외부 폐기 정책의 자동 마이그레이션 도구가 아니다.

## 기존 사용자 서버 적용

이 안내는 사용자 사례의 새 설치 `~/cloud-soc-local`, 포털 `192.168.1.159`, 공통 관리자가 만든 기본 Compose+runtime/site.json 구성 기준이다. ngrok 등 별도 Compose 파일을 추가한 서버에는 이 기동 명령을 그대로 사용하지 않는다.

수정본을 받은 뒤 **중앙 Ubuntu 서버**에서 실행한다. 서버를 최초 설치하거나 `state`를 삭제하지 않는다.

```bash
cd ~/cloud-soc-local
sudo python3 deploy/server/repair-enrollment-tls.py \
  --state "$PWD/state/server" \
  --portal-url https://192.168.1.159 \
  --install-renewal
```

출력에서 `ca_replaced: false`, `private_keys_replaced: false`, `server_certificate_reissued`, 보호 백업 경로와 `renewal_timer`를 확인한다. 오류이면 게이트웨이를 재생성하지 말고 멈춘다. CA/서버 키를 재생성하는 옵션은 제공하지 않는다.

수정 Caddyfile과 새 서버 인증서를 읽도록 게이트웨이만 재생성한다. 포털 접속은 잠깐 끊길 수 있다. Portal·Elasticsearch·워커를 재생성하거나 DB를 초기화하지 않는다.

```bash
sudo docker compose --project-name cloud-soc-central \
  --env-file state/server/compose.env \
  -f deploy/server/compose.yaml \
  -f state/server/runtime/site.json \
  up -d --no-deps --force-recreate gateway
```

`--install-renewal`은 이 상태 경로에서 파생한 고유 이름의 systemd service/timer를 추가한다. 기본 CRL 유효기간은7일이며 매일 갱신한다. 갱신 시 인증서/키는 그대로이고 공개 CRL만 새로 발급하므로 게이트웨이 재시작이 필요 없다. 실행 파일/저장소 경로를 이동하면 타이머도 관리해야 한다. CRL 만료·타이머 실패를 무시하지 않는다. 수동 갱신은 위 보완 명령에서 `--install-renewal`만 생략한다.

그다음 에이전트 측에서 기존 설치 패키지의 CA와 실제 서버 CA가 같다는 기존 조건을 유지한 채 등록을 진행한다. 이 도구는 에이전트 상태나 설치 토큰을 만지지 않는다. 패키지 등록 정보가 만료됐다면 Portal의 **같은 장치**에서 등록 자료를 갱신하고 새 안내 명령/해시를 사용한다. 자동 `--reenroll`·상태 삭제를 추가하지 않는다.

## 확인과 원복

공개 항목만 확인한다. 토큰·비밀번호·개인키를 출력하지 않는다.

```bash
sudo openssl x509 -in state/server/tls/server.crt -noout -ext crlDistributionPoints
sudo curl --fail --silent --show-error --cacert state/server/tls/ca.crt \
  https://192.168.1.159/.well-known/cloud-soc/ca.crl \
  -o /tmp/cloud-soc-ca.crl
sudo openssl crl -inform DER -in /tmp/cloud-soc-ca.crl \
  -CAfile state/server/tls/ca.crt -verify -noout
```

원복은 현재 파일이 해당 작업의 이전/새 해시와 일치할 때만 허용한다. 이후 CRL 갱신·폐기 등 다른 작업이 있었으면 이전 상태로 덮어쓰지 않고 거부한다. 출력된 타이머를 먼저 중지·비활성화한 뒤 해당 작업이 출력한 보호 백업 경로를 지정한다.

```bash
sudo systemctl disable --now <출력된-renewal_timer>
sudo python3 deploy/server/repair-enrollment-tls.py \
  --state "$PWD/state/server" --portal-url https://192.168.1.159 \
  --restore-from '<이 작업이 출력한 보호 백업 절대 경로>'
```

원복 후 게이트웨이에 예전 인증서를 다시 읽히려면 같은 Compose 구성으로 게이트웨이를 재생성한다. 예전 인증서는 CRL 주소가 없으므로 원복 자체가 Ubuntu 등록 문제를 해결하는 것은 아니다.

## 검증과 배포 구분

격리 임시 CA·키로 실제 OpenSSL 서명/CRL 검증, 보존/원복/폐기 이력/변조 거부, 실제 Ubuntu 등록기의 loopback HTTPS·CRL 검증과 신규 설치 연결을 검사했다. 실제 사용자 서버·개인키·DB·장치에는 접근하거나 적용하지 않았다. Docker gateway 통합 검사는 실행 환경 부재로 생략됐으며 사용자 서버의 CRL 공개·등록 성공은 위 적용 이후 별도 결과다.

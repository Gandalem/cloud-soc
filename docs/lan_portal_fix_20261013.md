# 직접 LAN 포털 접속 수정 — 2026-10-13

FIX-LAN-01. 사용자 브라우저의 `https://192.168.32.60/` 빈 화면을 실제 무인증 요청으로 재현했다. IP Host는200/본문0 bytes이고 기존 도메인 Host는401/Basic challenge였다. 이전 인수는 LAN 연결에 기존 Host를 지정한 프록시 경로였으므로 직접 IP 주소창 접속의 인수가 아니었다.

## 수정과 보호 적용

- `SOC_PORTAL_LAN_ORIGIN`을 명시적으로 설정할 때만 추가 HTTPS 사설 IP 주소를 허용한다. 기본 설정은 기존 단일 주소와 같다. 경로/쿼리/fragment·사용자 정보·임의 포트·공개 IP·DNS/wildcard·unspecified/multicast는 거부한다.
- 포털의 정확한 Host/authority와 요청 Host에 대응하는 Origin 검사를 유지한다. 기존 공개 주소와 LAN 주소 사이의 Origin 혼용도403이다. 인증·역할·조직·Basic 제한·세션 CSRF·JSON/X-Cloud-SOC 요구를 유지한다. 설치/수집 endpoint·기존 PUBLIC_URL은 바꾸지 않는다.
- Caddy443의 같은 포털 블록에 추가 LAN origin을 포함하고, Kibana5601과 기존 공개 Host·peer 제한을 유지한다. Host/Origin을 변환하지 않는다.
- 현재 중앙192.168.32.60의 포털/게이트웨이에만 적용했다. 기존 이미지·Caddy/Compose/override·비밀/TLS 및 포털 SQLite 온라인 backup·integrity/격리 restore 자료는 `/home/kopo/cloud-soc/state/lan-fix-20261013`에 보호했다. 원본 기본 Compose/Caddy 파일은 보존하고 기존 활성 override에 필요한 항목만 추가했다. 직접 응답 검증 실패 시 원래 override를 복구하는 적용 절차를 사용했다.
- 실제 포털 이미지: `sha256:e6620235ab4aba3ff30c97cd1b4b4c5b9a4ba345a5fee2759d9895cce79a3c97`, 태그 `cloud-soc:lan-131166bdfc08`. 검증된 기존 이미지 위에 포털 파일만 추가했다. 기준 소스970fedf + 실제 포털 파일SHA256 `131166bdfc0873a401e7011dfe7306fee5979dcea7c1073d47be6b2c474bf065`, Caddy 파일SHA256 `b72a6a618436d82de72f56dd9bf092501b379c06d3cc83939af0ada40f0813e4`를 manifest에 기록했다. 원래 소스의 LF/CRLF 차이는 정규화 해시로 동일성을 확인했다.
- 기존 ES/Kibana/정규화/탐지 컨테이너 ID·StartedAt와 모든 기존 비밀/CA/TLS 파일은 유지됐다. 기존 경보/수집/탐지 상태를 초기화하거나 규칙을 활성화하지 않았다.

다음 실행/복구에도 활성 `/home/kopo/cloud-soc/state/early-release-000659f/early.override.json`을 함께 사용해야 한다. 현재 release의 Caddy 마운트는 `/home/kopo/cloud-soc/state/lan-release-20261013/deploy/server/Caddyfile`이다. 새 일반 설치에서는 `compose.env`에 `SOC_PORTAL_LAN_ORIGIN=https://<인증서 SAN에 포함된 사설 IP>`를 명시하고 같은 소스의 Compose·포털을 사용한다. 인증서에 해당 IP가 포함되지 않으면 별도 인증서 준비가 필요하다.

## 실제 직접 검증

| 항목 | 결과 |
| --- | --- |
| 직접 IP 무인증 | 빈200 대신401/JSON88 bytes·Basic 로그인 요구 |
| 직접 IP 인증 |200/HTML3165 bytes·홈 포털 표시 |
| 서버 TLS | 실제 CA/IP 검증 통과·인증서/키 변경 없음 |
| 기존 도메인 Host | 같은 LAN 연결에서401 로그인 요구 유지·외부 터널 인증 전송 없음 |
| 직접 인증/개인 API | `/api/auth/me`·`/api/dashboards`200 |
| 다른 허용 주소의 Origin 혼용 |403·저장 수행 없음 |
| 브라우저 직접 LAN | 주소창에 실제 IP·관리자·홈1440/390·개인390·확정 통지1·JS 예외0·홈 가로 넘침 없음 |
| 직접 브라우저 저장 | 브라우저가 생성한 LAN Origin의POST200·지정 검증 대시보드를 동일 내용으로 저장·revision만1증가·모든 구성 내용 유지 |
| 로컬 회귀 | 관련91 passed/4 subtests, 전체789 passed/19 skipped/257 subtests(94.83초), Ruff·diff 통과·Bandit 중간/높음0 |
| Caddy 실제 버전 | 실행 이미지로 LAN 설정 유/무 두 구성 validate 통과 |

사용자는 현재 사용자 CA 신뢰 추가를 원하지 않았다. PC 신뢰 저장소는 변경하지 않았으므로 일반 브라우저의 인증서 경고는 남는다. 실제 CA 검증 HTTP 시험과 별도로 Playwright의 지정 시험 세션에만 ignoreHTTPSErrors를 사용해 UI를 검증했으며 인증은 `https://192.168.32.60`으로만 제한했다. 임시 Host 변환 프록시는 사용하지 않았다. 시험 브라우저와 추가 임시 인증 설정은 검증 후 정리한다. Git 제외 화면은 `output/playwright/early-live/lan-fixed-*.png`에 보존한다.

관련 파일: `src/cloud_soc/portal/app.py`, `deploy/server/{Caddyfile,compose.yaml}`, `tests/test_portal_lan_origin.py`, `.github/workflows/ci.yaml`. 원래 보호 배포/인수는 [기존 보고서](early_deployment_validation_20261013.md)에 보존한다.

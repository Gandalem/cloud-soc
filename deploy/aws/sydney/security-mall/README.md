# Security Mall 웹페이지 로그 수집

대상 소스: https://github.com/ZIYA0614/security-mall
고정 커밋: `aba2b423157cdcb4562fb0eaab3694e379b900e4`.
공유 채팅의 한 EC2·여러 화면·CloudWatch Agent 방식을 반영하되 리전은 사용자 지시에 따라 시드니(`ap-southeast-2`)입니다.

## 준비한 수집 경로

| 화면/이벤트 | 로컬 로그 | CloudWatch 그룹 |
| --- | --- | --- |
| `/`, `/login`, `/board` HTTP 요청 | `/var/log/nginx/security-mall-access.jsonl` | `/cloud-soc/security-mall/access` |
| HTTP 4xx·5xx | `/var/log/nginx/security-mall-http-errors.jsonl` | `/cloud-soc/security-mall/http-errors` |
| 로그인 성공·실패 | `/var/lib/security-mall/audit/security-audit.jsonl` | `/cloud-soc/security-mall/login-audit` |

Nginx는 허용된 세 경로 외에는 `<other>`로 기록합니다. 쿼리·본문·쿠키·비밀번호를 전달하지 않습니다.
로그인 사용자 식별자는 호스트 내부 키로 HMAC 처리합니다. HMAC 키·DB·일반 Java 오류 원문은 수집하지 않습니다.
Nginx 뒤 로그인 감사의 소켓 IP는 127.0.0.1입니다. 원격 접속 IP는 Nginx 접근 로그를 사용합니다.

## 새 EC2에서 실행

전용 새 Amazon Linux 2023 호스트용입니다. 기존 Nginx 설정을 백업한 뒤 교체하므로 다른 앱이 있는 서버에 실행하지 않습니다.
Java 17·Nginx·CloudWatch Agent를 설치하며 인터넷 패키지 다운로드가 필요합니다.
EC2·IAM Role·보안 그룹을 생성하거나 변경하지 않습니다. 앱은 localhost:8080, Nginx는 80을 사용합니다.
접근 경로와 보안 그룹은 기존 승인된 구성을 사용해야 합니다. ALB 대상 그룹 등록은 별도 미실행입니다.

```bash
bash bootstrap-al2023.sh
sudo bash bootstrap-al2023.sh --apply
```

CloudWatch 전송에는 해당 인스턴스에 연결된 승인된 Role의 Logs 쓰기 권한이 필요합니다.
인스턴스 프로필이 없으면 웹앱 검증 후 종료 코드10으로 멈춥니다. 액세스 키를 파일에 넣지 마세요.
전체 설치의 실제 EC2 실행은 아직 검증하지 않았습니다. AL2023 패키지 설치·Nginx·Agent 실행과 CloudWatch 수신을 현장에서 확인해야 합니다.
로컬에서는 패치된 Java 앱 빌드·테스트, 세 화면200·누락 경로404·실패 로그인 감사1건·원문 미포함·키0600을 확인했습니다.

## 중앙 수집 연결

현재 스크립트의 범위는 EC2 파일 → CloudWatch입니다.
CloudWatch → Firehose/S3 `services/...` → SQS → Cloud SOC worker 연결은 구독·전달 Role 및 실제 수신 검증이 추가로 필요합니다.
CloudTrail/VPC Flow/ALB는 AWS 측 서비스 로그이며 웹앱 접근 로그와 별도 경로입니다.
T-Pot 허니팟 로그도 별도 소스이며 웹 요청 로그를 자동 수집하지 않습니다.

같은 계정의 팀원 네 명은 실제 IAM 사용자 ARN을 collector 설정의 `user_teams`에 정확히 매핑합니다.
AssumeRole 이벤트는 `role_teams`의 session issuer로 매핑합니다. 웹 방문자는 IAM 사용자와 자동으로 연결되지 않습니다.
공유 EC2/VPC/ALB의 모든 이벤트를 요청 발생 팀원의 소유라고 추정하지 않습니다.

## 2026-10-21 실제 적용 기록

새 EC2 i-030c6cf5e642c1578에서 빌드·세 화면200·Nginx·Agent 검증 후 CloudWatch 3개 그룹의 실제 수신까지 확인했습니다. 이는 현재 호스트에서의 검증이며 다른 호스트의 성공을 보장하지 않습니다. 설치 부모 디렉터리를 root:security-mall 0750으로 수정했고 Gradle 작업자1개·daemon heap384MiB로 제한했습니다. 기존 CI runner는 사용하지 않았습니다.

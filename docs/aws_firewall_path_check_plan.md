# AWS Network Firewall 임시 경로 검증

작업 ID: AWS-FIREWALL-PATH-20261101 / AWS-FIREWALL-INTAKE-DEV-20261101. 2026-11-01 승인된 임시 경로1회·원상복구·새 RT2개 정리와 native ALERT/FLOW·개발 ES/Portal 인수를 완료했다. 지정 example.com 요청의 직접 상관관계는 미확인이다. 경로 시험을 다시 적용하지 않는다.
도구: [firewall-path-check.py](../deploy/aws/firewall-path-check.py). 기본 실행은 AWS 미접속 계획 출력이다.

## 확인한 상태와 변경 범위

EC2 `i-0e94f1225ca4df1e9`에서 정상 `https://example.com` HEAD 요청은 HTTP200이다.
mall·Firewall 서브넷은 ap-northeast-3b이며 기존 Firewall endpoint는 READY/IN_SYNC다.
현재 mall은 IGW 직결, Firewall subnet은 기본 경로 없는 main을 상속하므로 실제 경유 로그가 없다.
ALERT/FLOW CloudWatch 대상과 기존 HTTPS 경보 sid1000001은 이미 준비돼 있다.

| 대상 | 시험 중 | 복구 후 |
|---|---|---|
| 새 Firewall subnet 전용 RT | local + `0.0.0.0/0 → igw-07e3020d17e2a282f`; `subnet-0aa993e5f60986ee8`에만 연결 | 연결 해제 후 새 RT 삭제, 기존 implicit main 복귀 |
| 새 IGW ingress 전용 RT | local + `10.250.10.0/24 → vpce-0d3de19f10e3a1e23`; 기존 IGW에 edge 연결 | 새 edge 연결 해제 후 새 RT 삭제 |
| 기존 mall RT `rtb-0451cd3c7d6a78b05` | 기본 경로만 기존 IGW에서 같은 AZ의 Firewall endpoint로 교체 | 기본 경로를 원래 IGW로 복원 |

기존 main `rtb-0f881f16bf456eb55`, 기존 두 RT의 local/GuardDuty IPv4·IPv6 경로,
mall subnet 연결, RDS 서브넷, 규칙·로깅·SG·공유 NACL은 수정하지 않는다.
새 RT에는 자체 change ID/purpose/role 태그를 원자적으로 부여한다.
GuardDuty가 새 RT에 자동 추가한 경로 때문에 IGW 연결이 거절되면 기존 GuardDuty 경로를 지우지 않고 중단·복구한다.
새 EC2·NAT·Firewall·공인 IP·키·IAM 권한은 만들지 않는다.

왕복 경로가 필요하다는 근거: [AWS 단일 AZ/IGW 구성](https://docs.aws.amazon.com/network-firewall/latest/developerguide/arch-single-zone-igw.html).
IGW의 우회 대상은 전체 mall subnet CIDR이고 단일 호스트 /32로 줄이지 않는다:
[VPC gateway route table 조건](https://docs.aws.amazon.com/vpc/latest/userguide/gateway-route-tables.html).
따라서 해당 subnet의 인터넷 연결 전체가 시험 영향을 받는다.

## 영향·비용·승인

테스트 EC2의 인터넷/SSH 기존 연결이 잠시 끊길 수 있다. 요청자는 영향 시간에 해당 EC2/서브넷을 사용하는 팀 작업이 없는지 확인한다.
경로 구성·복구 시간이 추가되므로 2분은 전체 중단 시간의 상한이 아니라 정상 경유 대기 시간이다.
기존 Firewall 처리와 CloudWatch 로그 사용량이 소량 증가할 수 있다. RT2개 이외 새 클라우드 자원은 만들지 않는다.
실행 범위는 **임시 경로 연결1회·120초 정상 HTTPS 시험·원상복구**다. 지속 운영 경로 적용은 포함하지 않는다.

사용자의 최초 인계에서 AWS 영향/추가 비용 변경은 구체적인 변경·복구 범위를 제시한 후 승인하도록 요청했다.
앞선 RDS reboot/Finding 승인과 별개로 이번 범위의 명시 승인을 받았다. 추가 경로 적용이나 시험 반복은 포함하지 않는다.

## 실행 및 복구

승인 후 독립된 기본 CloudShell에서 패키징 명령을 한 번 실행한다. 변경 대상 EC2의 SSH 세션이나 해당 VPC에 붙은 CloudShell에서 실행하지 않는다.
도구는 계정·두 RT와 GuardDuty 경로·연결·서브넷/AZ/CIDR·ENI·공인 IP가 있는 실행 중 EC2·IGW 연결·Firewall 상태/정책/규칙·로그 대상·ACL을 다시 확인한다.
다르면 생성 전에 중단한다. 최초 쓰기 전에 mode0600 manifest를 CloudShell home에 보존하고 경로를 출력한다.

최초 실행은 AWS 쓰기 전 `rules_changed`로 중단됐다. 실제 규칙의 HOME_NET이 VPC 대역으로 명시돼 있었으나
검사기가 변수 부재를 요구한 문제였다. 사용자 조회로 확인한 `IPSets.HOME_NET.Definition=["10.250.0.0/16"]`만
정확히 허용하도록 보완하며, 규칙/AWS 설정 자체는 변경하지 않는다. 다른 대역·추가 변수·참조는 계속 거부한다.

새 RT의 경로를 구성하고 Firewall subnet/IGW를 연결한 뒤 마지막으로 mall default를 바꾼다.
`FIREWALL_WINDOW_BEGIN` 이후 EC2에서 아래 새 요청을 실행한다. 한 번 실패하면 10초 후 한 번만 재시도한다.

```bash
date -u +%Y-%m-%dT%H:%M:%SZ
curl -4 --connect-timeout 5 --max-time 15 -I -w '\npeer=%{remote_ip} http=%{http_code}\n' https://example.com
```

CloudShell은 120초 후 항상 복구를 시도한다. Ctrl-C·일반 종료 신호·API 오류에서도 finally 복구를 시도한다.
**브라우저/CloudShell을 닫거나 프로세스를 강제 종료하면 자동 복구를 보장할 수 없다.** 별도 watchdog이나 AWS 예약 작업을 만들지 않는다.
CloudShell을 유지하고 `FIREWALL_ROUTES_RESTORED` 출력까지 기다린다.
복구 순서는 mall default→IGW edge 해제→Firewall subnet 연결 해제→소유 새 RT 삭제다.
최종 기존 RT routes/associations를 보존본과 대조하며 기존 GuardDuty 경로도 포함한다.

복구 오류 시 생성 명령을 다시 실행하지 않는다. 출력한 영구 script 경로·manifest 경로를 사용해 같은 CloudShell에서 복구만 실행한다.

```bash
python3 "$HOME/cloud-soc-firewall-path-check-<표시된 코드 해시>.py" --restore "$HOME/cloud-soc-firewall-path-<표시된 manifest ID>.json"
```

소유 태그가 다른 RT를 지우거나, 다른 사람이 바꾼 mall target/새 RT 연결을 덮어쓰지 않는다.
권한·일시적 API 실패·외부 변경 시 수동 개입이 필요할 수 있으며 `RESTORE_NEEDS_ATTENTION`으로 보고한다.
이 경우 정확한 오류 코드와 출력된 경로를 먼저 확인하고 임의의 RT·GuardDuty 경로를 삭제하지 않는다.
복구 후 EC2에서 같은 HTTPS 요청200을 재확인한다.

## 인수 기준

승인·경유 창 시각/HTTPS 결과·원래 경로 복귀, 해당 EC2와 목적지에 일치하는 native ALERT/FLOW,
기존 보호 파서/해시/발생 시각, 개발 ES 정규화·Portal API·정확한 원본 참조를 각각 확인한다.
AWS 전달 확인 예약 스트림만 있는 상태는 실패다. Flow는 지연될 수 있어 경로 복구 후에도 읽기 전용으로 도착을 확인한다.
기존 `CLOUD_SOC_TEST_HTTPS` alert는 의도된 허용 트래픽 검증이며 실제 공격이라고 표시하지 않는다.
학교 서버 배포·상주 수집·운영 경로 유지·실제 브라우저 클릭은 별도 미완료 범위다.

## 실행 중간 근거

최종 결과: native 보호 표본 ALERT/FLOW 각1건을 확보했다. 시험 sid1000001·allowed·같은 테스트 EC2의 TCP443이며
앞선 example.com과 목적지가 다르고 두 flow ID도 다르다. 기존5건과 결합한 실제7종 ES·정규화·인증 Portal/API 및
규칙 관측 경보1건·정확한 근거/중복 방지 통합검사1건이 통과했다. 시험 Docker 자원 정리도 확인했다.
이는 실제 침해 탐지나 지정 curl과의 동일 세션 증거가 아니다. 아래 미확인/진행 표현은 당시 중간 이력이다.

최신 결과: 수정된 복구 도구434ccce8f0ae에서 FIREWALL_ROUTES_RESTORED를 확인했고
잔여 임시 RT 삭제·기존 경로 대조·manifest restored=true가 통과했다.
14:09:28Z의 보호 표본 조회는 peer 조건의 ALERT/FLOW 모두 no_sample_in_window였다.
실제 창 시작은13:56:20.667254Z, 사용자 HTTPS 응답은13:56:16Z라 요청이 약4.7초 앞섰다.
HTTP200을 방화벽 경유 검증으로 세지 않는다. 목적지/장치 조건을 완화한 native 로그 존재 조회를 먼저 진행한다.
승인된 경로 시험1회는 이미 사용됐으며 새 경로 적용은 이 복구/읽기 전용 후속 범위에 포함하지 않는다.

최초 복구는 association_removal_pending_retry_restore로 중단됐다. 후속 사용자 RT 조회에서
기존 main/mall 경로·GuardDuty 항목·mall 기본 IGW와 Firewall subnet 연결 복귀를 확인했다.
임시 ingress의 연결 해제 완료(disassociated) 기록이 남아 있던 것을 도구가 연결로 세어 삭제를 멈춘 문제다.
AWS는 [연결 상태](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RouteTableAssociationState.html)에
disassociated를 별도로 제공한다. 이 종료 상태만 무시하고 pending/failed/unknown은 계속 보호하도록 수정했다.
복구 오프라인23검사가 통과했다. 짧은 복구 전용 firewall-recovery-only.txt로 기존 manifest만 복구하고
남은 소유 RT2개를 삭제한다. 실제 삭제/완료 출력은 아직 받지 않았다. 경로 시험은 재적용하지 않는다.

갱신 도구04a0a59a9f01은 사용자 CloudShell에서 preflight_ok와 FIREWALL_WINDOW_BEGIN까지 진행됐다.
EC2의13:56:16Z HTTPS 요청은 HTTP200이었다. 원상복구 완료 출력은 아직 받지 않았다.
복구 확인 후 사용할 Git 제외 state/aws-real-source-check/firewall-real-samples.txt는
해당 manifest의 restored=true를 먼저 요구한다. 시험 시간과 실제 요청 peer의 기존 ALERT/FLOW만 읽고
AWS 설정/경로를 변경하지 않는다. src/cloud_soc/aws/verify_samples.py의 선택 기능/시간 범위를 확장했고
검증기18개 오프라인 검사가 통과했다. 실제 경유·복구·로그 수신 완료를 이 중간 출력만으로 추정하지 않는다.

# 클라우드 핵심 탐지 규칙

2026-10-04 / P5-03 코드·합성 검증. 운영 배포와 실제 ES·클라우드 로그 검증은 사용자 요청으로 보류했다.

전달 패치는 a581bf70ef09537a8461d7220a21f4f11f3e7e80 기준의 누적 변경이며 앞선 증분 탐지 구현도 포함한다. 깨끗한 동일 기준 소스에서 `git apply --check cloud-core-detection.patch` 후 적용한다. 앞선 incremental-detection.patch와 중복 적용하지 않는다. files/는 변경 파일 모음이며 전체 저장소가 아니다. 이미 앞선 패치나 운영 변경이 있으면 실제 차이를 대조하고 통합한다.

## 지원 규칙

| ID | 조건 | 심각도 | 해석 한계 |
| --- | --- | --- | --- |
| AWS-IAM-001 | iam.amazonaws.com의 AttachUserPolicy/AttachRolePolicy/AttachGroupPolicy 성공 + AWS 관리형 AdministratorAccess/PowerUserAccess ARN | high | 실제 유효 권한, 승인 여부, 고객 관리형/inline 정책·조건·SCP는 판단하지 않음 |
| AWS-AUDIT-001 | cloudtrail.amazonaws.com의 StopLogging/DeleteTrail 성공 | high | 전체 CloudTrail·모든 감사 기록이 중단됐다는 뜻 아님. 다른 Trail과 실제 수집 상태 확인 필요 |
| AWS-NETWORK-001 | ec2.amazonaws.com의 AuthorizeSecurityGroupIngress 성공 + 하나의 permission 안에 전체 주소/관리 포트 허용 | high | 라우팅·NACL·자산이 실제 공개됐는지 별도 확인. ModifySecurityGroupRules 미지원 |
| OCI-IAM-001 | oci.audit + IdentityControlPlane + CreatePolicy/UpdatePolicy 성공 + resource_id 존재 | medium | 현재 projection은 정책 본문을 보존하지 않으므로 고권한 부여나 악성 판정 아님 |

모두 `type: single`이다. 한 이벤트당 독립 경보이며 같은 조직/계정·동일 시각의 서로 다른 이벤트를 cooldown으로 억제하지 않는다. 기존 AUTH-001의 조건/임계값/cooldown은 유지한다. 사건 처리나 자동 차단은 추가하지 않는다.

## AWS 네트워크 필드

CloudTrail `requestParameters.ipPermissions.items` 또는 리스트에서 permission별 protocol/port/CIDR를 평가한다. TCP 22/3389를 포함하는 포트 범위 또는 모든 프로토콜(-1)에 0.0.0.0/0 또는 ::/0이 있으면 위험 신호다. 서로 다른 permission의 포트와 CIDR을 합치지 않는다.

request 누락, 지원하지 않는 형식, 평가 불가/상한 초과는 unknown(None)이며 false로 정상 확정하지 않는다. UDP/ICMP 또는 사설 CIDR/웹 443 허용은 이 관리 포트 규칙의 양성 조건이 아니다. request 전체·정책 본문·비밀번호는 보존하지 않고 `aws.cloudtrail.public_management_ingress` 불리언과 선택된 대상 메타데이터만 추가한다. 기존 원본 문서와 경보 근거는 다시 쓰지 않는다. 과거에 없던 네트워크 신호는 자동 소급 생성하지 않는다.

## 실행

기본 실행은 SSH만 선택한다. 다음 옵션은 SSH + 클라우드 4개 규칙을 선택한다.

```sh
PYTHONPATH=src python -m cloud_soc.detection --include-cloud
```

위 명령은 오프라인 규칙 검증이며 ES 연결/쓰기/서비스 기동이 없다.

증분 실행에는 기존 실행 옵션에 `--include-cloud`를 추가한다. 규칙 집합은 상태 identity에 포함되므로 기존 SSH 상태 파일에 옵션만 추가하면 명시적으로 거부한다. 운영 재개 시 [기존 데이터 전환 절차](detection_deployment_runbook.md)에 따라 시작점/과거 평가 범위를 결정하고 별도 상태를 준비한다. Compose 기본은 SSH만이며 클라우드 활성화 시 command override를 명시한다.

`--snapshot --include-cloud`도 지원하나 기존 전체 조회 상한이 적용된다. 이 옵션은 과거 자료의 일회성 검증 경로이며 대용량 이행 완료를 뜻하지 않는다.

증분 pending은 선택 규칙 중 하나에 일치한 이벤트만 보존한다. 규칙별 threshold runtime을 분리하고 single 규칙은 상태를 누적하지 않는다. 재시도는 규칙 snapshot/문서 근거의 결정적 경보 ID와 create-only 쓰기를 사용한다. 포털은 실행 중인 다중 프로필을 SSH·클라우드 탐지기로 표시한다.

## 정상 변경과 품질

정상 승인된 관리자 변경도 조건에 맞으면 경보가 생성된다. 승인 시스템 연동은 미구현이며 자동 억제하지 않는다. 분석가가 변경 승인/대상/영향을 확인하고 정상·오탐·악성을 판정한다.

실패 API, 다른 서비스, IAM 정책 ARN 누락, 위험 포트 평가 unknown은 양성 경보가 아니다. 그렇다고 위협 없음이나 데이터 품질 정상으로 판정하지 않는다. missing 필드의 `not_equals`는 이제 false이며 `exists` 조건으로 명시 검사할 수 있다.

합성 시험은 AWS 3종·OCI 정책 변경, 실패/누락/다른 서비스, IPv4/IPv6·포트 범위·모든 프로토콜, cross-permission 반증, 독립 single 이벤트, 개인정보 미보존, 증분 재시도/프로필 변경 거부를 포함한다. 실제 공급자 payload의 형식·OCI source 값·API 결과와 최종 자원 효과는 운영 로그로 재확인해야 한다.

## 공식 근거

- [AWS AttachUserPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html)
- [AWS StopLogging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html)
- [AWS AuthorizeSecurityGroupIngress](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html)
- [OCI Audit 이벤트 필드](https://docs.oracle.com/en-us/iaas/Content/Audit/Reference/logeventreference.htm)

공식 문서의 API/필드 의미를 바탕으로 만든 로컬 규칙이며 공급자의 완전한 위협 탐지 또는 ATT&CK coverage 인증을 주장하지 않는다.

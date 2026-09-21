# 참고 데이터: AWS Cloud Bank Breach S3

검토일: 2026-09-21. 목적: Cloud SOC의 클라우드 로그 파싱·표시·조사 흐름에 대한 참고. 이번에는 문서만 작성하며 수집기/파서/탐지/화면을 구현하거나 AWS 환경을 변경하지 않는다.

## 1. 자료의 역할

사용자가 제공한 [Security Datasets 시나리오](https://securitydatasets.com/notebooks/atomic/aws/initial_access/SDAWS-200914011940.html)는 잘못 설정된 EC2 리버스 프록시를 통해 인스턴스 역할 자격증명이 악용되고 S3 파일 접근으로 이어지는 공격 재현 자료다. Windows/Linux 전체 로그 수집 방법이나 실서비스 침해 증거가 아니라 공개 실습 데이터다.

프로젝트 적용 방향은 **호스트 OS 로그 + 클라우드 API 감사 로그를 서로 다른 수집 소스로 다루고, 조사 화면에서 관련성을 검토하는 것**이다. 이 시나리오의 모든 단계를 CloudTrail만으로 관측했다고 가정하지 않는다. 특히 프록시 요청/자격증명 획득의 직접 근거와 이후 API 활동 근거는 구분한다.

## 2. 실제 파일 확인 결과

페이지에 연결된 [공개 ZIP](https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/aws/collection/ec2_proxy_s3_exfiltration.zip)을 메모리에서 읽어 JSON 레코드와 집계를 확인했다. 압축을 디스크에 풀거나 저장소/Elasticsearch에 적재하지 않았으며, 페이지의 공격 명령·자격증명·주소를 실행하거나 사용하지 않았다.

| 확인 항목 | 관측 결과 |
| --- | --- |
| 데이터셋 ID | `SDAWS-200914011940` |
| 파일 | `ec2_proxy_s3_exfiltration_2020-09-14011940.json` |
| 형식 | 줄 단위 JSON, 103건 |
| 이벤트 식별자 | `eventID` 103개, 모두 고유 |
| 시각 | `@timestamp` 103건, `eventTime`은 없음 |
| UTC 범위 | `2020-09-14T00:44:20Z` ~ `2020-09-14T01:13:20Z` |
| S3 API | 11건: `ListBuckets` 2, `ListObjects` 7, `GetObject` 2 |
| 기타 API | EC2 80건, STS 5건, 기타 7건 |
| 호출 주체 유형 | `IAMUser` 87, `AssumedRole` 11, `AWSService` 5 |
| 출발지 값 | `sourceIPAddress` 중 IP 형식 98건, 비-IP 형식 5건 |
| 분류 결측 | `eventCategory=Data` 9건, 나머지 94건에는 값 없음 |

확인한 ZIP은 14,725바이트이며 SHA-256은 `83cc349afa5672ae46fc38a824946b470f2f3fa39f22889b59dce9fda43fe74d`다. 링크가 가변 브랜치를 사용하므로 향후 재현 시 버전/해시를 다시 확인한다. 위 집계는 전체 파일에 대한 관측이며 103건 전체의 공격 판정이나 객체 2개 유출을 의미하지 않는다.

## 3. 파싱과 표시 제안

아래는 향후 데이터 계약 제안이다. 현재 `src/cloud_soc/parsers/linux_auth.py`는 sshd 텍스트용이고 `normalize_linux_auth_event`는 인증/호스트/PID 중심이므로 이 JSON을 해당 경로에 억지로 넣지 않는다.

| 데이터 필드 | 향후 처리/표시 후보 |
| --- | --- |
| `eventID` | 원문 추적 및 재적재 중복 방지 키의 구성 요소. 소스/계정 범위도 유지 |
| `eventTime` 또는 데이터셋의 `@timestamp` | 입력 프로필별 이벤트 시각. 이 파일은 `@timestamp` 사용; 재생/수집 시각과 분리 |
| `eventSource`, `eventName` | AWS 서비스와 API 행위. SSH 로그인 행위로 변환하지 않음 |
| `awsRegion` | 클라우드 리전 |
| `userIdentity.type`, `arn`, `principalId`, `sessionContext` | 호출 주체·역할·세션. IAM 사용자와 역할 세션을 동일 사용자명으로 평탄화하지 않음 |
| `userIdentity.accountId`, `recipientAccountId` | 호출자 계정과 수신 계정을 구분하여 보존 |
| `sourceIPAddress` | IP 검증 후 `source.ip` 후보로 매핑. 비-IP 값은 원본 출발지 값으로 보존 |
| `requestParameters.bucketName`, `key`, `resources` | 버킷·객체·자원 참조. 누락 필드는 미관측 |
| `errorCode`, `errorMessage` | 존재 시 오류 근거. API 성공 여부와 정상/악성 판정을 분리 |

일반 CloudTrail 스키마와 이 가공된 데이터셋은 동일 입력으로 취급하지 않는다. 필드 의미는 [AWS CloudTrail 이벤트 구조](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)를 기준으로 별도 계약을 확정한다. `eventCategory`가 없다고 임의로 Management를 채우거나 모든 `sourceIPAddress`를 IP 필드에 넣지 않는다. 원본과 수집/가공 출처를 유지한다.

현재 UI의 AWS 웹/앱 데모는 CloudTrail 수집 지원이 아니다. 향후 통합 로그에는 플랫폼 AWS, 소스 CloudTrail, OS 해당 없음으로 구분하고, 시간·서비스·행위·계정·주체·출발지·리전·대상 자원과 원문 참조를 표시하는 방향을 검토한다. CloudTrail의 계정/버킷을 호스트명으로 꾸미지 않는다.

## 4. 조사와 검증 기준

- 조사 시나리오 후보는 동일 역할/세션의 S3 목록 조회 후 객체 접근이다. 역할/세션·대상·시간·출발지의 연관성을 확인하며 IP 하나만으로 묶거나 `GetObject` 한 건만으로 유출을 확정하지 않는다.
- 사건 조사에서는 API 활동 시간 흐름, 역할/세션, 버킷/객체, 선택한 로그의 원문을 연결한다. 탐지 일치 근거와 단순 관련 활동을 구분한다. 이 자료의 모든 이벤트를 악성 정답으로 사용하지 않는다.
- 오프라인 재생은 실제 수집 경로와 분리하고 공개 재현 데이터임을 표시한다. 2020년 이벤트 시각을 현재 시각으로 바꾸지 않으며, 재생 시각은 별도 기록한다. 정상 활동·실패·결측 사례를 추가해야 오탐과 파서 견고성을 평가할 수 있다.
- 실제 AWS 검증에는 해당 S3 데이터 이벤트의 수집 범위를 확인해야 한다. `GetObject` 같은 객체 활동은 데이터 이벤트이며 기본 trail/event data store 설정으로 모두 기록되지 않는다. 별도 설정과 비용 검토가 필요하다. [AWS 데이터 이벤트 문서](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- 향후 적재 전 라이선스/출처, 자격증명·식별자 마스킹과 공개 데모 사용 범위를 확인한다. 공격 재현 명령을 실행할 필요 없이 제공된 로그를 방어 분석 자료로 사용한다.

이번 확인은 파일 구조·건수·시각·필드/행위 집계에 한정된다. 실제 CloudTrail 수집, Cloud SOC 파서 변환, Elasticsearch 저장, 탐지 정확도, UI의 실데이터 연결은 검증하지 않았다.

## 5. 관련 참고 도구

[Stratus Red Team 검토](reference_stratus_red_team.md)는 이미 기록된 이 데이터셋과 별개로, 기법별 기대 이벤트를 설계하거나 향후 격리된 클라우드 실습에서 수집·탐지 흐름을 검증할 때 참고한다. 공개 실행 로그를 이용한 오프라인 검토와 실제 공격 재현 실행을 구분한다. 현재는 어느 도구도 설치하거나 실행하지 않는다.

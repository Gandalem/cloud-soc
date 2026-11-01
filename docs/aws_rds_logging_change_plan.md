# RDS 일반 로그 적용 계획 · 2026-11-01

실행 결과: 승인한 재부팅1회 후 available/in-sync와 general/error export·실제 일반 Query/SET 및 error 보호 표본을 확인했다. 실제7종의 개발 ES·정규화·인증 Portal API 인수에도 포함해 통과했다. SQL 원문은 전달하지 않았다. 아래 상태는 재부팅 전 조회 이력이며 반복 재부팅 지시가 아니다.

현재 사용자 CloudShell 읽기 결과: 계정897722691159, Osaka `cloud-soc-rds-mysql` available, Single-AZ, 다른 PendingModifiedValues 없음, `cloud-soc-mysql84-logging` pending-reboot, general/error export 활성, 자동 백업 보존 설정1일. 최근30분의 5분 측정6개 DatabaseConnections Maximum은 모두0이었다. 순간적인 새 연결까지 없음을 보장하는 지표는 아니다.

## 변경 범위

`RebootDBInstance`를 해당 DB에 **한 번**, failover 없이 요청한다. 기존에 선택한 custom 파라미터 그룹(general_log1/log_outputFILE/slow_query_log0)의 적용을 확인한다. 새 인스턴스/스토리지/계정·키·백업 snapshot·보안 그룹·라우팅·기존 DB 데이터 삭제는 포함하지 않는다.

재부팅 중 DB 연결이 일시 중단된다. 일반 로그가 실제 활성화되면 SQL 기록량에 따라 CloudWatch 수집/저장 및 DB 로그 I/O 사용량이 늘 수 있다. SQL 원문은 AWS 로그에 남을 수 있으므로 원문을 채팅/보고서로 내보내지 않는다. 사용자가 처음 지정한 비용 증가 변경 사전 승인 조건에 따라 **실행 전 별도 승인이 필요하다**.

## 검토 가능한 실행 명령

아래는 승인 후 사용할 명령이다. 계정/상태/대기 변경이 달라지면 중단한다. CLI 코드가 아니라 명령을 제공한 것만으로 실제 적용 성공을 기록하지 않는다.

```bash
bash <<'BASH'
set -euo pipefail
account=$(aws sts get-caller-identity --query Account --output text --no-cli-pager)
if [ "$account" != "897722691159" ]; then
  printf 'account_mismatch: stopped\n'; exit 1
fi
before=$(aws rds describe-db-instances --region ap-northeast-3 \
  --db-instance-identifier cloud-soc-rds-mysql \
  --query 'DBInstances[0].{Id:DBInstanceIdentifier,Status:DBInstanceStatus,Parameters:DBParameterGroups,Exports:EnabledCloudwatchLogsExports,Pending:PendingModifiedValues,MultiAZ:MultiAZ}' \
  --output json --no-cli-pager)
printf '%s' "$before" | python3 -c '
import json,sys
d=json.load(sys.stdin)
expected=[{"DBParameterGroupName":"cloud-soc-mysql84-logging","ParameterApplyStatus":"pending-reboot"}]
ok=(d.get("Id")=="cloud-soc-rds-mysql" and d.get("Status")=="available" and d.get("Pending")=={}
    and d.get("MultiAZ") is False and d.get("Parameters")==expected
    and {"error","general"} <= set(d.get("Exports",[])))
if not ok: raise SystemExit("preflight_changed: stopped before reboot")
print("preflight_ok")'
umask 077
backup_dir=$(mktemp -d "$HOME/cloud-soc-rds-before-XXXXXXXX")
printf '%s\n' "$before" > "$backup_dir/metadata.json"
aws rds reboot-db-instance --region ap-northeast-3 \
  --db-instance-identifier cloud-soc-rds-mysql \
  --query 'DBInstance.{Id:DBInstanceIdentifier,Status:DBInstanceStatus}' --output json --no-cli-pager
if ! aws rds wait db-instance-available --region ap-northeast-3 \
  --db-instance-identifier cloud-soc-rds-mysql; then
  printf 'reboot_requested_but_wait_failed: inspect console; do not reboot again\n'; exit 1
fi
aws rds describe-db-instances --region ap-northeast-3 \
  --db-instance-identifier cloud-soc-rds-mysql \
  --query 'DBInstances[].{Status:DBInstanceStatus,Parameters:DBParameterGroups,Exports:EnabledCloudwatchLogsExports}' \
  --output json --no-cli-pager
BASH
```

위 mktemp는 CloudShell 안에 비공개 메타데이터 사본만 저장한다. AWS DB snapshot을 생성하는 명령이 아니며 기존 CloudShell 파일을 덮어쓰지 않는다.

## 성공 기준과 복구 한계

- `available` 복귀, 원하는 파라미터 그룹 `in-sync`를 확인한다. 이후 general 그룹/스트림과 실제 일반 로그 기록을 별도 확인한다. 재부팅 완료만으로 수집 완료 처리하지 않는다.
- 실제 일반 로그가 없으면 실행 중인 `general_log`/`log_output`과 export·접속/조회 발생을 읽어 확인한다. DB 비밀번호를 요청/출력하거나 SQL 기록을 합성해 저장하지 않는다.
- API 호출 전 guard 실패는 변경 없이 중단한다. **재부팅 요청 후에는 취소·원상태로 되돌리는 명령이 없다.** 복귀 지연/실패 시 추가 변경·반복 재부팅·DB 삭제/복원/파라미터 reset을 하지 않고 RDS 상태/Events를 읽는다.
- 로그량/성능 문제가 있으면 기존 사용자 파라미터 값과 그룹 공유 범위를 확인해 general_log만 끄는 동적 변경을 별도 검토한다. 현재 런타임의 이전 값을 모른 채 default 그룹이나 general_log0으로 일괄 되돌리지 않는다. 기존 회원/업무 데이터·보존 로그·백업은 삭제하지 않는다.

공식 근거: [RDS 재부팅과 중단](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RebootDBInstance.html), [pending-reboot 적용](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/parameter-groups-overview.html), [MySQL 로그 내보내기 조건](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.MySQLDB.PublishtoCloudWatchLogs.html).

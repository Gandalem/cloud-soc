# MITRE ATT&CK mapping

2026-10-05 검토. 매핑은 관측된 행위의 조사 문맥이며 공격 성공이나 ATT&CK 전체 커버리지를 뜻하지 않는다. `mitre.tactic` 및 `mitre.technique: [{id, name}]`는 기존 엔진·UI 계약을 유지한다.

| Rule | 실제 severity | 매핑 | 근거 / 한계 |
| --- | --- | --- | --- |
| AUTH-001 | high | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | 5분 내 같은 조직/IP SSH 실패 10회; 비밀번호 추측 방식은 확정 불가 |
| AUTH-SEQ-001 | high | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | 같은 조직/호스트/계정/IP 실패 5회 뒤 성공; 계정 탈취는 미확정 |
| AWS-IAM-001 | high | [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) | AdministratorAccess/PowerUserAccess 연결 성공; 승인 변경도 탐지 |
| AWS-AUDIT-001 | high | [T1562.008 Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) | StopLogging/DeleteTrail 성공; 전체 감사 로그 상실은 미확정 |
| AWS-NETWORK-001 | high | [T1562.007 Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) | 전체 주소 SSH/RDP 허용은 방화벽 변경 문맥. 의도/라우팅/실제 외부 도달성은 별도 조사 |
| OCI-IAM-001 | medium | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | 정책 생성/갱신 메타데이터만 관측. 정책 본문/추가 권한이 없어 sub-technique 확정 불가 |

클라우드/순차 규칙에 `mapping_status: contextual`, rationale, 공식 URL을 넣었다. 이 metadata 변경은 규칙 버전·경보 ID에 영향을 줄 수 있다. 기존 경보를 덮어쓰지 않으며, 기존 증분 런타임에 새 규칙을 적용할 때는 runtime 계약/이행 안내를 먼저 확인한다.

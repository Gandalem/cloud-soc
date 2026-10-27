# Ubuntu 9종 운영 탐지 시작

대상은 사용자 지정 Ubuntu 192.168.1.159와 ~/security-mall이다. 기존 쇼핑몰 로그인 워커와 중앙 기본 워커는 계속 유지한다. 이 절차는 합성 로그, 자동 공격, 테스트, 린트, 검증을 수행하지 않는다. 탐지 프로세스는 실제 정규화 로그를 읽어 조건에 맞는 경보와 실행 상태를 기록한다.

## 전용 워커 실행

기존 쇼핑몰 탐지에 사용한 .venv-mall-detector와 Python 의존성을 사용한다. 아래 명령은 새 보호 상태 경로에 CA 사본과 30일 전용 탐지 키를 준비하고 9종 규칙을 실행한다. 서버 CA·키·회원 DB·기존 SQLite·체크포인트는 교체하지 않는다. 새 키 설정에는 기존 관리자 비밀번호 파일을 내부적으로 사용하며 출력하지 않는다. 준비 단계에서 오류가 나면 자동 삭제·재발급하지 않는다.

```bash
cd ~/cloud-soc-local
bash deploy/security-scenarios/start-detector.sh
```

별도 터미널에서 계속 실행한다. 중지는 Ctrl+C다. 재시작도 같은 명령이며 전용 잠금은 중복 프로세스를 거부한다. detector-security-scenarios는 정확히 9개 SCENARIO 규칙에만 허용하는 상태 ID다. 기존 detector-additional 및 detector-mall-login 상태를 덮어쓰지 않는다. 이 워커는 호스트 프로세스이며 systemd 자동 시작 등록은 하지 않는다.

## 실제 생산자 연결 계획

워커 실행과 생산자 연결은 별개다. 쇼핑몰 로그인 감사는 아래 앱 세 종류의 대체 입력이 아니다. 현재 코드만으로 9종의 실제 로그가 모두 수집되거나 경보가 발생한다고 간주하지 않는다.

| 규칙 | Ubuntu/쇼핑몰 연결 대상 | 추가 작업 |
| --- | --- | --- |
| SCENARIO-SERVER-FILE-001 | Linux auditd의 중요 파일 쓰기/권한 변경 | 감시 대상 지정, audit 원본 해석기 |
| SCENARIO-SERVER-PERSIST-001 | systemd·cron 구성 변경 감사 | 실제 생성/변경 증거 및 수행자 연결 |
| SCENARIO-SERVER-DEFENSE-001 | 보안 서비스 중지·설정 변경 감사 | 실제 서비스/정책 변경 증거 연결 |
| SCENARIO-APP-ROLE-001 | security-mall의 실제 권한 변경 | 권한 관리 기능, 변경 전후 감사 |
| SCENARIO-APP-EXPORT-001 | security-mall의 실제 데이터 내보내기 | 실제 처리 건수 기록; 작업당 1000건 이상 |
| SCENARIO-APP-UPLOAD-001 | security-mall의 실제 파일 업로드 | 저장/거부 결과와 확장자·MIME 등 위험 근거 |
| SCENARIO-NET-DNS-001 | Ubuntu 네트워크 센서 DNS 응답 | Suricata EVE 등 실제 NXDOMAIN 응답 해석 |
| SCENARIO-NET-FIREWALL-001 | Ubuntu 방화벽 차단 기록 | 실제 차단 기록 해석; 기존 방화벽 정책 보존 |
| SCENARIO-NET-IDS-001 | Ubuntu Suricata EVE alert | IDS 설치·수집 NIC·탐지 규칙·실제 시그니처 증거 |

공통 전송은 docs/security_scenarios.md의 구조화 내보내기 계약 → 별도 스풀/Filebeat → 중앙 정규화다. 원문을 임의 kind로 표시하거나 로그인 로그를 역할/업로드 이벤트로 변환해서는 안 된다. 생산자 연결 없이 기록을 만들어 경보를 충족시키지 않는다. 모든 규칙은 15분 내 서로 다른 조건 충족 원본 3건 이상이 필요하다. 앱 내보내기는 각 작업당 1000건 이상이라는 추가 조건이 있다.

## 현재 인수 범위

2026-10-28: 전용 상태 분리 코드와 시작 스크립트 작성. 사용자 지시에 따라 테스트·시험·검수·검사·구문 확인을 실행하지 않았다. 사용자 Ubuntu에서 워커를 직접 시작하거나 생산자/센서를 설치하지 않았다. 실제 9종 원본 수신·정규화·경보 생성은 미완료다. 기존 쇼핑몰 WEB-AUTH-01은 사용자 제공 결과에서 원본38건/정규화38건/경보1건이 확인됐으며 9종과 별개다.

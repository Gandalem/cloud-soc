# Cloud SOC

Elastic Stack과 Python 기반 자체 탐지 엔진을 이용한 **클라우드 보안관제 졸업작품 프로젝트**입니다.

서로 다른 서버 및 클라우드 환경에서 발생하는 로그를 수집하고, 공통 형식으로 정규화한 뒤 자체 탐지 규칙을 이용해 보안 위협을 탐지하는 것을 목표로 합니다.

---

## 프로젝트 목표

기업마다 로그 저장 위치와 로그 형식이 다르다는 문제를 고려하여 특정 환경에 종속되지 않는 보안관제 구조를 구현합니다.

```text
로그 발생
   ↓
Filebeat / Adapter
   ↓
Elasticsearch
(raw-logs)
   ↓
Python Parser
   ↓
ECS Normalizer
   ↓
normalized-events
   ↓
Detection Engine
   ↓
security-alerts
   ↓
Kibana Dashboard
```

### 주요 목표

- Linux / Web / Cloud 로그 수집
- 로그 Parser 모듈화
- ECS 기반 로그 정규화
- YAML 기반 탐지 Rule 관리
- Threshold / Time Window 기반 공격 탐지
- Elasticsearch 기반 로그 저장 및 검색
- Kibana 기반 보안관제 Dashboard
- MITRE ATT&CK Mapping
- 향후 이벤트 상관분석 기능 구현

---

# 기술 스택

## Backend

- Python

## Log Collection

- Filebeat

## Storage / Search

- Elasticsearch

## Visualization

- Kibana

## Infrastructure

- Docker
- Docker Compose

## Test Environment

- VMware
- Kali Linux
- Ubuntu Linux

## Configuration

- YAML
- `.env`

## Version Control

- Git
- GitHub

---

# 개발 환경

권장 개발 환경:

- Windows 10 / 11
- VS Code
- Git
- Python
- Docker Desktop
- VMware

---

# VS Code 권장 확장 프로그램

프로젝트의 `.vscode/extensions.json`을 통해 필요한 확장 프로그램을 팀원에게 자동으로 추천합니다.

주요 확장:

- Python
- Pylance
- Ruff
- YAML
- Container Tools
- Docker
- Remote - SSH
- GitLens

VS Code로 프로젝트를 열면 Workspace Recommended Extensions를 설치합니다.

---

# 프로젝트 구조

아래 트리는 목표 구조를 포함합니다. `tests/`는 아직 Git에 추적된 테스트가 없으며, `.env`와 샘플 로그는 로컬에서 준비합니다. 현재 구현과 미구현의 구분은 [데이터 요구사항 및 Gap Analysis](docs/dashboard_data_requirements.md)를 기준으로 확인합니다.

```text
Cloud-SOC/
│
├─ .vscode/
│  └─ extensions.json
│
├─ config/
│
├─ docs/
│  ├─ dashboard_requirements.md
│  ├─ dashboard_data_requirements.md
│  ├─ dashboard_implementation_plan.md
│  ├─ 클라우드 보안관제(4조).docx
│  └─ 클라우드_보안관제_MVP_구현계획.docx
│
├─ filebeat/
│
├─ rules/
│
├─ sample_logs/
│
├─ src/
│  └─ cloud_soc/
│     ├─ detection/
│     ├─ elastic/
│     ├─ normalizers/
│     └─ parsers/
│
├─ tests/
│
├─ .env
├─ .env.example
├─ .gitignore
├─ compose.yaml
├─ requirements.txt
└─ README.md
```

---

# 디렉터리 역할

### `src/cloud_soc/parsers`

서로 다른 형식의 원본 로그를 읽고 필요한 정보를 추출합니다.

예:

```text
SSH auth.log
Nginx access.log
AWS CloudTrail
```

---

### `src/cloud_soc/normalizers`

Parser에서 처리된 데이터를 ECS 기반 공통 형식으로 변환합니다.

예:

```text
src_ip
→
source.ip
```

---

### `src/cloud_soc/detection`

정규화된 이벤트에 탐지 Rule을 적용하여 보안 위협을 탐지합니다.

예:

```text
동일 IP
+
5분 이내
+
SSH 로그인 실패 10회 이상

→ SSH Brute Force Alert
```

---

### `src/cloud_soc/elastic`

Python 프로그램과 Elasticsearch 간의 연결 및 데이터 입출력을 담당합니다.

---

### `rules`

보안 탐지 규칙을 YAML 형식으로 관리합니다.

Python 코드를 수정하지 않고 Threshold, Severity 등의 탐지 조건을 변경할 수 있도록 구성합니다.

---

### `filebeat`

Ubuntu 등의 서버에서 로그를 수집하기 위한 Filebeat 설정을 관리합니다.

---

### `sample_logs`

Parser 및 탐지 테스트에 사용할 샘플 로그를 저장합니다.

---

### `tests`

Parser, Normalizer, Detection Engine 등에 대한 자동화 테스트를 관리합니다.

---

### `config`

프로그램 동작에 필요한 일반 설정을 관리합니다.

비밀번호, API Key 등의 민감정보는 저장하지 않습니다.

---

# 환경변수

실제 인증정보는 `.env`에서 관리합니다.

```text
.env
```

파일은 Git에 업로드하지 않습니다.

팀원은:

```text
.env.example
```

파일을 복사하여 자신의 `.env`를 생성합니다.

예:

```powershell
Copy-Item .env.example .env
```

> 비밀번호, API Key 등의 실제 Secret은 GitHub에 Commit하지 않습니다.

---

# Git 저장소

```text
https://github.com/Gandalem/cloud-soc
```

Clone:

```powershell
git clone https://github.com/Gandalem/cloud-soc.git
cd cloud-soc
```

---

# 개발 시작 준비

## 1. 저장소 Clone

```powershell
git clone https://github.com/Gandalem/cloud-soc.git
```

## 2. 프로젝트 이동

```powershell
cd cloud-soc
```

## 3. VS Code 실행

```powershell
code .
```

## 4. 권장 Extension 설치

VS Code에서 Workspace Recommendations를 확인하고 필요한 Extension을 설치합니다.

## 5. Python 가상환경 생성

```powershell
python -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

## 6. Python 패키지 설치

```powershell
pip install -r requirements.txt
```

## 7. 환경변수 파일 생성

```powershell
Copy-Item .env.example .env
```

---

# MVP 개발 목표

첫 번째 MVP에서는 **SSH Brute Force 탐지 하나를 처음부터 끝까지 동작시키는 것**을 목표로 합니다.

```text
Kali Linux
     ↓
SSH 로그인 반복 실패
     ↓
Ubuntu
     ↓
/var/log/auth.log
     ↓
Filebeat
     ↓
Elasticsearch
(raw-logs)
     ↓
Python Parser
     ↓
ECS Normalizer
     ↓
Detection Engine
     ↓
security-alerts
     ↓
Kibana
```

최종 목표:

> Kali에서 Ubuntu에 SSH 로그인 실패가 반복될 경우 자체 Detection Engine이 SSH Brute Force 공격으로 탐지하고 Kibana에서 경보를 확인할 수 있도록 한다.

---

# 개발 예정 순서

```text
1. 팀 개발환경 통일

2. Elasticsearch / Kibana 실행

3. Ubuntu SSH 로그 수집

4. Filebeat → Elasticsearch 연동

5. Linux auth.log Parser 구현

6. ECS Normalizer 구현

7. YAML Rule Loader 구현

8. SSH Brute Force Detection 구현

9. Kibana Alert Dashboard 구성

10. Nginx 로그 지원

11. AWS CloudTrail 지원

12. MITRE ATT&CK Mapping

13. 이벤트 상관분석

14. 탐지 성능 평가
```

---

# Git 기본 작업 방식

작업 시작 전:

```powershell
git pull
```

변경사항 확인:

```powershell
git status
```

Commit:

```powershell
git add .
git commit -m "feat: 작업 내용"
```

Push:

```powershell
git push
```

커밋 메시지 예시:

```text
feat: add SSH log parser
feat: implement ECS normalizer
feat: add SSH brute force detection
fix: prevent duplicate alerts
test: add parser tests
docs: update project documentation
chore: update development environment
```

---

# 주의사항

- `.env` 파일 Commit 금지
- Elasticsearch 비밀번호 코드에 직접 작성 금지
- API Key GitHub 업로드 금지
- 각자 작업 시작 전 `git pull`
- 기능 구현 후 테스트 후 Commit
- MVP가 완성되기 전 과도한 기능 추가 지양

---

# 현재 진행 상태

2026-09-10 확인 기준, **SSH 인증 로그의 수집·정규화·탐지·경보 저장 경로가 구현된 1차 MVP**입니다. 저장 데이터와 기본 Kibana 대시보드는 확인했지만, 지속 수집의 건강도와 조사/분석가 워크플로까지 완성된 상태는 아닙니다.

- [x] GitHub 저장소 생성
- [x] 기본 프로젝트 디렉터리 구성
- [x] Git 연동
- [x] VS Code 권장 Extension 설정
- [x] 로컬 Python 가상환경 구성
- [x] Elasticsearch / Kibana 구성 및 응답 확인
- [x] Filebeat 기반 SSH 원본 로그 저장
- [x] Linux auth.log Parser 및 ECS 기반 Normalizer 구현
- [x] YAML Rule Loader 및 AUTH-001 Threshold / Time Window / Group By / Cooldown 구현
- [x] `security-alerts` 저장 및 기본 Kibana 대시보드
- [x] SOC 업무 화면·데이터 Gap Analysis·구현 계획 문서 작성
- [ ] 팀 개발환경 통일
- [ ] 10,000건 조회 한도 해소 및 증분 처리/복구 검증
- [ ] 경보 근거 문서·원본·Host/User 연결
- [ ] 분석 상태·담당자·판단·메모 저장
- [ ] Entity Investigation 및 Data Source Health
- [ ] 자동 회귀 테스트 및 Kibana 설정 export
- [ ] 업무 요구에 따른 OCI Audit 연동

## SOC 업무 화면 설계

앞으로는 분석가의 업무 흐름을 먼저 정의하고 필요한 데이터와 로그 소스를 역산합니다. SSH Brute Force는 첫 번째 탐지 사례이며 프로젝트 전체 범위가 아닙니다.

- [화면 요구사항](docs/dashboard_requirements.md): SOC Operations, Alert Investigation, Entity Investigation, Data Source Health.
- [데이터 요구사항 및 Gap Analysis](docs/dashboard_data_requirements.md): 현재 코드/실제 필드, 패널별 데이터, 모델 보강 사항.
- [단계별 구현 계획](docs/dashboard_implementation_plan.md): 재사용할 코드, 수정/신설 파일, 테스트 및 완료 기준.

새 문서는 구현 전 검토안입니다. 기존 DOCX는 과거 계획 자료로 보존하며, 그 안의 웹 로그·근태/권한 관리 등 현재 코드와 다른 범위를 이번 SIEM 구현 기준에 자동 포함하지 않습니다.

---

## 1차 Milestone

> Ubuntu의 `/var/log/auth.log` 로그가 Filebeat를 통해 Elasticsearch에 저장되고 Kibana에서 확인된다.

## 2차 Milestone

> SSH 로그가 Parser와 ECS Normalizer를 거쳐 표준 이벤트로 변환된다.

## 3차 Milestone

> Kali에서 발생시킨 SSH Brute Force 공격을 자체 Detection Engine이 탐지한다.

## 4차 Milestone

> 탐지 결과를 Kibana Dashboard에서 보안 경보로 확인한다.

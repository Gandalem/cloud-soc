# Reproducible measurements

2026-10-05 checkout base `8a0abd8` + PORT changes. 합성 오프라인 측정, 운영 환경 성능/공격 탐지 정확도와 구분한다.

## Coverage

Linux Python 3.12.14: **417 passed, 5 skipped, 154 subtests passed**. 전체 `cloud_soc` statement coverage **88.5%** (4990 statements, 575 missed). branch coverage는 측정하지 않았다. OS/opt-in 시험 생략과 CLI/setup의 미커버 경로가 남아 있다. CI는 XML/JSON/HTML을 artifact로 올리며 배지는 로컬 스냅샷이다.

## Labeled detection quality

정답 라벨은 “선언한 규칙 조건에 맞아야 하는가”이다. 승인된 변경이라도 규칙에 해당하면 positive이며, 실제 악성 여부/현장 FP율은 평가하지 않는다. 테스트에서 설계한 사례라 독립 평가 집합도 아니다. SSH/OCI/sequence는 기존 회귀가 있지만 이 수치 집계 대상은 AWS 3개 규칙이다.

| Rule | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AWS-IAM-001 | 2 | 0 | 0 | 3 | 100% | 100% |
| AWS-AUDIT-001 | 2 | 0 | 0 | 3 | 100% | 100% |
| AWS-NETWORK-001 | 3 | 0 | 0 | 4 | 100% | 100% |

Precision = TP/(TP+FP), Recall = TP/(TP+FN); 분모 0은 null. 예상 밖 다른 규칙 탐지도 실패로 처리한다. 17개 사례는 실패 API·잘못된 provider·필드 누락·ReadOnly 정책·사설 SSH·공개 웹 등을 포함한다. 샘플이 작아 모집단 성능을 추정할 수 없다.

## Performance

10,000개 고유 StopLogging positive 이벤트; warmup 1회, 반복 3회, `time.perf_counter`. 고유 ID마다 실제 경보 1개가 생성되는지 검사한다. 생성 fixture/디스크 보고서 쓰기는 시간에서 제외. 환경 Linux 6.18.44 x86_64 / Python 3.12.14 / glibc 2.39; 공유 실행 컨테이너라 CPU·메모리 자원을 고정하거나 보장하지 않는다.

| Stage | Median seconds |
| --- | ---: |
| projection | 0.816 |
| normalization | 1.686 |
| detection | 2.712 |
| alert_build | 0.099 |

합계의 반복별 중앙값 **5.451초**, **1,835 events/sec**. 단계 중앙값의 합과 합계 중앙값은 같지 않을 수 있다.

실제 운영 end-to-end throughput/SLA가 아니다. ES indexing, network, SDK API, SQLite runtime, 혼합 로그, 장시간 메모리/백프레셔·부하·수집 지연을 포함하지 않았다. 머신/부하에 따라 결과가 달라진다.

```bash
python tools/portfolio_eval.py --events 10000 --repeats 3
```

[원시 반복 값·dataset SHA256·데모 결과](evaluation.json). 기존 `evaluation.json`을 갱신하면 README와 이 문서도 새 측정에 맞춰 갱신한다.

## 실제 Windows/Linux CI 검증

2026-10-05 코드 커밋 `8461f4374669e486a9d3f6e767398493c054a355`, [Actions 37256359248](https://github.com/Gandalem/cloud-soc/actions/runs/37256359248) 전체 success.

| 환경 | 실제 결과 |
| --- | --- |
| windows-2025 / Python 3.12 | 선별 pytest 51통과/5생략/35 subtests, PowerShell 구문 통과, agent Node 99통과/1 Linux 전용 생략, UI 82통과, Ruff/pip check/6규칙 profile 통과 |
| ubuntu-24.04 / Python 3.12 | 전체 pytest 413통과/11 OS·opt-in 생략/154 subtests, coverage88.5%, UI82통과, Ruff/Bandit/pip-audit/Compose/Docker 통과 |

처음 실행에서 PS5.1 Security 모듈 자동 로딩 실패 2건과 Windows에서 Linux health publication 시험 실패 1건을 발견했다. mock 시험이 현재 shell의 PSHOME Security 모듈을 명시 로딩하도록 수정하고 Linux 파일 발행 시험은 Linux에서만 수행하도록 전제를 바로잡아 재실행했다. PowerShell 5.1/7 시험은 유지했다. CI의 격리 설치/복구 시험 통과는 실제 운영 Windows 서비스 설치·중앙 수신·운영 배포 인수와 구분한다.

## Linux 파서·재처리 이력 포털 후속 CI

2026-10-05 코드 `07c42be796da23a4bb4dcb59ead4aadee8d0790c`, [Actions 37282971787](https://github.com/Gandalem/cloud-soc/actions/runs/37282971787) Windows/Linux 모두 success 확인.

| 환경 | 실제 결과 |
| --- | --- |
| ubuntu-24.04 / Python 3.12.14 | pytest439통과/11생략/157subtests, statement coverage88.9%(5190 statements/576 missed), UI87통과, Ruff·Bandit medium/high·pip-audit·Compose/Docker 성공 |
| windows-2025 / Python 3.12 | 선별 pytest54통과/5생략/38subtests, PowerShell 구문 성공, agent Node99통과/1 Linux 전용 생략, UI87통과, Ruff/pip check/rule profiles 성공 |

새 커버리지 상세는 해당 실행의 coverage artifact에 보관한다. 기존 README 배지88.5%는 이전 로컬 측정 스냅샷이며 이번88.9% artifact와 구분한다. 사용자 Ubuntu VM에서는 독립 합성SSH10건의 수집→정규화→AUTH-001 경보근거10건 일치, 과거757건의 별도 이력 저장(완전형식744/부분정규화13), 포털 실제조회·상세·페이지·필터·검색·ready 및새로고침 집계유지를 확인했다. Windows CI 성공을 실제 Windows 에이전트 운영 설치로 해석하지 않는다.

# PR #3 검토 지적 보완 — 2026-10-08

대상은 `JEONGRIM-SEO`의 `3f7203f8fba88968d98df621ea2bee2d7c7c0d52`이다. 사용자 요청에 따라 아래 세 문제를 별도 작업 공간에서 수정한다. `park-p2-02`의 별도 작업 및 기존 작업 폴더의 사용자 변경은 포함하지 않는다.

## 수정과 인수 기준

| 지적 | 수정 | 회귀 검증 |
| --- | --- | --- |
| 비정상 Linux 입력이 처리 위치를 막음 | 프로그램 이름·소스 종류·파일 경로·Docker level 자료형 검증. 해당 로그만 미지원 기록 | 배열·객체·숫자·불리언 입력, 정상/비정상 혼합 배치의 체크포인트 전진, 본문 제외 |
| 메모 저장이 다른 담당자 배정을 해제 | 기존 담당자 선택 항목 보존, 실제 선택 변경 시에만 owner 전송 | 다른/비활성 담당자 메모 저장, 명시적 배정·해제, 실제 select의 없는 값 처리 모사 |
| 분석가 사건 조사 접근 단절 | 세션 역할과 조직 정책을 함께 연결. 경보·근거·사건 SQL/ES 요청과 응답·재시도에 조직 제한 | 분석가 관제→근거→생성→메모→연결→재시도, 타 조직·조직 누락·위조 헤더·페이지·이력·키 차단 |

조직 설정이 없는 비관리자에게 전체 사건 권한을 주지 않는다. 세션 분석가는 같은 이름의 정책 investigator와 명시 조직이 필요하다. Basic 로그 전용 계정의 권한은 확대하지 않는다. 전역 처리/파이프라인 통계는 비관리자에게 미확인으로 반환하고 탐지/재처리 이력·설치·키·수집기 전체 현황은 관리자 전용으로 유지한다. 보호 원문은 기존 조직·사유·감사·CSRF 제한을 유지한다. 정책 적용 안내는 [조직별 접근 정책](log_access_policy.md)을 따른다.

## 로컬 검증

Windows 로컬 Python 3.13의 별도 시험 가상환경(저장소 constraints 적용)에서 수행했다. CI의 Python 3.12 결과 및 운영 검증과 구분한다.

- 전체 pytest: 482 통과, 11 skip, 186 subtest 통과. Linux root/선택 Docker·클라우드·플랫폼 조건 시험은 skip이며 통과로 계산하지 않는다.
- 후속 시험 공통 준비 코드 정리 후 관련 pytest: 47 통과, 21 subtest 통과.
- 화면 `node --test prototype/tests/*.test.cjs`: 96 통과, 실패 0.
- 수집기 `node --test --test-concurrency=1 deploy/agents/tests/*.test.cjs`: 100 통과, Linux 전용 1 skip, 실패 0. 격리 OS 모의 시험이며 실제 설치·수신 검증이 아니다.
- `python -m ruff check src tests tools`: 통과.
- `python -m bandit -r src -ll -q`: 중·고위험 지적 0. SQL 조직/ID는 바인딩하며 조건·정렬 조각은 프로그램 상수만 사용한다.
- Windows CI에도 이번 Linux 파서·사건·세션·조직/원문 회귀 시험을 추가했다. Linux CI의 전체 시험은 유지한다.

첫 추가 시험의 실패 2건은 시험 코드의 ES resolve 인자 이름과 유효하지 않은 원문 요청 본문 때문이었다. 실제 API 계약에 맞게 고친 뒤 재실행했다. Ruff의 fixture 이름 중복은 공통 준비 함수로 정리했고, Bandit의 동적 SQL 위치는 실제 값 바인딩을 확인하고 해당 식에 근거를 기록했다. 검사 오류를 숨기거나 테스트 전체를 비활성화하지 않았다.

## 원격 CI와 병합

수정 커밋 `8768bbd957167a072b0a8b750f8156e3b726724f`를 JEONGRIM-SEO에 반영했다. [PR CI](https://github.com/Gandalem/cloud-soc/actions/runs/37724776137)의 Ubuntu/Windows와 [브랜치 CI](https://github.com/Gandalem/cloud-soc/actions/runs/37724772477)의 Ubuntu/Windows, 총 4개 job이 모두 성공했다. Linux 전체 회귀·정적/보안 검사·의존성 감사·Compose 설정·운영 이미지 빌드와 Windows 관련 회귀·PowerShell 구문/격리 수집기·화면 회귀를 포함한다.

[PR #3](https://github.com/Gandalem/cloud-soc/pull/3)의 최종 head 및 main 기준을 재확인하고 검증 head 지정으로 병합했다. 병합 커밋은 `983e70f8758681153038a0be0e5aafad795ec42a`이며 검증한 PR head와 병합 tree 차이가 없다. 이 최종 문서·작업 목록 업데이트는 실행 코드를 바꾸지 않는다. 원래 작업 폴더는 park-p2-02/384b6ce 및 사용자 변경을 그대로 유지했다.

수집기 실제 설치·재부팅·운영 배포·실제 ES/에이전트 수신·자료 전환은 이번 단계에서 수행하지 않았다. 기존 인증/키/큐/DB·CA 설정은 변경하지 않았다. 별도 park-p2-02 기능의 main 통합도 이번 병합에 포함하지 않는다.

# 전용 로그인 활성화

2026-11-02. `/login`을 밝은 파랑·민트로 정리했다. 기존 `SOC_USERS_FILE` 설정을 우선하며, 명시 설정이 없으면 보호된 STATE_DIR/portal-users.json이 있을 때만 기존 세션/RBAC를 활성화한다. 파일이 없으면 Basic 모드를 유지한다. 링크 파일은 거부하며 기존 private0600 검사도 유지한다.

운영자 터미널:

```bash
sudo python3 '/home/lyn/문서/ChatGPT/융프/cloud-soc-merge-review/deploy/server/enable-session-login.py'
```

도구는 중앙 Portal 및 /data 경로를 확인하고 기존 관리자 이름·비밀번호 해시를 재사용한다. 새 비밀번호를 생성/출력하지 않는다. runtime UID 소유0600 사용자파일을 배치하고 기존 배포 관리자를 실행한다. 동일 파일이면 배포 재시도가 가능하며 다른 기존 설정/계정별 로그정책은 자동 변경하지 않는다. 파일 생성만으로 기존 프로세스가 바뀌지 않으며 새 코드로 배포/재기동해야 활성화된다. 일반 deploy-dashboard.sh만 실행하면 사용자 파일을 새로 만들지 않는다.

배포 후 새 시크릿 창에서 /api/auth/config가 mode=session인지 확인한다. / 접속이 /login으로 이동하고 기존 관리자 계정으로 로그인되는지, 로그아웃 뒤 다시 로그인 화면으로 이동하는지 확인한다. 설정값·비밀번호 해시·쿠키는 공유하지 않는다.

로컬 검증: 관련33검사+2subtests 통과,3skip. 미인증302(no WWW-Authenticate), 폼페이지200, 비밀번호 실패401, 로그인쿠키 Secure/HttpOnly/SameSite=Strict, CSRF없는 로그아웃403, 정상 로그아웃 및 이후401 검증. 실제 운영 적용은 sudo 암호 요구로 중단됐다. 코드 구현과 운영 인수를 구분한다.

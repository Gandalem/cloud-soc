#!/usr/bin/env python3
"""Apply the reviewed login audit patch; preserve local changes on mismatch."""
import argparse
from pathlib import Path
import subprocess


def apply_patch(mall, name):
    patch = Path(__file__).resolve().with_name(name)
    def git(*args):
        return subprocess.run(['git', '-C', str(mall), 'apply', *args, str(patch)],
                              capture_output=True)
    if git('--reverse', '--check').returncode == 0:
        print(name + ': 이미 적용돼 있습니다.')
        return
    if git('--check').returncode:
        raise SystemExit('패치 기준과 소스가 다릅니다. 로컬 변경을 보존하고 중단합니다. 패치 내용을 검토하세요.')
    if git().returncode:
        raise SystemExit('패치 적용 실패. git status로 변경 상태를 확인하세요.')
    print('로그인 감사 패치 적용 완료. 실행 중 앱에는 재빌드·재시작 후 반영됩니다.')


def apply(mall):
    # The supplemental patch changes the base patch's login lines; recognize its
    # complete application before trying the original base reverse check.
    supplemental = Path(__file__).resolve().with_name('security-mall-duplicate-login.patch')
    done = subprocess.run(['git', '-C', str(mall), 'apply', '--reverse', '--check', str(supplemental)],
                          capture_output=True)
    if done.returncode == 0:
        print('로그인 감사·중복 아이디 보호 패치가 이미 적용돼 있습니다.')
        return
    apply_patch(mall, 'security-mall-login.patch')
    apply_patch(mall, 'security-mall-duplicate-login.patch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mall', type=Path, default=Path.home() / 'security-mall')
    apply(parser.parse_args().mall.resolve())

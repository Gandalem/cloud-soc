"""Explicit local certificate/CRL repair; never starts or stops services."""
import argparse
import json
import os
from pathlib import Path

from enrollment_pki import repair, restore, install_renewal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=Path(__file__).resolve().parents[2] / 'state/server')
    parser.add_argument('--portal-url', required=True)
    parser.add_argument('--crl-days', type=int, default=7)
    parser.add_argument('--restore-from', type=Path, help='Explicit rollback from this repair tool backup')
    parser.add_argument('--install-renewal', action='store_true', help='Install a dedicated daily CRL renewal timer')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('중앙 Ubuntu 서버에서 sudo로 실행하세요')
    os.umask(0o077)
    if args.restore_from:
        if args.install_renewal:
            raise ValueError('복원과 타이머 설치를 함께 실행할 수 없습니다')
        result = restore(args.state, args.restore_from)
    else:
        result = repair(args.state, args.portal_url, days=args.crl_days)
        if args.install_renewal:
            result['renewal_timer'] = install_renewal(args.state, args.portal_url, Path(__file__), days=args.crl_days)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('인증서 보완 중단 (' + type(error).__name__
                         + '). CA·개인키·등록 자료를 삭제하지 마세요. 보호 백업과 상태를 확인하세요.') from None

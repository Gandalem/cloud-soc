"""Create an optional alias request. DNS records and running services are unchanged."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'deploy/server'))
from server_cli import KoreanParser
from cloud_soc.deployment.access import profile
from cloud_soc.deployment.compose_review import ComposeReviewError


def main():
    parser = KoreanParser(description='추가 Portal DNS 또는 IP 주소 설정 파일 생성')
    parser.add_argument('--alias', required=True, action='append', help='추가 HTTPS 주소 (최대 8개)')
    parser.add_argument('--output', required=True, type=Path, help='새 설정 파일 경로')
    args = parser.parse_args()
    try:
        value = profile({'version': 1, 'aliases': args.alias})
        if any(p.is_symlink() for p in (args.output, *args.output.parents)):
            raise ComposeReviewError('설정 파일 경로에 링크를 사용할 수 없습니다.')
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    except ComposeReviewError as error:
        parser.exit(1, str(error) + '\n')
    except OSError:
        parser.exit(1, '새 파일을 만들지 못했습니다. 경로·권한·기존 파일 유무를 확인하세요.\n')
    print('추가 주소 설정 파일을 만들었습니다. 서버 적용에는 설치 또는 배포 명령이 필요합니다.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

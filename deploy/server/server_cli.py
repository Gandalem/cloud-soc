"""Small stdlib-only presentation helpers for the local server tools."""
import argparse
import sys


class KoreanParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['add_help'] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = '명령'
        self._optionals.title = '옵션'
        self.add_argument('-h', '--help', action='help', help='도움말 표시')

    def format_help(self):
        return super().format_help().replace('usage:', '사용법:', 1)

    def format_usage(self):
        return super().format_usage().replace('usage:', '사용법:', 1)

    def error(self, message):
        # An accidental secret in argv must not be echoed in a parser error.
        self.print_usage(sys.stderr)
        self.exit(2, '입력 오류: 명령과 옵션을 확인하세요. --help로 사용 예시를 볼 수 있습니다.\n')

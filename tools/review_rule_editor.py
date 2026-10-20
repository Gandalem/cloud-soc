"""One-shot synthetic Portal/browser review. Always stop the local HTTP server."""
import argparse
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from unittest.mock import Mock

from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]

from cloud_soc.portal.app import create_app  # noqa: E402
from test_integration_security import make_session_portal  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output) as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        _, monitor, settings, _ = make_session_portal(Path(directory))
        settings['PUBLIC_URL'] = origin
        app = create_app(settings, issuer=Mock(), monitor=monitor)
        server = make_server('127.0.0.1', port, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            return subprocess.run(['node', str(ROOT / 'tools/review_rule_editor.cjs'), origin,
                                   str(args.output.resolve())], cwd=ROOT, check=False).returncode
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())

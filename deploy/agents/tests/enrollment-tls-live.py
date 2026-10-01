"""Synthetic loopback enrollment HTTPS requests; no OS trust or agent changes."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

spec = importlib.util.spec_from_file_location("soc_tls_fixtures", Path(__file__).with_name("windows-tls-live.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class EnrollmentTlsTests(fixtures.SchannelTests):
    def setUp(self):
        super().setUp()
        self.response_status = 401
        self.response_size = 2
        self.requests = []
        self.original = getattr(fixtures.Handler, "do_POST", None)
        owner = self
        def post(handler):
            owner.requests.append({"path": handler.path, "token_present": bool(handler.headers.get("Authorization")),
                                   "installer": handler.headers.get("X-Cloud-SOC") == "installer"})
            handler.rfile.read(int(handler.headers.get("Content-Length", 0)))
            handler.send_response(owner.response_status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(owner.response_size))
            if owner.response_status == 302:
                handler.send_header("Location", "/unexpected-redirect")
            handler.end_headers()
            try:
                handler.wfile.write(b"{}" if owner.response_size == 2 else b"x" * owner.response_size)
            except (BrokenPipeError, ConnectionResetError):
                pass
        fixtures.Handler.do_POST = post

    def probe(self, url, *, compatibility=False, ca=None, shell="powershell.exe"):
        source = Path(__file__).resolve().parents[1] / "enrollment-http.cs"
        code = ("$ErrorActionPreference='Stop'; "
                f"$compile=@{{Path='{str(source).replace(chr(39), chr(39)*2)}';ErrorAction='Stop'}}; "
                "if ($PSVersionTable.PSEdition -eq 'Core') { $compile.CompilerOptions=@('/nowarn:SYSLIB0014,SYSLIB0057') }; Add-Type @compile; "
                "$p=[Console]::In.ReadLine() | ConvertFrom-Json; "
                "try { $r=[CloudSocEnrollmentHttp]::Post($p.url,'/api/installer/enroll',$p.ca,$p.allow,$p.token,'{}'); $r.Status } "
                "catch { exit 60 }")
        encoded = base64.b64encode(code.encode("utf-16le")).decode()
        payload = {"url": url, "ca": str(ca or self.ca_path), "allow": compatibility,
                   "token": "1" * 32 + "." + "a" * 43}
        return subprocess.run([shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                              input=json.dumps(payload) + "\n", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=40)

    def test_private_ca_requires_explicit_compatibility(self):
        url = self.serve()
        for shell in ("powershell.exe", "pwsh"):
            with self.subTest(shell=shell):
                self.assertEqual(self.probe(url, shell=shell).returncode, 60)
                self.assertEqual(self.requests, [])
                result = self.probe(url, shell=shell, compatibility=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "401")
                self.assertEqual(self.requests.pop(), {"path": "/api/installer/enroll", "token_present": True, "installer": True})

    def test_redirect_is_not_followed(self):
        self.response_status = 302
        result = self.probe(self.serve(), compatibility=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "302")
        self.assertEqual(len(self.requests), 1)

    def test_response_body_is_bounded(self):
        self.response_status, self.response_size = 200, 40000
        self.assertEqual(self.probe(self.serve(), compatibility=True).returncode, 60)

    def test_leaf_cannot_be_used_as_trust_anchor(self):
        self.assertEqual(self.probe(self.serve(), compatibility=True, ca=self.root / "server.crt").returncode, 60)
        self.assertEqual(self.requests, [])

    def tearDown(self):
        if self.original is None:
            del fixtures.Handler.do_POST
        else:
            fixtures.Handler.do_POST = self.original
        super().tearDown()


if __name__ == "__main__":
    unittest.main()

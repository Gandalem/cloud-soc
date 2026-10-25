"""A common runtime plus data-only, short-lived device handoff. No build on the portal."""
import io
import json
import tarfile
import zipfile
import hashlib


DATA = {'package.json', 'ca.crt', 'collection-profile.json', 'SHA256SUMS', 'README.txt'}


def bundle(package, archive, registration):
    if package['os'] == 'windows':
        with zipfile.ZipFile(io.BytesIO(archive)) as stream:
            members = {n: stream.read(n) for n in stream.namelist()}
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as stream:
            members = {m.name: stream.extractfile(m).read() for m in stream.getmembers() if m.isfile()}
    runtime = io.BytesIO()
    with zipfile.ZipFile(runtime, 'w', zipfile.ZIP_DEFLATED) as stream:
        for name in sorted(set(members) - DATA):
            # Fixed timestamps make an identical reviewed runtime byte-identical for every device.
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            stream.writestr(info, members[name])
    payload = runtime.getvalue()
    registration = {**registration, 'runtime_sha256': hashlib.sha256(payload).hexdigest()}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as stream:
        stream.writestr('runtime.zip', payload)
        for name in sorted(set(members) & DATA):
            stream.writestr(name, members[name])
        stream.writestr('registration.json', json.dumps(registration))
        if package['os'] == 'windows':
            stream.writestr('Start.cmd', '@echo off\r\npowershell.exe -NoProfile -File "%~dp0bootstrap-windows.ps1" %*\r\npause\r\n')
            stream.writestr('bootstrap-windows.ps1', members['bootstrap-windows.ps1'])
        else:
            stream.writestr('soc-agent', '#!/bin/sh\nset -eu\nHERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)\nexec python3 "$HERE/bootstrap-linux.py" "$@"\n')
            stream.writestr('bootstrap-linux.py', members['bootstrap-linux.py'])
        stream.writestr('시작안내.txt', (
            '압축을 모두 푸세요. 이 묶음에는 만료되는 등록 정보가 있으므로 대상 장치에만 전달하세요.\n'
            'Windows: Start.cmd 실행. Linux: sudo sh soc-agent install\n'
            '도움말: Windows Start.cmd help / Linux sh soc-agent --help\n'
            '수집 키를 복사할 필요는 없습니다. 기존 설치를 덮어쓰지 않습니다.\n'
            '등록 정보가 만료되면 포털의 같은 장치에서 갱신하세요.\n'
            '등록 수신 확인은 최초 시험 문서의 도착이며 일반 로그·탐지 완료와 구분됩니다.\n'
        ))
    return output.getvalue()

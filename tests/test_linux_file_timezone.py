"""Render the real discovery input and require runtime locale enrichment."""
import json
from pathlib import Path
import subprocess


def test_discovered_file_input_uses_live_host_offset_without_static_timezone():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(['bash','-c',
        'source deploy/agents/discover-linux.sh; DISCOVERED_PATHS=(/var/log/auth.log); render_discovered_inputs'],
        cwd=root, text=True, capture_output=True, check=True)
    inputs = json.loads(result.stdout)
    assert len(inputs) == 1
    assert inputs[0]['paths'] == ['/var/log/auth.log']
    assert inputs[0]['processors'] == [{'add_locale': {'format':'offset'}}]
    assert 'timezone' not in inputs[0].get('fields', {}).get('event', {})

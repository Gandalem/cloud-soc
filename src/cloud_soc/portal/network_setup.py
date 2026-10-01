"""Central-only initialization of version-pinned Packetbeat dependencies."""
import json
from pathlib import Path
from elasticsearch import NotFoundError

from cloud_soc.portal.status_setup import SetupConflict

PREFIX = 'packetbeat-9.5.2-'
SERVER_FIELDS = {'created_date_millis', 'modified_date_millis'}


def pipeline_body(value):
    return {key: item for key, item in value.items() if key not in SERVER_FIELDS}


def install_network_pipelines(client, source):
    definitions = json.loads(Path(source).read_text(encoding='utf-8'))
    if not definitions or any(not name.startswith(PREFIX) or not value.get('processors')
                              for name, value in definitions.items()):
        raise SetupConflict('Invalid pinned Packetbeat pipeline definitions')
    try:
        existing = client.ingest.get_pipeline(id=PREFIX + '*')
    except NotFoundError:
        existing = {}
    # Check every conflict before making changes; never replace administrator edits.
    for name, value in definitions.items():
        if name in existing and pipeline_body(existing[name]) != pipeline_body(value):
            raise SetupConflict('Existing Packetbeat pipeline differs; review required')
    for name, value in definitions.items():
        if name not in existing:
            client.ingest.put_pipeline(id=name, body=pipeline_body(value))
    confirmed = client.ingest.get_pipeline(id=PREFIX + '*')
    if any(name not in confirmed or pipeline_body(confirmed[name]) != pipeline_body(value)
           for name, value in definitions.items()):
        raise SetupConflict('Packetbeat pipeline verification failed')
    return len(definitions)

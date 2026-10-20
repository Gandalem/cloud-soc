"""Current lab Portal; existing identities/config stay on the VM."""
import ast
import json
import os
from pathlib import Path

from elasticsearch import Elasticsearch
from cloud_soc.portal.app import create_app

os.umask(0o077)
ROOT=Path(os.environ['SOC_LAB_ROOT']).resolve()
RUNTIME=ROOT/'live-runtime'


def legacy_settings():
    source=ROOT/'portal-lab/portal_wsgi.py'
    tree=ast.parse(source.read_text())
    # Read the established local configuration without constructing its old app.
    tree.body=[n for n in tree.body if not (
        isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='app' for t in n.targets)
        or isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
        and isinstance(n.value.func,ast.Attribute) and ast.unparse(n.value.func).startswith('app.'))]
    namespace={'__file__':str(source),'__name__':'lab_saved_configuration'}
    exec(compile(tree,str(source),'exec'),namespace)
    if namespace.get('reader') is not None:namespace['reader'].close()
    return namespace['settings']


settings=legacy_settings()
connection=json.loads((RUNTIME/'config/connection.json').read_text())
settings.update(PROCESSING_SCOPE=connection['processing_scope'],
    MANAGED_WORKER_CONFIG=json.loads((RUNTIME/'config/managed.json').read_text()),
    PUBLIC_URL='http://127.0.0.1:18081')
settings['AGENT_SOURCE']=Path(os.environ['SOC_LAB_RELEASE'])/'deploy/agents'
review_users=RUNTIME/'config/review-users.json'
if review_users.exists():settings['USERS_FILE']=str(review_users)
reader=Elasticsearch(connection['es_url'],api_key=(RUNTIME/'secrets/reader.key').read_text().strip(),
    ca_certs=connection['ca_file'],verify_certs=True,request_timeout=8,max_retries=0,retry_on_timeout=False)
# The data reader grants no key/role management rights. Never substitute an admin issuer.
app=create_app(settings,issuer=reader,monitor=reader)
app.config.update(DEBUG=False,TESTING=False)

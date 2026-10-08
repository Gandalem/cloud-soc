"""Synthetic authorization/secret canaries; never use production credentials."""
import base64
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from werkzeug.security import generate_password_hash
from cloud_soc.portal.app import create_app
from cloud_soc.portal.log_access import LogAccessPolicy, LogPrincipal
from cloud_soc.portal.source_access import protected_fields, SOURCE_VIEW_FIELDS
from cloud_soc.portal import backup
from test_log_query import client, FIXTURE, response, hits

HASH=generate_password_hash('synthetic-password',method='pbkdf2:sha256:1000')
def auth(name='admin'):
 return {'Authorization':'Basic '+base64.b64encode((name+':synthetic-password').encode()).decode()}
POLICY={'version':1,'protected_source_enabled':True,'admin_source_organizations':['synthetic'],
        'users':[{'username':n,'password_hash':HASH,'role':r,'organizations':org}
                 for n,r,org in [('view','viewer',['synthetic']),('investigate','investigator',['synthetic']),('other','investigator',['foreign'])]]}

class SourceAccessTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.es=client();self.issuer=Mock()
  self.settings={'STATE_DIR':Path(self.tmp.name),'AGENT_SOURCE':Path(__file__).resolve().parents[1]/'deploy/agents','CA_BYTES':b'SYNTHETIC CA',
   'PUBLIC_URL':'http://localhost','ENDPOINT':'https://example.test:9200','ADMIN_USER':'admin','ADMIN_HASH':HASH,'LOG_ACCESS_POLICY':deepcopy(POLICY)}
  self.app=create_app(self.settings,issuer=self.issuer,monitor=self.es);self.http=self.app.test_client()
 def post(self,user='investigate',data=None,extra=None):
  return self.http.post('/api/logs/source',json=data if data is not None else {**{'index':FIXTURE['_index'],'id':FIXTURE['_id']},'purpose':'investigation'},
    headers={**auth(user),'X-Cloud-SOC':'portal',**(extra or {})})
 def audit(self):
  with self.app.extensions['source_audit'].connect() as db:return db.execute('SELECT actor,purpose,outcome,reference_sha256 FROM source_access ORDER BY seq').fetchall()
 def test_defaults_deny_admin_source_without_changing_metadata(self):
  app=create_app({**self.settings,'LOG_ACCESS_POLICY':None},issuer=self.issuer,monitor=self.es)
  c=app.test_client();self.assertFalse(c.get('/api/logs/access',headers=auth()).json['protected_source'])
  r=c.post('/api/logs/source',json={'index':FIXTURE['_index'],'id':FIXTURE['_id'],'purpose':'support'},headers={**auth(),'X-Cloud-SOC':'portal'})
  self.assertEqual(r.status_code,403);self.es.get.assert_not_called()
  self.assertEqual(c.get('/api/logs',headers=auth()).status_code,200)
 def test_viewer_can_read_own_metadata_and_never_manage_packages(self):
  self.assertEqual(self.http.get('/api/logs',headers=auth('view')).status_code,200)
  self.assertIn({'terms':{'organization.id':['synthetic']}},self.es.search.call_args.kwargs['body']['query']['bool']['filter'])
  for path in ['/api/portal','/api/keys','/api/cases','/api/agents/status','/agents.html','/demo-data.js']:
   self.assertEqual(self.http.get(path,headers=auth('view')).status_code,403,path)
  for path in ['/logs.html','/agents.css','/source-view.js']:
   with self.http.get(path,headers=auth('view')) as r:
    self.assertEqual(r.status_code,200,path)
  self.assertEqual(self.post('view').status_code,403);self.assertEqual(self.audit()[-1][2],'forbidden')
  self.issuer.security.create_api_key.assert_not_called()
 def test_foreign_organization_is_indistinguishable_from_missing(self):
  for user in ['other']:
   self.assertEqual(self.http.get('/api/logs/detail',query_string={'index':FIXTURE['_index'],'id':FIXTURE['_id']},headers=auth(user)).status_code,404)
   self.assertEqual(self.post(user).status_code,404)
  foreign=deepcopy(FIXTURE);foreign['_source']['organization']['id']='foreign';self.es.get.return_value=foreign
  self.assertEqual(self.post().status_code,404)
  foreign['_source'].pop('organization');self.assertEqual(self.post().status_code,404)
 def test_scoped_reader_checks_es_results_even_if_upstream_ignores_filter(self):
  self.assertEqual(self.http.get('/api/logs',headers=auth('other')).status_code,503)
  self.assertEqual(self.app.extensions['log_access'].capabilities(LogPrincipal('other','investigator',('foreign',),('foreign',)))['metadata_organizations'],['foreign'])
 def test_cursors_are_bound_to_principal_not_bearer_authority(self):
  self.es.search.return_value=response(hits(26));r=self.http.get('/api/logs',headers=auth('view'));self.assertEqual(r.status_code,200)
  cursor=r.json['next_cursor'];self.es.search.reset_mock()
  for user in ['admin','investigate','other']:
   self.assertEqual(self.http.get('/api/logs',query_string={'cursor':cursor},headers=auth(user)).status_code,400)
  self.es.search.assert_not_called()
 def test_source_preserves_allowlisted_types_masks_secrets_and_records_before_return(self):
  hit=deepcopy(FIXTURE);hit['_source'].update(message='PRIVATE_CANARY',unknown='PRIVATE_CANARY',password='PRIVATE_CANARY')
  hit['_source']['event']['original']='PRIVATE_CANARY';hit['_source']['winlog']['event_data'].update(CommandLine='PRIVATE_CANARY',TaskContent='PRIVATE_CANARY',TargetUserName='postgres://u:PRIVATE_CANARY@host/db')
  self.es.get.return_value=hit;r=self.post();self.assertEqual(r.status_code,200)
  self.assertNotIn('PRIVATE_CANARY',r.get_data(as_text=True));self.assertNotIn('message',r.json['source']);self.assertFalse(r.json['complete_source'])
  self.assertEqual(r.json['source']['winlog']['event_data']['TargetUserName'],'[REDACTED]')
  self.assertEqual(r.json['source']['@timestamp'],hit['_source']['@timestamp']);self.assertEqual(r.json['raw_access'],'protected_fields')
  self.assertEqual(self.es.get.call_args.kwargs['source_includes'],list(SOURCE_VIEW_FIELDS))
  self.assertEqual(self.audit()[0][:3],('investigate','investigation','granted'));self.assertEqual(len(self.audit()[0][3]),64)
  self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertNotIn('token',self.http.get('/api/logs/access',headers=auth('investigate')).get_data(as_text=True))
 def test_failed_audit_never_releases_a_source(self):
  with self.app.extensions['source_audit'].connect() as db:db.execute('DROP TABLE source_access')
  r=self.post();self.assertEqual(r.status_code,503);self.assertEqual(r.json['code'],'source_audit_unavailable');self.assertNotIn('source',r.json)
 def test_invalid_reason_reference_duplicates_and_read_query_are_rejected(self):
  for data in [{'index':FIXTURE['_index'],'id':FIXTURE['_id'],'purpose':x} for x in ['password=PRIVATE_CANARY',{},None]]+[
   {'index':'.security','id':'1','purpose':'support'},{'index':FIXTURE['_index'],'id':'token=PRIVATE_CANARY','purpose':'support'},
   {'index':FIXTURE['_index'],'id':'1','purpose':'support','fields':['message']}]:
   r=self.post(data=data);self.assertEqual(r.status_code,400);self.assertNotIn('PRIVATE_CANARY',r.get_data(as_text=True))
  r=self.http.post('/api/logs/source',data='{"index":"a","index":"b","id":"1","purpose":"support"}',headers={**auth('investigate'),'X-Cloud-SOC':'portal','Content-Type':'application/json'})
  self.assertEqual(r.status_code,400);self.es.get.assert_not_called()
  self.assertEqual(self.http.post('/api/logs/source?token=PRIVATE_CANARY',json={},headers={**auth(),'X-Cloud-SOC':'portal'}).status_code,400)
 def test_origin_csrf_and_basic_auth_cannot_be_role_headers(self):
  self.assertEqual(self.http.post('/api/logs/source',json={},headers=auth()).status_code,403)
  self.assertEqual(self.post(extra={'Origin':'https://foreign.test'}).status_code,403)
  self.assertEqual(self.post(extra={'Sec-Fetch-Site':'cross-site'}).status_code,403)
  self.assertEqual(self.http.get('/api/logs/access',headers={'X-Role':'admin','X-Organization':'synthetic'}).status_code,401)
 def test_errors_and_export_do_not_echo_upstream_source(self):
  self.es.get.side_effect=RuntimeError('password=PRIVATE_CANARY')
  r=self.post();self.assertEqual(r.status_code,503);self.assertNotIn('PRIVATE_CANARY',r.get_data(as_text=True));self.assertEqual(self.audit()[-1][2],'unavailable')
  for path in ['/api/logs/export','/api/logs/raw']:
   self.assertNotEqual(self.http.get(path,headers=auth()).status_code,200)
 def test_audit_backup_v2_restore(self):
  self.assertEqual(self.post().status_code,200)
  extra=tempfile.TemporaryDirectory();self.addCleanup(extra.cleanup)
  root=Path(self.tmp.name);out=Path(extra.name)/'backup';report=backup.backup(root,out)
  self.assertEqual(report['format'],2);self.assertIn('log-access.sqlite',[f['name']for f in report['files']]);backup.verify(out)
  restored=Path(extra.name)/'restored';backup.restore(out,restored)
  with closing(sqlite3.connect(restored/'log-access.sqlite'))as db:self.assertEqual(db.execute('SELECT outcome FROM source_access').fetchall(),[('granted',)])

class PureSourceTests(unittest.TestCase):
 def test_typed_bounds_unknown_objects_arrays_and_secret_option_forms(self):
  for text in ['--password PRIVATE_CANARY','/token PRIVATE_CANARY','mongodb://u:PRIVATE_CANARY@host/x','ssh://host/x?private=PRIVATE_CANARY','abc\u200bPRIVATE_CANARY']:
   result=protected_fields({'host':{'name':text},'unknown':text});self.assertNotIn('PRIVATE_CANARY',json.dumps(result));self.assertEqual(result['source']['host']['name'],'[REDACTED]')
  r=protected_fields({'host':{'ip':['192.0.2.1','password=PRIVATE_CANARY']},'source':{'ip':{'unknown':'PRIVATE_CANARY'}}})
  self.assertEqual(r['source']['host']['ip'],['[REDACTED]']);self.assertEqual(r['source']['source']['ip'],'[WITHHELD]')
 def test_invalid_and_duplicate_configuration_fails_closed(self):
  for change in [{'protected_source_enabled':'true'},{'admin_source_organizations':['*']},{'version':True},{'users':[POLICY['users'][0]]*2}, {'users':[{**POLICY['users'][0],'role':'admin'}]}]:
   with self.assertRaises(ValueError):LogAccessPolicy('admin',HASH,{**deepcopy(POLICY),**change})

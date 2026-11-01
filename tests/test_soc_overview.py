"""Independent SQL/API checks for exact totals and tenant boundaries."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from cloud_soc.portal.cases import CaseStore, CaseError
from cloud_soc.portal.overview import case_overview
from cloud_soc.portal.app import create_app
from werkzeug.security import generate_password_hash
import base64
import json

class OverviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store = CaseStore(Path(self.tmp.name)/'cases.sqlite', 'admin', principals={'admin','viewer'}, organizations={'admin':None,'viewer':('A',)})
        self.start = datetime(2026,11,1,tzinfo=timezone.utc)
        self.pairs = [('start',self.start.isoformat()),('end',(self.start+timedelta(days=1)).isoformat())]
        with self.store.connect() as db:
            for i in range(62):
                db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(f'{i:032x}','Incident','A' if i<60 else 'B','high','closed' if i%2 else 'new',None,'unreviewed',1,(self.start+timedelta(hours=1)).isoformat(),self.start.isoformat()))
            # Exclusive end and before-start events must not contribute.
            for i,stamp in [(100,self.start-timedelta(seconds=1)),(101,self.start+timedelta(days=1))]:
                db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(f'{i:032x}','Outside','A','high','new',None,'unreviewed',1,stamp.isoformat(),stamp.isoformat()))
    def test_totals_not_truncated_to_recent_fifty(self):
        result=case_overview(self.store,'admin',self.pairs)
        self.assertEqual((result['total'],len(result['rows']),result['active'],result['closed']),(62,50,31,31))
    def test_scope_and_filter_apply_to_groups_rows_and_totals(self):
        result=case_overview(self.store,'viewer',self.pairs)
        self.assertEqual(result['total'],60)
        self.assertEqual(result['organizations'],['A'])
        self.assertEqual([g['organization'] for g in result['groups']],['A'])
        with self.assertRaises(CaseError):case_overview(self.store,'viewer',self.pairs+[('organization','B')])
        result=case_overview(self.store,'admin',self.pairs+[('organization','B')])
        self.assertEqual(result['total'],2)
        self.assertEqual({r['organization'] for r in result['rows']},{'B'})
    def test_invalid_and_duplicate_filters_rejected(self):
        for extra in [[('provider','aws')],[('organization','A'),('organization','B')],[('start','bad')],[('organization',' A')]]:
            with self.assertRaises(ValueError):case_overview(self.store,'admin',self.pairs+extra)
    def test_session_viewer_keeps_tenant_scope_and_cannot_expand_it(self):
        hashed=generate_password_hash('fixture-password')
        users={'admin':{'role':'admin','password_hash':hashed},'viewer':{'role':'viewer','password_hash':hashed}}
        filename=Path(self.tmp.name)/'users.json';filename.write_text(json.dumps(users));filename.chmod(0o600)
        policy={'version':1,'protected_source_enabled':False,'admin_source_organizations':[],
                'users':[{'username':'viewer','password_hash':hashed,'role':'viewer','organizations':['A']}]}
        app=create_app({'STATE_DIR':Path(self.tmp.name)/'session','CA_BYTES':b'fixture','PUBLIC_URL':'http://localhost','ENDPOINT':'https://fixture.invalid:9200','ADMIN_USER':'admin','ADMIN_HASH':hashed,'AGENT_SOURCE':Path('deploy/agents'),'USERS_FILE':str(filename),'LOG_ACCESS_POLICY':policy},issuer=Mock())
        client=app.test_client()
        result=client.post('/api/auth/login',json={'username':'viewer','password':'fixture-password'},headers={'X-Cloud-SOC':'portal'})
        self.assertEqual(result.status_code,200)
        captured=[]
        def summary(reader,pairs):
            captured.append(reader.organizations)
            return {'start':self.start.isoformat(),'end':(self.start+timedelta(days=1)).isoformat(),'sections':{k:{'state':'no_index'} for k in ['intake','alerts','processing','quality']}}
        with patch('cloud_soc.portal.app.Operations.summary',summary):
            result=client.get('/api/overview')
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.json['cases']['organizations'],['A'])
            self.assertEqual(captured,[('A',)])
            self.assertEqual(client.get('/api/overview?organization=B').status_code,403)
            self.assertEqual(captured,[('A',)])
        for path in ['/soc.html','/soc/app.js','/soc/app.css']:
            with client.get(path) as result:self.assertEqual(result.status_code,200)

    def test_api_assets_and_scoped_existing_operations_adapter(self):
        app=create_app({'STATE_DIR':Path(self.tmp.name)/'portal','CA_BYTES':b'fixture','PUBLIC_URL':'http://localhost','ENDPOINT':'https://soc.example.test:9200','ADMIN_USER':'admin','ADMIN_HASH':generate_password_hash('fixture-password'),'AGENT_SOURCE':Path('deploy/agents')},issuer=Mock())
        client=app.test_client();headers={'Authorization':'Basic '+base64.b64encode(b'admin:fixture-password').decode()}
        self.assertEqual(client.get('/api/overview').status_code,401)
        for path in ['/','/index.html','/soc.html','/soc/app.js','/soc/app.css']:
            response=client.get(path,headers=headers);self.assertEqual(response.status_code,200,path)
            self.assertNotIn('unsafe-inline',response.headers['Content-Security-Policy']);response.close()
        captured=[]
        def summary(reader,pairs):
            captured.append(reader.organizations)
            return {'start':self.start.isoformat(),'end':(self.start+timedelta(days=1)).isoformat(),'sections':{k:{'state':'no_index'} for k in ['intake','alerts','processing','quality']}}
        with patch('cloud_soc.portal.app.Operations.summary',summary):
            self.assertEqual(client.get('/api/overview?organization=A',headers=headers).status_code,200)
            self.assertEqual(captured,[('A',)])
        self.assertEqual(client.get('/api/overview?unexpected=x',headers=headers).status_code,400)
        self.assertEqual(client.get('/soc/../../config/app.yml',headers=headers).status_code,404)

if __name__=='__main__':unittest.main()

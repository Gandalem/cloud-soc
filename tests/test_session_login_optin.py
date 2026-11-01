import json,tempfile
from pathlib import Path
from unittest.mock import Mock
from werkzeug.security import generate_password_hash
from cloud_soc.portal.app import create_app

def test_private_local_config_enables_form_login_and_revocable_cookie():
 with tempfile.TemporaryDirectory() as folder:
  state=Path(folder);f=state/'portal-users.json'
  f.write_text(json.dumps({'admin':{'role':'admin','password_hash':generate_password_hash('fixture-password')}}));f.chmod(0o600)
  app=create_app({'STATE_DIR':state,'CA_BYTES':b'fixture','PUBLIC_URL':'https://portal.test','ENDPOINT':'https://fixture.test:9200','ADMIN_USER':'admin','ADMIN_HASH':generate_password_hash('unused-basic'),'AGENT_SOURCE':Path('deploy/agents').resolve()},issuer=Mock())
  c=app.test_client();base='https://portal.test'
  assert c.get('/api/auth/config',base_url=base).json['mode']=='session'
  r=c.get('/',base_url=base);assert r.status_code==302 and r.headers['Location']=='/login';assert 'WWW-Authenticate' not in r.headers
  assert c.get('/login',base_url=base).status_code==200
  headers={'X-Cloud-SOC':'portal','Origin':base}
  assert c.post('/api/auth/login',base_url=base,json={'username':'admin','password':'wrong'},headers=headers).status_code==401
  r=c.post('/api/auth/login',base_url=base,json={'username':'admin','password':'fixture-password'},headers=headers)
  assert r.status_code==200
  cookie=r.headers['Set-Cookie'];assert all(v in cookie for v in ['Secure','HttpOnly','SameSite=Strict'])
  identity=c.get('/api/auth/me',base_url=base).json;assert identity['mode']=='session' and identity['user']=='admin'
  assert c.post('/api/auth/logout',base_url=base,json={},headers=headers).status_code==403
  assert c.post('/api/auth/logout',base_url=base,json={},headers={**headers,'X-CSRF-Token':identity['csrf']}).status_code==200
  assert c.get('/api/auth/me',base_url=base).status_code==401

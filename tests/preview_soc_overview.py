"""Isolated UI acceptance server: synthetic observations, real Flask/case routes."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock
from werkzeug.security import generate_password_hash
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cloud_soc.portal.app import create_app
from cloud_soc.portal.cases import CaseStore
from cloud_soc.portal.operations import Operations
root=Path(__file__).resolve().parents[1]
tmp=tempfile.TemporaryDirectory(prefix='soc-ui-fixture-')
app=create_app({'STATE_DIR':Path(tmp.name),'CA_BYTES':b'SYNTHETIC','PUBLIC_URL':'http://127.0.0.1:18765','ENDPOINT':'https://fixture.invalid:9200','ADMIN_USER':'admin','ADMIN_HASH':generate_password_hash('fixture-password'),'AGENT_SOURCE':root/'deploy/agents'},issuer=Mock())
store=CaseStore(Path(tmp.name)/'cases.sqlite','admin')
now=datetime.now(timezone.utc)
for i,(org,title,status,priority) in enumerate([('본사','반복된 인증 실패 후 로그인 성공','investigating','high'),('연구소','비정상 접근 시도 탐지','new','critical'),('서비스센터','보안 설정 변경 확인','closed','medium'),('본사','외부 접속 경보 조사','triage','medium')]):
    stamp=(now-timedelta(hours=i+1)).isoformat()
    with store.connect() as db:
        db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(f'{i+1:032x}',title,org,priority,status,'admin','unreviewed',1,stamp,stamp))
        db.execute('INSERT INTO case_history(case_id,actor,at,version,action,changes,note) VALUES (?,?,?,?,?,?,?)',(f'{i+1:032x}','admin',stamp,1,'created','{}',''))

def summary(self,pairs):
    from cloud_soc.portal.log_contract import parse_filters
    f=parse_filters(pairs)
    values=[2,1,3,2,4,3,8,5,3,6,4,7,5,3,9,6,4,12,7,5,4,8,6,3]
    scale=1 if self.organizations is None else 2
    b=[{'time':(datetime.fromisoformat(f.start.replace('Z','+00:00'))+timedelta(hours=i)).isoformat(),'count':n//scale} for i,n in enumerate(values)]
    rows=[{'organization':'본사','severity':'high','risk_level':'high','risk_score':61}]*8+[{'organization':'연구소','severity':'critical','risk_score':75}]*3+[{'organization':'서비스센터','severity':'medium','risk_score':42}]*18+[{'organization':'본사','severity':'low','risk_score':18}]*12
    if self.organizations is not None:rows=[r for r in rows if r['organization'] in self.organizations]
    section=lambda count:{'state':'ok','count':count,'buckets':b,'rows':[],'statuses':[]}
    return {'start':f.start,'end':f.end,'sections':{'intake':section(12480//scale),'alerts':{**section(sum(r['count'] for r in b)),'rows':rows},'processing':section(12000//scale),'quality':section(25),'pipeline':{'state':'success','coverage':{'state':'observed'}}}}
Operations.summary=summary
if __name__=='__main__':app.run(host='127.0.0.1',port=18765,debug=False,use_reloader=False)

"""Loopback-only QA: real notice APIs/SQLite and normalizer, synthetic ES storage."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import uuid
from flask import jsonify, request
from werkzeug.serving import make_server
from preview_portal_ux import build
from test_early_notices import Fixture, samples, BASE
from cloud_soc.detection import early
from cloud_soc.detection.engine import detect_rule
from cloud_soc.detection.worker import approved_rules
from cloud_soc.processing.contract import NORMALIZED
from cloud_soc.main import make_alert_id, build_security_alert


def application(directory):
    app=build(directory)
    f=Fixture([])
    monitor=app.extensions['monitor']
    # Base preview stubs other views; the new view uses the real Operations
    # created during app startup, whose Mock.options child must share this IO.
    startup_client=monitor.options.return_value
    startup_client.indices=monitor.indices
    startup_client.search=monitor.search
    startup_client.get=monitor.get
    monitor.options.return_value=monitor
    monitor.indices.resolve_index.side_effect=f.client.indices.resolve_index.side_effect
    monitor.indices.get_mapping.side_effect=f.client.indices.get_mapping.side_effect
    monitor.search.side_effect=f.search
    identity=uuid.uuid4().hex
    path=directory/'notice.sqlite'
    report={'synthetic':True}
    original_get=monitor.get.side_effect

    def get(**kw):
        if (kw['index'],kw['id']) in f.docs:
            return {'_source':f.docs[(kw['index'],kw['id'])]}
        for h in f.hits:
            if kw['index']==NORMALIZED and kw['id']==h['_id']:
                return {'_source':h['_source']}
            if {'index':kw['index'],'id':kw['id']}==h['_source']['cloud_soc']['provenance']['raw']:
                norm=h['_source']
                return {'_source':{k:v for k,v in norm.items() if k in ('@timestamp','event','organization','host','source','user')}}
        return original_get(**kw)
    monitor.get.side_effect=get

    def control():
        nonlocal identity,path
        if request.path!='/__fixture/notices':return None
        action=request.args.get('action','report')
        now=datetime.now(timezone.utc)
        if action=='nine':
            identity=uuid.uuid4().hex
            path=directory/(identity+'.notice.sqlite')
            f.docs.clear()
            f.hits=samples(9)
            for h in f.hits:h['_source']['cloud_soc']['normalized_at']=now.isoformat()
            report['nine_searchable_at']=now.isoformat()
        elif action=='ten':
            tenth=samples(10)[-1]
            tenth['_source']['cloud_soc']['normalized_at']=now.isoformat()
            f.hits.append(tenth)
            report['tenth_searchable_at']=now.isoformat()
        elif action=='confirmed':
            events=[{**h['_source'],'_cloud_soc_meta':{'index':NORMALIZED,'document_id':h['_id']}} for h in f.hits]
            match=detect_rule(events,approved_rules()[0])[0]
            identifier=make_alert_id(match)
            f.docs[('security-alerts',identifier)]=build_security_alert(match)
            with closing(sqlite3.connect(directory/'final.sqlite')) as db:
                early.queue_final(db,[(match,identifier)],(now-timedelta(seconds=900)).isoformat());db.commit()
                early.finalize(f.client,final_db=db,path=path)
        elif action=='delayed':early.delayed(f.client,path)
        elif action in ('corrected','verifying','initial'):
            with closing(early.connection(path)) as db:
                body=json.loads(db.execute('SELECT body FROM early_notices').fetchone()[0])
                early.emit(db,body,action,reason='synthetic_state_qa');db.commit()
            early.flush(f.client,path)
        elif action=='empty':f.docs.clear()
        elif action=='unconfigured':
            monitor.indices.resolve_index.side_effect=lambda **kw:{'indices':[]}
        elif action=='configured':monitor.indices.resolve_index.side_effect=f.client.indices.resolve_index.side_effect
        elif action=='report':pass
        else:return jsonify(error='Unknown synthetic action'),400
        if action in ('nine','ten'):
            result=early.run(f.client,path=path,rule=approved_rules()[0],identity=identity,start=BASE,
                now=now+timedelta(milliseconds=1),frontier=BASE-timedelta(seconds=900),scanner=f.scan)
            report.update(result)
            if path.exists():
                with closing(sqlite3.connect(path)) as db:
                    notices=[json.loads(row[0]) for row in db.execute('SELECT body FROM early_notices')]
                    if notices:report['initial_at']=notices[0]['initial_at']
        return jsonify(report)
    app.before_request_funcs[None].insert(0,control)
    return app


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='soc-early-qa-') as directory:
        app=application(Path(directory))
        print('SYNTHETIC only http://127.0.0.1:8773/login',flush=True)
        make_server('127.0.0.1',8773,app,threaded=True).serve_forever()

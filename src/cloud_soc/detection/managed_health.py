"""Read-only health for the configured local rule worker, never a global tenant view."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from cloud_soc.detection.managed import configuration
from cloud_soc.portal.rule_library import aware, digest
from cloud_soc.detection.engine import rule_revision


def snapshot(path,config,*,now=None):
    c=configuration(config);p=Path(path)
    if not p.is_file() or p.is_symlink():return {'state':'unavailable'}
    now=now or datetime.now(timezone.utc)
    with closing(sqlite3.connect(p.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        db.row_factory=sqlite3.Row
        beat=db.execute('SELECT at,failed FROM managed_heartbeat WHERE scope=?',(digest(c),)).fetchone()
        if beat is None:return {'state':'not_started'}
        age=(now-aware(beat['at'])).total_seconds()
        rows=db.execute("SELECT * FROM managed_rules WHERE desired='running' AND status NOT IN ('deleted','delete_pending')").fetchall()
        rows=[r for r in rows if r['organization'] in c['organizations']]
        checkpoints=[];rules=[];pending=0
        for row in rows:
            release=db.execute('SELECT engine_rule FROM managed_releases WHERE rule_id=? AND generation=?',
                               (row['id'],row['generation'])).fetchone()
            state=db.execute('SELECT body FROM managed_worker_state WHERE rule_id=? AND generation=?',
                             (row['id'],row['generation'])).fetchone()
            revision=rule_revision(json.loads(release['engine_rule'])) if release else None
            observed=(row['observed']==row['generation'] and row['observed_state']=='running' and state is not None)
            if observed:checkpoints.append(aware(json.loads(state['body'])['checkpoint']))
            else:pending+=1
            rules.append({'id':row['rule_key'],'scope':'managed','catalog_revision':revision,
                'state':'running' if observed and 0<=age<=45 else 'failed' if row['observed_state']=='failed' else 'stale',
                'observations':[{'worker':'managed','state':'running' if observed and 0<=age<=45 else 'stale',
                    'revision':revision,'last_success':row['observed_at'],'checkpoint':checkpoints[-1].isoformat() if observed else None}]})
        issues=sum(db.execute('SELECT count(*) FROM managed_input_issues WHERE rule_id=?',(r['id'],)).fetchone()[0] for r in rows)
        stale=not 0<=age<=45
        state='stale' if stale else 'failed' if beat['failed'] else 'waiting' if not rows or pending else 'success'
        checkpoint=min(checkpoints).isoformat() if checkpoints and not pending else None
        lag=max(0,int((now-aware(checkpoint)).total_seconds())) if checkpoint else None
        health='stale' if stale else 'failed' if beat['failed'] else 'warning' if issues or pending else 'delayed' if lag is not None and lag>30 else 'healthy'
        return {'state':state,'health':health,'detection':'managed','checkpoint':checkpoint,
                'last_success':beat['at'] if not beat['failed'] else None,'lag_seconds':lag,
                'active_rules':len(rows),'excluded_total':issues,'pending_rules':pending,'rules':rules}

"""Geographic coverage and evidence-based assessment/evaluation calculations."""
from collections import Counter
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import re

from cloud_soc.portal.agent_status import parse_time
from cloud_soc.portal.dashboard_insights import accepted_cloud, selection, account_key
from cloud_soc.portal.insight_state import InsightError, exact, identity, integer


def aware(value):
    stamp=parse_time(value)
    if stamp is None:raise InsightError('invalid_time')
    return stamp


def label(value,maximum=512):
    if not isinstance(value,str) or not 1<=len(value)<=maximum or any(ord(c)<32 for c in value):raise InsightError('invalid_text')
    from cloud_soc.privacy import sensitive
    if sensitive(value):raise InsightError('sensitive_input')
    return value


def validate_policy(body):
    exact(body,('id','organization','version','approved','purpose','items'))
    for key in ('id','organization','version'):identity(body[key])
    if body['approved'] is not True:raise InsightError('explicit_policy_approval_required',409)
    label(body['purpose']);items=body['items']
    if not isinstance(items,list) or not 1<=len(items)<=32:raise InsightError('invalid_policy_items')
    seen=set()
    for item in items:
        exact(item,('id','title','weight','criterion','rationale'));identity(item['id'])
        if item['id'] in seen:raise InsightError('duplicate_policy_item')
        seen.add(item['id']);label(item['title'],80);label(item['criterion']);label(item['rationale']);integer(item['weight'],1,100)


def validate_assessment(body):
    exact(body,('id','organization','provider','account','policy_id','observed_at','expires_at','source','items'))
    for key in ('id','organization','account','policy_id'):identity(body[key])
    if body['provider'] not in ('aws','oci') or body['source']!='operator_evidence_review':raise InsightError('invalid_assessment_source')
    start,end=aware(body['observed_at']),aware(body['expires_at'])
    if not 0<(end-start).total_seconds()<=31*86400 or start>datetime.now(timezone.utc):raise InsightError('invalid_assessment_window')
    if not isinstance(body['items'],list) or not 1<=len(body['items'])<=32:raise InsightError('invalid_assessment_items')
    seen=set()
    for item in body['items']:
        exact(item,('id','state','evidence'),('exception_reason',))
        identity(item['id']);label(item['evidence'])
        if item['id'] in seen or item['state'] not in ('pass','fail','unknown','exempt'):raise InsightError('invalid_assessment_item')
        seen.add(item['id'])
        if item['state']=='exempt':label(item.get('exception_reason'))
        elif 'exception_reason' in item:raise InsightError('invalid_exception')


def assessment_score(policy,assessment,now=None):
    validate_policy(policy);validate_assessment(assessment)
    now=now or datetime.now(timezone.utc)
    if assessment['organization']!=policy['organization'] or assessment['policy_id']!=policy['id']:raise InsightError('policy_scope_mismatch')
    expected={i['id']:i for i in policy['items']};actual={i['id']:i for i in assessment['items']}
    if set(actual)-set(expected):raise InsightError('unknown_assessment_item')
    stale=aware(assessment['expires_at'])<=now or aware(assessment['observed_at'])>now
    required={key:item for key,item in expected.items() if actual.get(key,{}).get('state')!='exempt'}
    total=sum(item['weight'] for item in required.values())
    known=sum(item['weight'] for key,item in required.items() if actual.get(key,{}).get('state') in ('pass','fail'))
    failed=sum(item['weight'] for key,item in required.items() if actual.get(key,{}).get('state')=='fail')
    eligible=not stale and total>0 and known==total
    return {'state':'expired' if stale else 'assessed' if eligible else 'unassessed',
            'score':round(100*failed/total,2) if eligible else None,
            'coverage_percent':round(100*known/total,2) if total and not stale else 0,
            'failed_weight':failed,'applicable_weight':total,'evaluated_weight':known,
            'policy_id':policy['id'],'policy_version':policy['version'],
            'basis':'approved_policy_weighted_violation_not_compromise_probability',
            'contributions':[{'id':key,'title':item['title'],'weight':item['weight'],
                              'state':actual.get(key,{}).get('state','unknown'),'evidence':actual.get(key,{}).get('evidence')}
                             for key,item in expected.items()]}


def validate_evaluation(body):
    exact(body,('id','organization','kind','status','started_at','completed_at','rule_id','rule_version',
                'code_revision','input_digest','scenario_revision','cases','scope'))
    for key in ('id','organization','rule_id','rule_version','code_revision','scenario_revision'):identity(body[key])
    if (body['kind'] not in ('rule','pipeline') or body['status'] not in ('complete','failed','cancelled','inconclusive')
            or body['scope']!='synthetic_scenarios' or not isinstance(body['input_digest'],str)
            or not re.fullmatch('[0-9a-f]{64}',body['input_digest'])):raise InsightError('invalid_evaluation')
    if aware(body['completed_at'])<aware(body['started_at']) or aware(body['completed_at'])>datetime.now(timezone.utc):raise InsightError('invalid_evaluation_window')
    if not isinstance(body['cases'],list) or not 1<=len(body['cases'])<=64:raise InsightError('invalid_scenarios')
    seen=set()
    for case in body['cases']:
        exact(case,('id','expected','verdict','evidence'),('alert_ids',))
        identity(case['id']);label(case['evidence'])
        if (case['id'] in seen or type(case['expected']) is not bool or
                case['verdict'] not in ('alert','no_alert','inconclusive','execution_failed')):raise InsightError('invalid_scenario')
        seen.add(case['id']);refs=case.get('alert_ids',[])
        if not isinstance(refs,list) or len(refs)>20 or any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{64}',x) for x in refs):raise InsightError('invalid_alert_refs')
        if refs and case['verdict']!='alert':raise InsightError('conflicting_scenario_result')


def evaluation_metrics(runs):
    counts=Counter(TP=0,FN=0,FP=0,TN=0);excluded=failed=0;case_total=0
    for run in runs:
        validate_evaluation(run)
        case_total+=len(run['cases'])
        if run['status']!='complete':failed+=1;excluded+=len(run['cases']);continue
        for case in run['cases']:
            if case['verdict'] not in ('alert','no_alert'):excluded+=1;continue
            name=('TP' if case['expected'] else 'FP') if case['verdict']=='alert' else ('FN' if case['expected'] else 'TN')
            counts[name]+=1
    tp,fp,fn=counts['TP'],counts['FP'],counts['FN']
    return {**counts,'precision':round(100*tp/(tp+fp),2) if tp+fp else None,
            'recall':round(100*tp/(tp+fn),2) if tp+fn else None,
            'run_count':len(runs),'failed_runs':failed,'excluded_cases':excluded,'case_total':case_total,
            'eligible_cases':sum(counts.values()),'basis':'registered_synthetic_scenario_results_not_production_success_rate'}


def evaluation_summary(store,organizations,pairs):
    f,values,offset=selection(pairs)
    if set(values)-{'start','end','offset'}:raise InsightError('invalid_query')
    start,end=aware(f.start),aware(f.end)
    records=[r for r in store.records('evaluation',organizations) if start<=aware(r['body']['completed_at'])<end]
    # Aggregate separately by kind AND fixed rule/code/input/scenario revision.
    groups={}
    for record in records:
        r=record['body'];key=tuple(r[k] for k in ('organization','kind','rule_id','rule_version','code_revision','input_digest','scenario_revision'))
        groups.setdefault(key,[]).append(r)
    summaries=[dict(zip(('organization','kind','rule_id','rule_version','code_revision','input_digest','scenario_revision'),key),**evaluation_metrics(runs)) for key,runs in groups.items()]
    return {'state':'ok' if records else 'no_evaluations','groups':summaries,'run_total':len(records),
            'runs':records[offset:offset+25],'next_offset':offset+25 if offset+25<len(records) else None,
            'filters':{'start':f.start,'end':f.end},'basis':'operator_registered_result_records'}


def account_overview(reader,store,organizations,pairs):
    rows,data_state,f,values,offset=reader.dataset(pairs,'cloud')
    if set(values)-{'start','end','provider','account','organization','offset'}:raise InsightError('invalid_query')
    cloud=[r for r in rows if accepted_cloud(r)]
    counts=Counter(key for r in cloud if (key:=account_key(r)) is not None)
    policies={}
    for r in store.records('policy',organizations):policies[(r['body']['organization'],r['body']['id'])]=r
    records=store.records('assessment',organizations);latest={}
    for r in records:
        a=r['body'];key=(a['organization'],a['provider'],a['account']);previous=latest.get(key)
        # Observed time, not import order. Preserve all earlier snapshots in the ledger.
        if not previous or (aware(a['observed_at']),r['recorded_at'],a['id'])>(aware(previous['body']['observed_at']),previous['recorded_at'],previous['body']['id']):latest[key]=r
    selected=sorted(set(counts)|set(latest))
    if values.get('organization'):selected=[k for k in selected if k[0]==values['organization']]
    if values.get('provider'):selected=[k for k in selected if k[1]==values['provider']]
    if values.get('account'):selected=[k for k in selected if k[2]==values['account']]
    accounts=[]
    for key in selected[offset:offset+50]:
        result={'organization':key[0],'provider':key[1],'account':key[2],'event_count':counts[key],
                'score':None,'state':'unassessed','coverage_percent':0}
        snapshot=latest.get(key)
        if snapshot:
            a=snapshot['body'];policy=policies.get((a['organization'],a['policy_id']))
            result.update(assessment_id=a['id'],observed_at=a['observed_at'],expires_at=a['expires_at'],
                          assessor=snapshot['actor'],source=a['source'])
            if policy:result.update(assessment_score(policy['body'],a),policy_approved_by=policy['actor'])
        accounts.append(result)
    return {'state':'ok' if selected else 'no_accounts','data_state':data_state,'accounts':accounts,'total':len(selected),
            'next_offset':offset+50 if offset+50<len(selected) else None,'policy_count':len(policies),
            'policies':[{'id':p['body']['id'],'organization':p['body']['organization'],'version':p['body']['version'],
                         'items':p['body']['items'],'approved_by':p['actor']} for p in list(policies.values())[:100]],
            'filters':{'start':f.start,'end':f.end},'basis':'observed_cloud_events_and_operator_evidence_assessments'}


def geographic(reader,pairs,database):
    rows,data_state,f,values,offset=reader.dataset(pairs,'web')
    if set(values)-{'start','end','country','offset'}:raise InsightError('invalid_query')
    valid=[];invalid=0
    for r in rows:
        fields=r['interpretation'].get('fields',{})
        if r['interpretation']['status'] not in ('recognized','partial') or (r['source_kind']=='security_mall_edge' and fields.get('stream')!='access'):
            invalid+=1;continue
        valid.append(r)
    internal=missing=0;public=[]
    for r in valid:
        raw=r.get('source_ip') or r['interpretation']['fields'].get('source_ip')
        try:ip=ipaddress.ip_address(raw)
        except (ValueError,TypeError):missing+=1;continue
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:internal+=1;continue
        public.append((r,str(ip)))
    result={'state':'ok','data_state':data_state,'total':len(valid),'invalid_or_unsupported':invalid,
            'internal':internal,'missing_ip':missing,'public':len(public),'located':0,'unknown':len(public),
            'coverage_percent':0,'countries':[],'rows':[],'next_offset':None,
            'filters':{'start':f.start,'end':f.end},'basis':'validated_access_documents_not_attackers_or_unique_people'}
    if not public:result['state']='internal_only' if internal else 'no_access_data';return result
    if not database:result['state']='configuration_required';return result
    p=Path(database)
    if p.is_symlink() or not p.is_file() or any(a.is_symlink() for a in p.parents) or p.stat().st_size>256*1024*1024:
        raise InsightError('invalid_geo_database',503)
    try:import maxminddb
    except ImportError:
        result['state']='dependency_required';return result
    countries=Counter();matched=[]
    with maxminddb.open_database(str(p),mode=maxminddb.MODE_MMAP) as geo:
        metadata=geo.metadata();built=datetime.fromtimestamp(metadata.build_epoch,timezone.utc)
        if metadata.database_type not in ('GeoLite2-Country','GeoIP2-Country'):raise InsightError('country_database_required',503)
        result['database_version']=str(metadata.build_epoch);result['attribution']='This product includes GeoLite/GeoIP data created by MaxMind, available from https://www.maxmind.com.'
        if not 0<=(datetime.now(timezone.utc)-built).total_seconds()<=35*86400:
            result['state']='database_stale';return result
        cache={}
        for r,ip in public:
            if ip not in cache:
                value=geo.get(ip) or {};country=value.get('country',{}).get('iso_code')
                cache[ip]=country if isinstance(country,str) and re.fullmatch('[A-Z]{2}',country) else None
            country=cache[ip]
            if country:
                countries[country]+=1
                if values.get('country') in (None,country):matched.append({**r,'country':country})
    result.update(countries=[{'country':k,'count':v} for k,v in countries.most_common()],located=sum(countries.values()),
                  unknown=len(public)-sum(countries.values()),rows=matched[offset:offset+50],
                  next_offset=offset+50 if offset+50<len(matched) else None)
    result['coverage_percent']=round(100*result['located']/result['total'],2) if result['total'] else 0
    result['public_coverage_percent']=round(100*result['located']/result['public'],2) if result['public'] else None
    return result


def account_alert_links(reader,operations,pairs):
    rows,state,f,values,offset=reader.dataset(pairs,'cloud')
    if set(values)-{'start','end','provider','account','organization'} or not all(values.get(k) for k in ('provider','account','organization')):
        raise InsightError('account_scope_required')
    refs={(r['reference']['index'],r['reference']['id']) for r in rows if accepted_cloud(r)
          and r['organization']==values['organization'] and r['cloud_provider']==values['provider'] and r['cloud_account']==values['account']}
    seconds=(aware(f.end)-aware(f.start)).total_seconds()
    alerts=operations.series([operations.alert_index],'@timestamp',f.start,f.end,'5m' if seconds<=86400 else '1h',alerts=True,cloud_only=True)
    linked=[];checked=0
    from cloud_soc.portal.dashboard_insights import response_body
    for alert in alerts['rows'][:5]:
        if alert['organization']!=values['organization']:continue
        checked+=1
        detail=response_body(operations.detail([('id',alert['id'])]))
        if not detail['evidence_count']:continue
        evidence=response_body(operations.detail([('id',alert['id']),('evidence','0')]))['evidence']
        raw=evidence.get('raw',{})
        if evidence.get('integrity')=='normalized_hash_verified' and (raw.get('index'),raw.get('id')) in refs:linked.append(alert)
    return {'state':'ok','rows':linked,'examined':checked,'cloud_alert_total':alerts['count'],
            'basis':'first_verified_evidence_of_latest_five_cloud_alerts_not_full_account_alert_count',
            'scope':{'organization':values['organization'],'provider':values['provider'],'account':values['account']}}

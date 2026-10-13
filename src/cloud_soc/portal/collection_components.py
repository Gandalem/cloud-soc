"""Bounded admin view of declared collection switches and actual ES receipts."""
from datetime import datetime, timedelta, timezone
import json
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.collection_health import project as project_health

KINDS = {
    'system':('soc-host-raw-*',['linux_file','linux_journald','windows_file','windows_event']),
    'web':('soc-host-raw-*',['generic_web_access','web_access_metadata']),
    'network':('soc-network-*',['network_packetbeat']),
}


def state(configured, received, now, *, errors=0, report_recent=True):
    result={'last_received':iso(received) if received else None}
    if errors: value='error'
    elif configured is False and report_recent: value='unconfigured'
    elif received is None: value='no_data' if configured is True else 'unknown'
    elif (now-received).total_seconds() < -60: value='unknown'
    elif (now-received).total_seconds() > 900 or not report_recent: value='delayed'
    else: value='normal'
    return {**result,'state':value,'configured':configured}


def snapshot(client, now=None):
    now=now or datetime.now(timezone.utc)
    reader=client.options(request_timeout=5,max_retries=0)
    response=reader.search(index='soc-agent-health-*',size=0,timeout='4s',allow_no_indices=True,
        allow_partial_search_results=False,
        query={'range':{'event.ingested':{'gte':iso(now-timedelta(days=30)),'lte':iso(now+timedelta(minutes=1))}}},
        aggs={'agents':{'composite':{'size':10,'sources':[
            {'organization':{'terms':{'field':'organization.id','missing_bucket':True}}},
            {'agent_id':{'terms':{'field':'agent.id'}}}]},'aggs':{'latest':{'top_hits':{'size':1,
                'sort':[{'event.ingested':'desc'}], '_source':['host.id','host.name','cloud_soc.discovery','event.ingested']}}}}})
    if response.get('timed_out') or response.get('_shards',{}).get('failed'): raise ValueError('Incomplete collection report')
    rows,searches,positions=[],[],[]
    for bucket in response.get('aggregations',{}).get('agents',{}).get('buckets',[]):
        source=bucket['latest']['hits']['hits'][0]['_source']; report=project_health(source,bucket['key'],now)
        declared=source['cloud_soc']['discovery'].get('collection')
        if (not isinstance(declared,dict) or declared.get('schema')!=1 or
            any(type(declared.get(k)) is not bool for k in KINDS) or
            type(declared.get('web_errors')) is not int or not 0<=declared['web_errors']<=8):declared=None
        host_id=source.get('host',{}).get('id'); org=bucket['key'].get('organization')
        row={'host_name':report['host'],'agent_id':report['agent_id'],'organization':report['organization'],
             'reported_at':report['received_at'],'identity':'agent_reported_not_attested'}
        for kind,(index,sources) in KINDS.items():
            enabled=declared[kind] if declared else None
            errors=declared['web_errors'] if declared and kind=='web' else report['errors'] if kind=='system' else 0
            if enabled is False: errors=0
            row[kind]=state(enabled,None,now,errors=errors,report_recent=report['report_state']=='recent')
            if not isinstance(host_id,str) or not host_id or len(host_id)>256 or not isinstance(org,str) or not org:continue
            searches += [{'index':index,'allow_no_indices':True,'ignore_unavailable':True,'allow_partial_search_results':False},
                {'size':1,'timeout':'4s','sort':[{'event.ingested':{'order':'desc','unmapped_type':'date'}}],
                 '_source':['event.ingested'],'query':{'bool':{'filter':[{'bool':{'minimum_should_match':1,'should':[{'term':{'host.id':host_id}},{'term':{'host.id.keyword':host_id}}]}},
                  {'term':{'organization.id':org}},{'terms':{'labels.log_source':sources}},
                  {'range':{'event.ingested':{'gte':iso(now-timedelta(days=30))}}}]}}}]
            positions.append((len(rows),kind,enabled,errors,report['report_state']=='recent'))
        rows.append(row)
    if searches:
        response=reader.msearch(searches=searches,max_concurrent_searches=3)
        replies=response.get('responses',[])
        if len(replies)!=len(positions):raise ValueError('Incomplete component receipts')
        for (pos,kind,enabled,errors,recent),reply in zip(positions,replies):
            if reply.get('error') or reply.get('timed_out') or reply.get('_shards',{}).get('failed'):raise ValueError('Component receipt query failed')
            hits=reply.get('hits',{}).get('hits',[])
            received=parse_time(hits[0]['_source'].get('event',{}).get('ingested')) if hits else None
            rows[pos][kind]=state(enabled,received,now,errors=errors,report_recent=recent)
    payload={'rows':rows,'checked_at':iso(now),'limit':10,'scope':'latest_reports_sample_not_fleet_total','basis':'declared_settings_and_server_ingestion'}
    if len(json.dumps(payload).encode())>65536:raise ValueError('Component response too large')
    return payload

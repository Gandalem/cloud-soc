"""Bounded server-side dashboard queries, scoped through existing access readers."""
from collections import Counter
import json
import re
import threading
import time

from cloud_soc.portal.insight_state import InsightError, identity, integer
from cloud_soc.portal.log_contract import parse_filters
from cloud_soc.portal.log_query import FIELD_HELPER, project_list_hit, valid_sort

IAM = frozenset(('CreateUser','DeleteUser','CreateAccessKey','UpdateAccessKey','DeleteAccessKey','AttachUserPolicy',
                 'DetachUserPolicy','AttachRolePolicy','DetachRolePolicy','PutUserPolicy','PutRolePolicy','CreatePolicy',
                 'CreatePolicyVersion','SetDefaultPolicyVersion','UpdateAssumeRolePolicy','AddUserToGroup',
                 'RemoveUserFromGroup','UpdateUser','CreateGroup','DeleteGroup','CreatePolicy','UpdatePolicy',
                 'DeletePolicy','AddUserToGroup','RemoveUserFromGroup'))
AUDIT = frozenset(('StopLogging','DeleteTrail','UpdateTrail','StartLogging','PutEventSelectors',
                   'CreateAuditConfiguration','UpdateConfiguration','UpdateAuditConfiguration'))
CLOUD_SOURCES = ('aws_cloudtrail','oci_audit')
WEB_SOURCES = ('generic_web_access','web_access_metadata','security_mall_edge')


def response_body(value):
    return json.loads(value) if isinstance(value,(bytes,str)) else value


def selection(pairs):
    values={}
    for k,v in pairs:
        if k in values or k not in ('start','end','provider','account','group','offset','country','organization'):
            raise InsightError('invalid_query')
        values[k]=v
    f=parse_filters([(k,values[k]) for k in ('start','end') if k in values])
    if values.get('provider') not in (None,'aws','oci'):raise InsightError('invalid_provider')
    if 'account' in values:identity(values['account'])
    if 'organization' in values:identity(values['organization'])
    if values.get('group') not in (None,'iam','audit'):raise InsightError('invalid_cloud_group')
    if 'country' in values and not re.fullmatch('[A-Z]{2}',values['country']):raise InsightError('invalid_country')
    offset=values.get('offset','0')
    if not re.fullmatch('[0-9]{1,5}',offset):raise InsightError('invalid_offset')
    return f,values,int(offset)


def accepted_cloud(row):
    return (row['source_kind'] in CLOUD_SOURCES and row['cloud_provider'] in ('aws','oci')
            and row['interpretation']['status'] in ('recognized','partial')
            and (row['source_kind']=='aws_cloudtrail')==(row['cloud_provider']=='aws'))


def account_key(row):
    try:
        identity(row.get('organization'));identity(row.get('cloud_account'))
    except InsightError:return None
    if row.get('cloud_provider') not in ('aws','oci'):return None
    return row['organization'],row['cloud_provider'],row['cloud_account']


def cloud_summary(rows, *, limit=50):
    valid=[r for r in rows if accepted_cloud(r)]
    def grouped(key):
        counts=Counter(r[key] for r in valid if r.get(key))
        return [{'title':str(k),'count':v} for k,v in sorted(counts.items(),key=lambda item:(-item[1],str(item[0])))]
    account_counts=Counter(key for r in valid if (key:=account_key(r)) is not None)
    accounts=[{'organization':o,'provider':p,'account':a,'count':n} for (o,p,a),n in sorted(account_counts.items())]
    groups={'iam':[r for r in valid if r.get('action') in IAM],'audit':[r for r in valid if r.get('action') in AUDIT]}
    return {'state':'ok','basis':'complete_bounded_server_query','total':len(rows),'recognized':len(valid),
            'invalid_or_unsupported':len(rows)-len(valid),'unidentified_account_events':sum(account_key(r) is None for r in valid),'rows':valid[:limit],
            'services':grouped('cloud_service'),'accounts':accounts,
            'iam':{'count':len(groups['iam']),'rows':groups['iam'][:limit]},
            'audit':{'count':len(groups['audit']),'rows':groups['audit'][:limit]}}


def evidence_flow(operations, alert_id, offset=0, limit=10):
    integer(offset,0,100000);integer(limit,1,10)
    detail=response_body(operations.detail([('id',alert_id),('offset',str(offset)),('limit',str(limit))]))
    kind=detail.get('rule_snapshot',{}).get('type') if isinstance(detail.get('rule_snapshot'),dict) else None
    rows=[]
    for position in detail['evidence_page']['positions']:
        found=response_body(operations.detail([('id',alert_id),('evidence',str(position))]))['evidence']
        event=found.get('normalized_event',{})
        rows.append({'position':position,'state':found.get('state'),'integrity':found.get('integrity'),
                     'raw_integrity':found.get('raw_integrity'),'raw':found.get('raw'),'normalized':found.get('normalized'),
                     'event':{k:event.get(k) for k in ('timestamp','action','outcome','organization','host_id','site_id','source_ip')}})
    return {'state':'ok','checked_at':int(time.time()),'alert':detail['alert'],'kind':kind or 'unspecified','rule_version':detail.get('rule_version'),
            'condition':detail.get('condition'),'total':detail['evidence_count'],'rows':rows,
            'next_offset':detail['evidence_page']['next_offset'],
            'basis':'stored_rule_match_order' if kind=='sequence' else 'matched_evidence_list_not_attack_causality'}


class InsightReader:
    def __init__(self, reader, *, clock=time.monotonic, max_events=10000, seconds=12):
        self.reader,self.clock,self.max_events,self.seconds=reader,clock,max_events,seconds
        self.cache={};self.lock=threading.Lock()

    def scan(self, filters, mode, values):
        r=self.reader;r.require_client();names=r.indices(r.allowed_indices)
        if not names:return [],'no_index'
        r.check_mappings(names,filters)
        if len(names)>64:raise InsightError('query_scope_capacity',413)
        deadline=self.clock()+self.seconds;pit=None;after=None;rows=[];seen=set();last=None
        try:
            opened=r.client.open_point_in_time(index=','.join(names),keep_alive='30s',allow_partial_search_results=False)
            pit=opened['id']
            if opened.get('_shards',{}).get('failed'):raise InsightError('incomplete_query',503)
            while True:
                if self.clock()>deadline:raise InsightError('query_time_limit',503)
                body=r.body(filters,pit,after);body['size']=250
                clauses=body['query']['bool']['filter'];runtime=body.setdefault('runtime_mappings',{})
                if values.get('organization'):
                    if r.organizations is not None and values['organization'] not in r.organizations:raise InsightError('organization_forbidden',403)
                    clauses.append({'term':{'organization.id':values['organization']}})
                runtime['insight_source']={'type':'keyword','script':{'source':FIELD_HELPER+"def v=value(params._source,'labels.log_source');if(v instanceof String)emit(v);"}}
                clauses.append({'terms':{'insight_source':list(CLOUD_SOURCES if mode=='cloud' else WEB_SOURCES)}})
                if mode=='cloud':
                    for name,path in (('provider','cloud.provider'),('account','cloud.account.id')):
                        if values.get(name):
                            field='insight_'+name;runtime[field]={'type':'keyword','script':{'source':FIELD_HELPER+"def v=value(params._source,params.path);if(v instanceof String)emit(v);",'params':{'path':path}}}
                            clauses.append({'term':{field:values[name]}})
                    if values.get('group'):
                        runtime['insight_api']={'type':'keyword','script':{'source':FIELD_HELPER+"def v=value(params._source,'event.action');if(v instanceof String)emit(v);"}}
                        clauses.append({'terms':{'insight_api':sorted(IAM if values['group']=='iam' else AUDIT)}})
                else:
                    runtime['insight_access']={'type':'boolean','script':{'source':FIELD_HELPER+"def k=value(params._source,'labels.log_source');emit(k!='security_mall_edge'||value(params._source,'security_mall_edge.stream')=='access');"}}
                    clauses.append({'term':{'insight_access':True}})
                result=r.client.search(body=body,allow_partial_search_results=False);pit=result.get('pit_id',pit)
                if result.get('timed_out') or result.get('terminated_early') or result.get('_shards',{}).get('failed'):
                    raise InsightError('incomplete_query',503)
                hits=result['hits']['hits']
                if len(hits)>250:raise InsightError('invalid_page',503)
                for hit in hits:
                    order=hit.get('sort');key=(hit['_index'],hit['_id'])
                    if not valid_sort(order) or key in seen:raise InsightError('invalid_page',503)
                    current=(-order[0],order[1])
                    if last is not None and current<=last:raise InsightError('invalid_page',503)
                    last=current;seen.add(key);row=project_list_hit(hit)
                    if values.get('organization') and row['organization']!=values['organization']:raise InsightError('scope_mismatch',503)
                    if mode=='cloud' and any(values.get(k) and row.get(field)!=values[k] for k,field in (('provider','cloud_provider'),('account','cloud_account'))):raise InsightError('scope_mismatch',503)
                    if hit['_index'] not in names or (r.organizations is not None and row['organization'] not in r.organizations):
                        raise InsightError('scope_mismatch',503)
                    if len(rows)>=self.max_events:raise InsightError('query_event_capacity',413)
                    rows.append(row)
                if len(hits)<250:return rows,'ok'
                after=hits[-1]['sort']
        finally:
            r.close(pit)

    def dataset(self, pairs, mode):
        try:f,values,offset=selection(pairs)
        except ValueError as e:
            if isinstance(e,InsightError):raise
            raise InsightError('invalid_query') from None
        key=(mode,f.start,f.end,values.get('provider'),values.get('account'),values.get('group'),values.get('organization'))
        # Per-principal instance; never share cached tenant rows across identities.
        with self.lock:
            cached=self.cache.get(key)
            if cached and self.clock()-cached[0]<30:return cached[1],cached[2],f,values,offset
            rows,state=self.scan(f,mode,values)
            self.cache={k:v for k,v in self.cache.items() if self.clock()-v[0]<30}
            if len(self.cache)>=12:self.cache.clear()
            self.cache[key]=(self.clock(),rows,state)
        return rows,state,f,values,offset

    def cloud(self,pairs):
        rows,state,f,values,offset=self.dataset(pairs,'cloud');result=cloud_summary(rows)
        if set(values)-{'start','end','provider','account','organization','group','offset'}:raise InsightError('invalid_query')
        valid=[r for r in rows if accepted_cloud(r)]
        result.update(state='no_index' if state=='no_index' else 'no_cloud_data' if not rows else 'ok',rows=valid[offset:offset+50],next_offset=offset+50 if offset+50<len(valid) else None,
                      filters={'start':f.start,'end':f.end,'time_basis':'ingested'},data_state=state)
        # Bound high-cardinality distributions; never label truncation as a full display.
        result['account_total']=len(result['accounts']);result['service_total']=len(result['services'])
        result['accounts']=result['accounts'][:100];result['services']=result['services'][:100]
        return result

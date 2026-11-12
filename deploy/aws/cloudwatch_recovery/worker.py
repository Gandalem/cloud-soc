"""Recover CloudTrail management events from the configured Filebeat mirror."""
import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from elasticsearch import Elasticsearch
from cloud_soc.aws.cloudtrail import project_event
from cloud_soc.deployment.contract import AWS_RULE_IDS, policy, validate_rules
from cloud_soc.detection.engine import detect_rule, rule_revision
from cloud_soc.detection.telemetry import evaluate, runs, stats_for
from cloud_soc.detection.worker import approved_rules
from cloud_soc.elastic.repository import save_security_alert
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import NORMALIZED, RECORDS, normalize
from cloud_soc.processing.worker import create_batch

RAW = 'soc-host-raw-linux-*'
VERSION = 'cloudwatch-cloudtrail-recovery-v1'
STATE = Path('/data')
STEP = timedelta(minutes=15)
WRITE_ALERTS = True
RAW_FIELDS = ['@timestamp','event.ingested','event.id','input.type','log_source',
              'organization.id','aws.cloudwatch.log_stream','aws.cloudwatch.log_group']

def configure_scope(source_label):
    global GROUP, REGION, ACCOUNT, ORG, GROUP_ARN, FLOOR, FILTER
    GROUP = os.environ['SOC_CW_LOG_GROUP']
    REGION = os.environ['SOC_CW_REGION']
    ACCOUNT = os.environ['SOC_CW_ACCOUNT_ID']
    ORG = os.environ['SOC_CW_ORGANIZATION']
    FLOOR = datetime.fromisoformat(os.environ['SOC_CW_HISTORY_START'])
    if (not re.fullmatch(r'[0-9]{12}', ACCOUNT)
            or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', REGION)
            or not re.fullmatch(r'[A-Za-z0-9_/.-]{1,512}', GROUP)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', ORG)
            or FLOOR.tzinfo is None):
        raise ValueError('invalid_cloudwatch_source_scope')
    GROUP_ARN = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{GROUP}'
    FILTER = [{'term': {'input.type.keyword':'aws-cloudwatch'}},
              {'term': {'log_source.keyword':source_label}},
              {'term': {'organization.id':ORG}},
              {'term': {'aws.cloudwatch.log_group.keyword':GROUP_ARN}}]


def now():
    return datetime.now(timezone.utc)

def millis(value):
    stamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    delta = stamp - datetime(1970,1,1,tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000

def checked(response):
    if response.get('timed_out') or response.get('_shards', {}).get('failed'):
        raise RuntimeError('incomplete_elasticsearch_response')
    return response

def hits(es, basis, start, end):
    query = {'bool':{'filter':FILTER + [{'range':{basis:{'gte':start.isoformat(),'lt':end.isoformat()}}}]}}
    result = checked(es.search(index=RAW, size=4000, query=query, source_includes=RAW_FIELDS,
                              track_total_hits=True, allow_partial_search_results=False))
    total = result['hits']['total']['value']
    rows = result['hits']['hits']
    if total == len(rows):
        yield from rows
        return
    if end - start <= timedelta(milliseconds=2):
        raise RuntimeError('too_many_simultaneous_receipts')
    middle = start + (end-start)/2
    yield from hits(es,basis,start,middle)
    yield from hits(es,basis,middle,end)

def originals(logs, rows):
    wanted = {field(row['_source'],'event.id') for row in rows}
    stamps = [millis(row['_source']['@timestamp']) for row in rows]
    params = dict(logGroupName=GROUP,startTime=min(stamps),endTime=max(stamps)+1)
    if len(streams := {field(row['_source'],'aws.cloudwatch.log_stream') for row in rows}) <= 100:
        params['logStreamNames'] = sorted(streams)
    matched = {}
    for n,page in enumerate(logs.get_paginator('filter_log_events').paginate(**params)):
        if n >= 500:
            raise RuntimeError('cloudwatch_page_limit')
        for event in page['events']:
            if event['eventId'] in wanted:
                matched[event['eventId']] = event
        if len(matched) == len(wanted):
            break
    return matched

def recovery(hit, original, stamp, historical):
    raw = hit['_source']
    cw_id = field(raw, 'event.id')
    if not original:
        return 'original_missing', None
    if (original['logStreamName'] != field(raw,'aws.cloudwatch.log_stream')
            or original['timestamp'] != millis(raw['@timestamp'])):
        return 'original_mismatch', None
    try:
        payload = json.loads(original['message'])
        _, record, _ = normalize(hit, stamp)
        index, key, metadata = project_event({
            'CloudTrailEvent':original['message'], 'EventId':payload['eventID'],
            'EventTime':payload['eventTime'],
        },account=ACCOUNT,region=payload['awsRegion'],organization=ORG)
    except (ValueError,KeyError,TypeError):
        return 'outside_management_contract', None
    metadata['event']['ingested'] = field(raw,'event.ingested')
    _, _, normalized = normalize({'_index':index,'_id':key,'_source':metadata}, stamp)
    if normalized is None:
        return 'normalizer_rejected', None
    if record.get('reason') != 'adapter_not_supported':
        raise RuntimeError('raw_adapter_scope_changed')
    reference = record['raw']
    identifier = hashlib.sha256(json.dumps([record['version'],reference],sort_keys=True).encode()).hexdigest()
    provider_ms = millis(normalized['@timestamp'])
    is_history = historical or millis(stamp)-provider_ms >= 13*60000
    if is_history:
        normalized['cloud_soc']['recovery_mode'] = 'cloudwatch_history'
    normalized['cloud_soc']['provenance']['raw'] = reference
    normalized['cloud_soc']['provenance']['cloudwatch_match'] = {
        'method':'event_id_stream_timestamp','collector_timestamp':raw['@timestamp'],
        'collector_event_id_sha256':hashlib.sha256(cw_id.encode()).hexdigest(),
    }
    normalized['cloud_soc']['normalizer_version'] = VERSION
    normalized['cloud_soc']['provenance']['time'] = {
        'basis':'provider_event_time','receipt_basis':'original_soc_receipt','year_inferred':False}
    record.update(status='normalized',reason=normalized['cloud_soc']['parse_status'],
                  adapter='aws_cloudtrail_metadata_v1',
                  normalized={'index':NORMALIZED,'id':identifier},
                  recovery={'version':VERSION,'previous_reason':'adapter_not_supported'})
    return 'prepared', (identifier,record,normalized)

def write_records(es, candidates):
    ops=[]
    for identifier,record,_ in candidates:
        ops.extend([{'update':{'_index':RECORDS,'_id':identifier,'retry_on_conflict':3}},
                    {'script':{'lang':'painless',
                      'source':"if (ctx._source.raw != params.doc.raw) {throw new IllegalArgumentException('raw_mismatch');} "
                               "if (ctx._source.status == 'unsupported' && ctx._source.reason == 'adapter_not_supported') "
                               "{ctx._source = params.doc;} "
                               "else if (ctx._source.status == 'normalized' && ctx._source.normalized == params.doc.normalized) "
                               "{ctx.op = 'noop';} else {throw new IllegalArgumentException('unexpected_processing_status');}",
                      'params':{'doc':record}},'upsert':record}])
    r=es.bulk(operations=ops)
    if len(r['items'])!=len(candidates) or any(item['update']['status'] not in (200,201) for item in r['items']):
        raise RuntimeError('processing_record_update_failed')

def process(es, logs, rules, rows, historical, stamp, counts, stats):
    found=originals(logs,rows)
    candidates=[]
    for hit in rows:
        counts['raw']+=1
        code, candidate = recovery(hit,found.get(field(hit['_source'],'event.id')),stamp,historical)
        if candidate:
            candidates.append(candidate)
        else:
            counts[code]+=1
    for offset in range(0,len(candidates),150):
        batch=candidates[offset:offset+150]
        create_batch(es,[(NORMALIZED,key,doc) for key,_,doc in batch])
        docs=es.mget(index=NORMALIZED,ids=[key for key,_,_ in batch])['docs']
        if len(docs)!=len(batch):
            raise RuntimeError('recovered_documents_missing')
        for (key,record,_),saved in zip(batch,docs):
            if not saved.get('found') or saved['_id']!=key:
                raise RuntimeError('recovered_document_missing')
            event=saved['_source']
            if (field(event,'cloud_soc.provenance.raw')!=record['raw']
                    or field(event,'cloud_soc.normalizer_version')!=VERSION):
                raise RuntimeError('recovered_provenance_conflict')
            counts['normalized']+=1
            eligibility=field(event,'cloud_soc.detail.fields.eligibility')
            if eligibility in ('not_applicable','not_evaluable'):
                record['recovery']['assessment']=eligibility
                counts[eligibility]+=1
                if eligibility=='not_evaluable':
                    for rule in rules:
                        stats[rule['id']]['input_events']+=1
                        stats[rule['id']]['source_events']+=1
                        stats[rule['id']]['unknown']+=1
                continue
            if field(event,'cloud_soc.recovery_mode') not in ('cloudwatch_history','cloudwatch_source_worker'):
                record['recovery']['assessment'] = 'routed_live'
                counts['routed_live']+=1
                continue
            event['_cloud_soc_meta']={'index':NORMALIZED,'document_id':key}
            complete=True
            for rule in rules:
                metric=stats[rule['id']]
                metric['source_events']+=1
                metric['input_events']+=1
                outcome,missing=evaluate(event,rule)
                metric[outcome]+=1
                if outcome in ('unknown','excluded'):
                    complete=False
                if outcome!='matched':
                    continue
                if WRITE_ALERTS:
                    for match in detect_rule([event],rule):
                        result=save_security_alert(es,build_security_alert(match),document_id=make_alert_id(match),
                                                   refresh=False,index_prepared=True)
                        metric['alerts_'+result['result']]+=1
                        counts['alerts_'+result['result']]+=1
                else:
                    record['recovery'].setdefault('matched_rules',[]).append(rule['id'])
                    counts['matched']+=1
                    metric['detection_matches']=metric.get('detection_matches',0)+1
            result = 'evaluated' if complete else 'not_evaluable'
            record['recovery']['assessment'] = result
            counts[result]+=1
        write_records(es,batch)

def window(es,logs,rules,start,end,historical):
    stamp=now().isoformat()
    stats=stats_for(rules)
    counts=Counter()
    buckets=defaultdict(list)
    for hit in hits(es,'@timestamp' if historical else 'event.ingested',start,end):
        bucket=millis(hit['_source']['@timestamp'])//900000
        buckets[bucket].append(hit)
    for rows in buckets.values():
        process(es,logs,rules,rows,historical,stamp,counts,stats)
    if any(item['source_events'] for item in stats.values()):
        basis='history' if historical else 'receipt'
        material=[VERSION,basis,start.isoformat(),end.isoformat(),[rule_revision(r) for r in rules]]
        run_id=hashlib.sha256(json.dumps(material).encode()).hexdigest()
        runs(es,rules,stats,run_id=run_id,stamp=stamp,start=start.isoformat(),end=end.isoformat(),state='committed')
    return dict(counts)

def main():
    release=policy(Path('/app'))
    validate_rules(release)
    rules=approved_rules(additional_rule_ids=list(AWS_RULE_IDS))
    if any(rule['type']!='single' for rule in rules):
        raise RuntimeError('historical_rules_must_be_single_event')
    es=Elasticsearch('https://elasticsearch:9200',api_key=Path('/run/worker.key').read_text().strip(),
                     ca_certs='/run/ca.crt',request_timeout=45,max_retries=1)
    logs=boto3.client('logs',region_name=REGION,config=Config(retries={'mode':'standard','max_attempts':5}))
    with sqlite3.connect(STATE/'progress.sqlite') as db:
        db.execute('CREATE TABLE IF NOT EXISTS progress (lane TEXT PRIMARY KEY, cursor TEXT, end TEXT, totals TEXT)')
        cutover=now()-timedelta(minutes=3)
        db.executemany('INSERT OR IGNORE INTO progress VALUES (?,?,?,?)',[
            ('history',FLOOR.isoformat(),cutover.isoformat(),'{}'),
            ('live',cutover.isoformat(),None,'{}')])
        db.commit()
        while True:
            activity=False
            for lane in ('live','history'):
                cursor,ceiling,totals=db.execute('SELECT cursor,end,totals FROM progress WHERE lane=?',(lane,)).fetchone()
                start=datetime.fromisoformat(cursor)
                end=min(start+(STEP if lane=='history' else timedelta(minutes=2)),
                        datetime.fromisoformat(ceiling) if ceiling else now()-timedelta(seconds=90))
                if end<=start or (lane=='live' and end-start<timedelta(minutes=1)):
                    continue
                try:
                    counts=window(es,logs,rules,start,end,lane=='history')
                    cumulative=Counter(json.loads(totals))
                    cumulative.update(counts)
                    db.execute('UPDATE progress SET cursor=?,totals=? WHERE lane=?',
                               (end.isoformat(),json.dumps(cumulative),lane))
                    db.commit()
                    print(json.dumps({'state':'success','lane':lane,'checkpoint':end.isoformat(),
                                      'counts':counts,'totals':cumulative}),flush=True)
                    activity=True
                except Exception as error:
                    db.rollback()
                    print(json.dumps({'state':'error','lane':lane,'type':type(error).__name__,
                                      'reason':str(error) if isinstance(error,RuntimeError) and str(error).replace('_','').isalnum() else None,
                                      'status':getattr(error,'status_code',None),
                                      'aws':getattr(error,'response',{}).get('Error',{}).get('Code') if isinstance(getattr(error,'response',None),dict) else None}),flush=True)
            time.sleep(2 if activity else 15)

if __name__=='__main__':
    configure_scope('aws_cloudtrail')
    main()

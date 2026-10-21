"""Explicit recent/history receipt runners; existing checkpoints retain their scope."""
import argparse
from datetime import datetime, timezone
import signal
import threading
from pathlib import Path
import re

from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.portal.log_contract import document_reference
from cloud_soc.processing.mall_runtime import private_json, error_code
from cloud_soc.processing.worker import run_once


def configuration(value):
    required={'mode','start','state','es_url','ca_file','api_key_file','source_indices',
              'normalized_index','records_index','status_index','interval_seconds',
              'window_minutes','max_pages','receipt_lag_seconds','overlap_seconds','burst_cycles'}
    if not isinstance(value,dict) or set(value)!=required or value['mode'] not in ('recent','history'):
        raise ValueError('processing_scope_invalid')
    c=dict(value)
    if parse_time(c['start']) is None or parse_time(c['start'])>=datetime.now(timezone.utc):
        raise ValueError('explicit_past_receipt_floor_required')
    c['es_url']=endpoint(c['es_url'])
    for name in ('state','ca_file','api_key_file'):
        if not isinstance(c[name],str) or not Path(c[name]).is_absolute() or Path(c[name]).is_symlink():
            raise ValueError('explicit_private_paths_required')
    raw=c['source_indices']
    if (not isinstance(raw,list) or not 1<=len(raw)<=8 or len(set(raw))!=len(raw)
            or any(not isinstance(n,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,254}',n)
                   or document_reference(n,'scope') is None for n in raw)):
        raise ValueError('exact_source_indices_required')
    for name in ('normalized_index','records_index','status_index'):
        if not isinstance(c[name],str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,254}',c[name]):
            raise ValueError('exact_output_indices_required')
    if len(set([*raw,c['normalized_index'],c['records_index'],c['status_index']]))!=len(raw)+3:
        raise ValueError('processing_roles_overlap')
    for k,low,high in [('interval_seconds',1,60),('window_minutes',1,60),('max_pages',1,1000),
                       ('receipt_lag_seconds',0,300),('overlap_seconds',60,86400),('burst_cycles',1,12)]:
        if type(c[k]) is not int or not low<=c[k]<=high:raise ValueError('processing_budget_invalid')
    if c['mode']=='history' and (c['receipt_lag_seconds'],c['overlap_seconds'])!=(30,900):
        raise ValueError('preserve_history_receipt_policy')
    return c


def main(argv=None):
    parser=argparse.ArgumentParser(description='Scoped persistent receipt processor')
    parser.add_argument('--config',required=True,type=Path)
    args=parser.parse_args(argv)
    stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:stop.set())
    try:
        c=configuration(private_json(args.config))
        state=Path(c['state']);state.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        key=protected_key(c['api_key_file'])
        worker_id='normalizer-priority' if c['mode']=='recent' else 'normalizer'
        with Elasticsearch(c['es_url'],api_key=key,ca_certs=c['ca_file'],verify_certs=True,
                           request_timeout=15,max_retries=0,retry_on_timeout=False) as client:
            burst=0;failures=0
            while not stop.is_set():
                delay=c['interval_seconds']
                try:
                    result=run_once(client,state,c['start'],source_indices=c['source_indices'],
                        normalized_index=c['normalized_index'],records_index=c['records_index'],
                        status_index=c['status_index'],status_id=worker_id,window_minutes=c['window_minutes'],
                        max_pages=c['max_pages'],receipt_lag_seconds=c['receipt_lag_seconds'],overlap_seconds=c['overlap_seconds'])
                    failures=0
                    lag=(datetime.now(timezone.utc)-parse_time(result['checkpoint'])).total_seconds()
                    if c['mode']=='history' and lag>c['window_minutes']*60 and burst<c['burst_cycles']-1:
                        delay=.1;burst+=1
                    else:burst=0
                    print('processing_'+c['mode']+'_'+result['state'],flush=True)
                except Exception as error:
                    failures+=1;delay=min(60,2**min(failures,5))
                    print('processing_'+c['mode']+'_'+error_code(error)+'; checkpoint retained',flush=True)
                stop.wait(delay)
        return 0
    except Exception:
        print('processing_configuration_or_connection_failed; no credentials printed',flush=True)
        return 1


if __name__=='__main__':raise SystemExit(main())

"""Opt-in normalizer for projected audit logs; independent state and API key."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.processing.worker import run_once
from cloud_soc.processing.errors import error_code
from cloud_soc.multicloud.adapter import PATTERN


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start',required=True)
    parser.add_argument('--state',required=True)
    parser.add_argument('--es-url',required=True)
    parser.add_argument('--ca-file',required=True)
    parser.add_argument('--api-key-file',required=True)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--interval',type=int,default=30)
    parser.add_argument('--window-minutes',type=int,default=5)
    parser.add_argument('--max-pages',type=int,default=100)
    args=parser.parse_args(argv)
    start=parse_time(args.start)
    if start is None or start>=datetime.now(timezone.utc) or not 10<=args.interval<=3600 or not 1<=args.window_minutes<=60 or not 1<=args.max_pages<=10000 or args.once and not args.run:
        parser.error('Invalid time or capacity')
    path=Path(args.state)
    if path.name!='multicloud-checkpoint.sqlite' or path.is_symlink():
        parser.error('Use a dedicated multicloud-checkpoint.sqlite, never an existing worker state')
    url=endpoint(args.es_url)
    if not args.run:
        print('Configuration valid; no network or state changes.');return 0
    os.umask(0o077)
    key=protected_key(args.api_key_file)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with Elasticsearch(url,api_key=key,ca_certs=args.ca_file,request_timeout=15,max_retries=0) as client:
        while True:
            try:
                result=run_once(client,path,args.start,source_indices=[PATTERN],status_id='normalizer-multicloud',
                    max_pages=args.max_pages,window_minutes=args.window_minutes)
                print(json.dumps({'state':result['state'],'checkpoint':result['checkpoint'],'counts':result['counts']}),flush=True)
            except Exception as failure:
                print('multicloud_normalization_failed code='+error_code(failure)+'; checkpoint retained',flush=True)
                if args.once:return 1
            if args.once:return 0
            time.sleep(args.interval)

if __name__=='__main__':
    raise SystemExit(main())

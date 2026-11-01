"""Explicit adapter grants; no change to existing worker keys, state, or rules."""
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
ROLE={'cluster':[],'indices':[
    {'names':['soc-multicloud-*'],'privileges':['read','view_index_metadata']},
    {'names':[NORMALIZED,RECORDS],'privileges':['create_doc']},
    {'names':[STATUS],'privileges':['index']}]}

def issue_key(client):
    # Verify destinations already exist; operator uses standard processing.prepare first.
    for index in (NORMALIZED,RECORDS,STATUS):
        if not client.indices.exists(index=index):raise ValueError('Processing destination not prepared')
        mapping=client.indices.get_mapping(index=index)
        if set(mapping)!={index} or mapping[index].get('mappings',{}).get('_meta',{}).get('contract')!=index:
            raise ValueError('Processing destination contract mismatch')
    return client.security.create_api_key(name='cloud-soc-multicloud-normalizer',expiration='30d',
        role_descriptors={'multicloud_normalizer':ROLE})


def main(argv=None):
    import argparse
    import json
    import os
    from pathlib import Path
    from elasticsearch import Elasticsearch
    from cloud_soc.aws.__main__ import endpoint, protected_key
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--es-url',required=True)
    parser.add_argument('--ca-file',required=True)
    parser.add_argument('--admin-key-file',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    url=endpoint(args.es_url)
    if not args.apply:
        print(json.dumps({'apply':False,'role':ROLE,'existing_worker_keys_changed':False}));return 0
    output=Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        parser.error('Output must be a new file in an existing protected directory')
    if output.parent.stat().st_mode & 0o077:parser.error('Output directory must be private (0700)')
    with Elasticsearch(url,api_key=protected_key(args.admin_key_file),ca_certs=args.ca_file,request_timeout=15,max_retries=0) as client:
        issued=issue_key(client)
        try:
            from cloud_soc.secret_store import write_new
            write_new(output,issued['encoded'])
        except Exception:
            client.security.invalidate_api_key(ids=[issued['id']])
            raise
    print(json.dumps({'issued':True,'existing_worker_keys_changed':False}))
    return 0

if __name__=='__main__':
    raise SystemExit(main())

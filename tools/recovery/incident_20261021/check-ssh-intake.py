#!/usr/bin/env python3
"""Read recent raw SSH activity and its exact processing lineage; no writes."""
import json
import os
import subprocess

CHECK = r'''
import json
import hashlib
import cloud_soc.processing.contract as contract
from cloud_soc.portal.app import create_app
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import RECORDS
from cloud_soc.parsers.linux_security import parse_linux_ssh, parse_linux_ssh_source

client = create_app().extensions['monitor']
def search(index, **kwargs):
    result = client.search(index=index, allow_partial_search_results=False, timeout='10s', **kwargs)
    if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
        raise ValueError('incomplete_search')
    return result

filters = [{'term': {'organization.id': 'school'}},
           {'term': {'host.name': 'lyn-virtual-machine'}},
           {'range': {'event.ingested': {'gte': 'now-24h'}}}]
raw = search('soc-host-raw-*', size=20, track_total_hits=True,
    sort=[{'event.ingested':'desc'}], query={'bool': {'filter': filters + [
        {'terms': {'labels.log_source':['linux_file','linux_auth','linux_journald']}}],
        'minimum_should_match':1, 'should':[
            {'match_phrase': {'message': phrase}} for phrase in
            ('Failed password','Invalid user','Failed publickey','Connection closed by invalid user')]}})
normalized = search('soc-normalized-v1', size=5, track_total_hits=True,
    sort=[{'event.ingested':'desc'}], query={'bool': {'filter': filters + [
        {'term': {'event.outcome':'failure'}}, {'term': {'network.protocol':'ssh'}}]}})
rows = []
for hit in raw['hits']['hits']:
    source = hit['_source']
    reference = {'index':hit['_index'], 'id':hit['_id']}
    versions = {value for name,value in vars(contract).items()
                if isinstance(value,str) and (name == 'VERSION' or name.endswith('_VERSION'))}
    versions.add('linux-unclassified-v1')
    identifiers = [hashlib.sha256(json.dumps([version,reference],sort_keys=True).encode()).hexdigest()
                   for version in versions]
    response = client.mget(index=RECORDS, ids=identifiers)
    if any('error' in doc for doc in response['docs']):
        raise ValueError('processing_record_lookup_failed')
    records = [doc['_source'] for doc in response['docs'] if doc.get('found')
               and doc['_source'].get('raw') == reference]
    message = source.get('message','')
    message_kind = next((label for text,label in (
        ('Failed password','failed_password'),('Invalid user','invalid_user'),
        ('Failed publickey','failed_publickey'),
        ('Connection closed by invalid user','connection_closed_invalid_user'))
        if isinstance(message,str) and text in message),'other')
    row = {'occurred':source.get('@timestamp'), 'received':field(source,'event.ingested'),
           'source_family':field(source,'labels.log_source'),
           'message_kind':message_kind,
           'journal_pid_type':type(field(source,'journald.pid')).__name__,
           'ssh_program_present':any(field(source,key) in ('sshd','sshd-session') for key in
               ('process.name','log.syslog.appname','journald.syslog.identifier','journald.process.name')),
           'ssh_parser_recognized':bool(parse_linux_ssh_source(source) or parse_linux_ssh(source.get('message'))),
           'processing':[{'status':r.get('status'),'reason':r.get('reason'),
                          'adapter':r.get('adapter'),'version':r.get('version')} for r in records],
           'exact_normalized_reference_found':False}
    for record in records:
        reference = record.get('normalized')
        if record.get('status') == 'normalized' and reference:
            doc = client.get(index=reference['index'],id=reference['id'])['_source']
            lineage = field(doc,'cloud_soc.provenance.raw')
            if lineage == {'index':hit['_index'],'id':hit['_id']}:
                row['exact_normalized_reference_found'] = True
                row['normalized_outcome'] = field(doc,'event.outcome')
                row['normalized_protocol'] = field(doc,'network.protocol')
    rows.append(row)
result = {'scope':{'organization':'school','host':'lyn-virtual-machine','receipt_window':'last_24_hours'},
          'raw_ssh_candidates':raw['hits']['total'],
          'normalized_ssh_failures':normalized['hits']['total'],
          'latest_normalized_failures':[{'occurred':h['_source'].get('@timestamp'),
              'received':field(h['_source'],'event.ingested'),
              'normalized_at':field(h['_source'],'cloud_soc.normalized_at'),
              'adapter':field(h['_source'],'cloud_soc.detail.adapter')} for h in normalized['hits']['hits']],
          'latest_raw_lineage':rows}
print(json.dumps(result,ensure_ascii=False,indent=2))
'''

if os.geteuid() != 0:
    raise SystemExit('Run with sudo python3.')
# The existing portal supplies its own read credentials internally; none are printed.
result = subprocess.run(['docker','--host','unix:///var/run/docker.sock','exec','-i',
    'cloud-soc-central-portal-1','python','-'],input=CHECK,text=True,capture_output=True,timeout=180)
if result.returncode:
    # Never echo exception bodies from credentialed requests.
    lines = result.stderr or ''
    kind = next((name for name in ('AuthenticationException','AuthorizationException',
                 'NotFoundError','ConnectionTimeout','BadRequestError') if name in lines),'read_check_failed')
    raise SystemExit('SSH intake check failed: '+kind+'; credentials and raw messages omitted.')
try:
    data = json.loads(result.stdout)
except ValueError:
    raise SystemExit('Unexpected diagnostic output; no credentials printed.') from None
print(json.dumps(data,ensure_ascii=False,indent=2))

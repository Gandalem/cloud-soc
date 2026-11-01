"""Cross-provider, exact-reference, isolation and real engine adapter checks."""
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock
from cloud_soc.multicloud.normalize import normalize as collect
from cloud_soc.processing.contract import normalize,NORMALIZED
from cloud_soc.portal.log_query import project_list_hit,LogReader
from cloud_soc.processing.worker import DEFAULT_SOURCE_INDICES,run_once
from cloud_soc.processing.setup import ROLE
from cloud_soc.multicloud.processing_setup import ROLE as MC_ROLE
from cloud_soc.detection.engine import event_matches_rule,event_evidence
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.detection.profiles import source_observed
from test_processing import START,NOW
from test_log_query import client as read_client


def hit(provider='aws'):
    scope={'account':'acct' if provider!='aws' else '123456789012','organization':'school','id':'test-collector'}
    raw={'aws':{'recipientAccountId':scope['account'],'eventID':'unique','eventTime':START,
                  'eventName':'StopLogging','eventSource':'cloudtrail.amazonaws.com','awsRegion':'us-west-2',
                  'userIdentity':{'arn':'arn:aws:iam::123456789012:user/a'},'sourceIPAddress':'192.0.2.8'},
         'azure':{'subscriptionId':'acct','eventDataId':'unique','time':START,'operationName':'Microsoft.Authorization/roleAssignments/write',
                  'resultType':'Failed','caller':'operator','location':'westus','callerIpAddress':'192.0.2.9'},
         'naver':{'historyId':'unique','eventTime':START,'nrn':'nrn:public:server:kr:acct:server/x','actionDisplayName':'login',
                  'productName':'IAM','actionIdNo':'operator','regionCode':'KR','sourceIp':'192.0.2.10','actionResultType':'FAIL'}}[provider]
    index,key,source=collect(provider,raw,scope)
    source['event']['ingested']='2026-09-22T01:01:00Z'
    return {'_index':index,'_id':key,'_source':source}

class AdapterTests(unittest.TestCase):
    def test_all_providers_list_normalize_and_preserve_exact_evidence(self):
        for provider in ('aws','azure','naver'):
            with self.subTest(provider=provider):
                source=hit(provider);row=project_list_hit(source)
                self.assertEqual((row['source_kind'],row['os'],row['stream']),('multicloud_audit','cloud','cloud'))
                self.assertEqual(row['interpretation']['status'],'recognized')
                key,record,event=normalize(source,'2026-09-22T01:20:00Z')
                self.assertEqual(record['status'],'normalized')
                self.assertEqual(event['cloud']['provider'],provider)
                self.assertEqual(event['cloud_soc']['provenance']['raw'],{'index':source['_index'],'id':source['_id']})
                self.assertEqual(event['@timestamp'],START)
                self.assertEqual(event['event']['ingested'],'2026-09-22T01:01:00Z')
                self.assertEqual(event['cloud_soc']['normalized_at'],'2026-09-22T01:20:00Z')
                self.assertTrue(event_evidence({**event,'_cloud_soc_meta':{'index':NORMALIZED,'document_id':key}})['complete'])
                self.assertNotIn('message',event)
                self.assertEqual(normalize(source,'2026-09-22T01:21:00Z')[0],key)
    def test_aws_audit_event_matches_existing_real_rule_without_ssh_match(self):
        _,_,event=normalize(hit(),'2026-09-22T01:20:00Z')
        rules=load_rules(Path(__file__).resolve().parents[1]/'rules/cloud.yml')
        rule=next(r for r in rules if r['id']=='AWS-AUDIT-001')
        self.assertTrue(event_matches_rule(event,rule))
        self.assertTrue(source_observed(event,'AWS-AUDIT-001'))
        auth=load_rules()[0]
        self.assertFalse(event_matches_rule(event,auth))
    def test_schema_provider_dataset_identity_and_secrets_cannot_be_forged(self):
        mutations=[('soc.schema_version',True),('cloud.provider','oci'),('cloud.provider',{'untrusted':'value'}),('event.dataset','oci.audit'),
                   ('event.id','0'*64),('event.outcome','made-up'),('user.id','token=PRIVATE_CANARY')]
        for path,value in mutations:
            source=hit();parts=path.split('.');target=source['_source']
            for part in parts[:-1]:target=target[part]
            target[parts[-1]]=value
            _,record,event=normalize(source,'2026-09-22T01:20:00Z')
            self.assertEqual(record['status'],'invalid',path)
            self.assertIsNone(event,path)
            self.assertNotIn('PRIVATE_CANARY',json.dumps(record))
    def test_existing_normalizer_scope_and_key_are_not_expanded(self):
        self.assertNotIn('soc-multicloud-*',DEFAULT_SOURCE_INDICES)
        self.assertNotIn('soc-multicloud-*',ROLE['indices'][0]['names'])
        self.assertEqual(MC_ROLE['indices'][0]['names'],['soc-multicloud-*'])
        self.assertEqual(MC_ROLE['cluster'],[])
    def test_new_daily_indices_do_not_change_adapter_checkpoint_scope(self):
        client=Mock();client.options.return_value=client
        client.indices.resolve_index.return_value={'indices':[]}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'multicloud-checkpoint.sqlite'
            a=run_once(client,path,START,now=NOW,source_indices=['soc-multicloud-*'],status_id='normalizer-multicloud')
            b=run_once(client,path,START,now=NOW,source_indices=['soc-multicloud-*'],status_id='normalizer-multicloud')
            self.assertGreater(b['checkpoint'],a['checkpoint'])
            self.assertEqual(client.indices.resolve_index.call_args.kwargs['name'],'soc-multicloud-*')
    def test_multicloud_metadata_cannot_impersonate_a_host_source(self):
        source=hit();source['_index']='soc-host-raw-test'
        _,record,event=normalize(source,'2026-09-22T01:20:00Z')
        self.assertEqual(record['status'],'invalid')
        self.assertEqual(record['reason'],'source_scope_mismatch')
        self.assertIsNone(event)
    def test_independent_status_binding_cannot_overwrite_existing_worker(self):
        client=Mock()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'checkpoint.sqlite'
            for source,status in [(['soc-multicloud-*'],'normalizer'),(None,'normalizer-multicloud')]:
                with self.assertRaises(ValueError):run_once(client,path,START,now=NOW,source_indices=source,status_id=status)
            self.assertFalse(path.exists())

    def test_adapter_failure_is_not_reported_as_full_coverage(self):
        from cloud_soc.portal.operations import Operations
        from unittest.mock import patch
        reader=Operations(Mock())
        with patch.object(reader,'_base_pipeline',return_value={'coverage':{'state':'observed'}}),patch.object(reader,'worker_status',return_value={'state':'failed','health':'failed'}):
            self.assertEqual(reader.pipeline()['coverage'],{'state':'blocked','reason':'multicloud_normalizer_failed'})

    def test_key_issuer_rejects_unprepared_or_foreign_destinations(self):
        from cloud_soc.multicloud.processing_setup import issue_key
        client=Mock();client.indices.exists.return_value=False
        with self.assertRaises(ValueError):issue_key(client)
        client.security.create_api_key.assert_not_called()
        client.indices.exists.return_value=True
        client.indices.get_mapping.return_value={'foreign':{'mappings':{}}}
        with self.assertRaises(ValueError):issue_key(client)
        client.security.create_api_key.assert_not_called()
        client.indices.get_mapping.side_effect=lambda index:{index:{'mappings':{'_meta':{'contract':index}}}}
        issue_key(client)
        grants=client.security.create_api_key.call_args.kwargs['role_descriptors']['multicloud_normalizer']
        self.assertEqual(grants,MC_ROLE)
        client.security.put_role.assert_not_called()

    def test_list_detail_remains_tenant_scoped(self):
        client=read_client();doc=hit();client.get.return_value=doc
        client.indices.resolve_index.return_value={'indices':[{'name':doc['_index']}]}
        reader=LogReader(client,secret='fixture',principal='viewer',organizations=('foreign',))
        from cloud_soc.portal.log_query import LogQueryError
        with self.assertRaises(LogQueryError) as error:
            reader.detail([('index',doc['_index']),('id',doc['_id'])])
        self.assertEqual(error.exception.status,404)

if __name__=='__main__':unittest.main()

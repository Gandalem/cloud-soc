"""Diagnostic facade must never write documents or close the live worker PIT."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock
spec=importlib.util.spec_from_file_location('normalizer_probe',Path(__file__).resolve().parents[1]/'deploy/server/probe-normalizer.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class ProbeSafetyTests(unittest.TestCase):
    def test_status_and_bulk_never_reach_es_writes(self):
        client=Mock();facade=probe.ReadOnlyClient(client)
        self.assertEqual(facade.index(index=probe.worker.STATUS,id='normalizer',document={}),{})
        reply=facade.bulk(operations=[{'create':{'_index':'target'}},{'private':'canary'}])
        self.assertEqual(reply,{'items':[{'create':{'status':201}}]})
        self.assertEqual(facade.document_count,1)
        self.assertEqual(facade.bulk_batches,1)
        self.assertEqual(facade.pending_indices,{'target'})
        client.index.assert_not_called();client.bulk.assert_not_called()
        with self.assertRaises(probe.WriteBoundary):facade.index(index='target',id='x',document={})
        client.index.assert_not_called()
    def test_serializer_failure_precedes_any_document_write(self):
        client=Mock();client.transport.serializers.get_serializer.return_value.dumps.side_effect=TypeError('fixture')
        facade=probe.ReadOnlyClient(client)
        with self.assertRaises(TypeError):facade.bulk(operations=[{'create':{'_index':'target'}},{}])
        client.bulk.assert_not_called()
        self.assertEqual(facade.bulk_batches,0)

    def test_only_probe_owned_pits_are_closed(self):
        client=Mock();client.open_point_in_time.return_value={'id':'own'}
        facade=probe.ReadOnlyClient(client)
        facade.close_point_in_time(id='live-worker')
        client.close_point_in_time.assert_not_called()
        facade.open_point_in_time(index=['raw'],keep_alive='10m')
        facade.close_owned_pits()
        client.close_point_in_time.assert_called_once_with(id='own')
    def test_pit_rotation_stays_owned(self):
        client=Mock();client.open_point_in_time.return_value={'id':'first'};client.search.return_value={'pit_id':'second'}
        facade=probe.ReadOnlyClient(client);facade.open_point_in_time(index=['raw'])
        facade.search(pit={'id':'first'})
        self.assertEqual(facade.pits,{'second'})
        facade.close_owned_pits();client.close_point_in_time.assert_called_once_with(id='second')

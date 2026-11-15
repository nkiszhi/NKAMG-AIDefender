import asyncio
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import main
from app import codefender_client as client, model_runtime as runtime
from app.config import settings
from app.detection_queue import DetectionTaskStore
import test_external_api as external
from test_external_api import model_result
from test_pe_structure import make_pe


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'tasks.sqlite3'
        self.store = DetectionTaskStore(self.path, 60)

    def add(self, key, size=1, sha=None):
        return self.store.create(key, key, '/owned/' + key, 100, sha256=sha,
                                 request_source='api', file_size=size)

    def test_two_small_but_no_third(self):
        for key in 'abc':
            self.add(key)
        self.assertEqual(self.store.claim_next()['task_id'], 'a')
        self.assertEqual(self.store.claim_next()['task_id'], 'b')
        self.assertIsNone(self.store.claim_next())

    def test_boundary_large_is_exclusive_and_fifo_does_not_starve(self):
        self.add('a')
        self.add('large', 100 * 1024**2)
        self.add('small')
        self.store.claim_next()
        self.assertIsNone(self.store.claim_next())
        self.store.set_status('a', 'failed')
        self.assertEqual(self.store.claim_next()['task_id'], 'large')
        self.assertIsNone(self.store.claim_next())
        self.store.set_status('large', 'failed')
        self.assertEqual(self.store.claim_next()['task_id'], 'small')

    def test_same_sha_cannot_race_before_memory_failure_is_recorded(self):
        self.add('a', sha='a'*64)
        self.add('b', sha='a'*64)
        self.store.claim_next()
        self.assertIsNone(self.store.claim_next())

    def test_memory_block_survives_cleanup_restart_and_is_versioned(self):
        self.add('a', sha='a'*64)
        self.store.remember_memory_failure('a', 'v1', 'memory')
        self.store.set_status('a', 'failed')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE detection_tasks SET updated_at='2000-01-01'")
        self.store.cleanup()
        store = DetectionTaskStore(self.path, 60)
        self.assertIsNotNone(store.memory_failure('a'*64, 'v1'))
        self.assertIsNone(store.memory_failure('a'*64, 'v2'))
        self.assertEqual(store.forget_memory_failure('a'*64, 'v1'), 1)

    def test_web_restart_does_not_replay_unconfirmed_running_job(self):
        self.add('a')
        self.add('b')
        self.store.claim_next()
        self.assertEqual(self.store.recover(), 1)
        self.assertEqual(self.store.get('a')['error_code'], 'MODEL_STATUS_UNKNOWN')
        self.assertEqual(self.store.claim_next()['task_id'], 'b')

    def test_waiting_has_deadline(self):
        self.add('a')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE detection_tasks SET created_at='2000-01-01'")
        self.assertEqual(self.store.expire_waiting(1800), ['/owned/a'])
        self.assertEqual(self.store.get('a')['error_code'], 'QUEUE_TIMEOUT')

    def test_old_schema_migrates_without_losing_tasks(self):
        path = Path(self.temp.name) / 'old.sqlite3'
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE detection_tasks (task_id TEXT PRIMARY KEY,status TEXT NOT NULL,filename TEXT NOT NULL,file_path TEXT NOT NULL,result_json TEXT,error TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
            db.execute("INSERT INTO detection_tasks VALUES('old','queued','a','/a',NULL,NULL,'2026-11-15','2026-11-15')")
        self.assertEqual(DetectionTaskStore(path, 3600).get('old')['file_size'], 0)

    def test_unknown_request_cooldown_survives_web_restart(self):
        node = {'id':'id1', 'started_at':'first', 'ready':True}
        pool = client.ModelEndpointPool()
        pool.attach_storage(self.store)
        pool.quarantine('one', node)
        restarted = client.ModelEndpointPool()
        restarted.attach_storage(self.store)
        with patch.object(runtime, 'node_evidence', return_value=node):
            self.assertEqual(restarted.recovering(), ['one'])
        with patch.object(runtime, 'node_evidence', return_value={**node, 'started_at':'new'}):
            self.assertEqual(restarted.recovering(), [])
        self.assertEqual(self.store.load_cooldowns(), [])


class EvidenceTests(unittest.TestCase):
    def test_only_matching_oom_after_request_is_confirmed(self):
        error = runtime.ModelTaskFailure('disconnected', endpoint='one', started_at=100, container_id='abc')
        for kind, identity, stamp, expected in [('oom','abc',101,True), ('die','abc',101,False),
            ('oom','other',101,False), ('oom','abc',99,False)]:
            with self.subTest(kind=kind, identity=identity, stamp=stamp), patch.object(runtime, 'node_evidence',
                return_value={'events':[{'kind':kind,'time':stamp,'container_id':identity}]}):
                self.assertEqual(runtime.confirmed_oom(error), expected)
        self.assertFalse(runtime.confirmed_oom(RuntimeError('HTTP 502')))

    def test_missing_stale_and_low_memory_pause_dispatch(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(settings,'model_monitor_path',Path(folder)/'state.json'):
            path = settings.model_monitor_path
            self.assertFalse(runtime.admission_status()[0])
            for age, available, ready, expected in [(60,10**11,True,False),(0,1,True,False),
                (0,10**11,False,False),(0,10**11,True,True)]:
                path.write_text(json.dumps({'updated_at':time.time()-age,'memory_available_bytes':available,
                    'nodes':{url:{'ready':ready} for url in settings.codefender_api_bases}}))
                self.assertEqual(runtime.admission_status()[0], expected)

    def test_disconnect_is_not_replayed_on_second_endpoint(self):
        pool = client.ModelEndpointPool()
        with patch.object(client, '_endpoint_pool', pool), patch.object(settings,'codefender_api_bases',['one','two']), \
             patch.object(settings,'model_monitor_path',None), patch.object(client,'_scan_by_upload',return_value=None) as scan:
            with self.assertRaises(runtime.ModelTaskFailure):
                client.scan_file(Path('fixture'))
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(pool.recovering(), ['one'])

    def test_monitor_keeps_oom_event_through_new_container_generation(self):
        path = Path(__file__).resolve().parents[2] / 'deploy/model_resource_monitor.py'
        spec = importlib.util.spec_from_file_location('observer',path)
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        line = json.dumps({'Action':'oom','Actor':{'ID':'abc'},'timeNano':101500000000})
        events = observer.merge_events([],line,102)
        self.assertEqual(events[0]['time'],101.5)
        self.assertEqual(observer.merge_events(events,line,103),events)


class FailureIntegrationTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = external.ExternalAPITests.asyncSetUp
    asyncTearDown = external.ExternalAPITests.asyncTearDown
    process_one = external.ExternalAPITests.process_one
    submit_and_process = external.ExternalAPITests.submit_and_process
    async def test_confirmed_oom_returns_nonretryable_and_repeat_sha_is_blocked(self):
        response = await self.submit_and_process(error=runtime.ModelTaskFailure(runtime.MEMORY_MESSAGE, code='MODEL_MEMORY_LIMIT'))
        self.assertEqual(response.status_code,502)
        self.assertEqual(response.json()['error_code'],'MODEL_MEMORY_LIMIT')
        self.assertIs(response.json()['retryable'],False)
        with patch.object(main,'scan_file') as scan:
            repeat = await self.client.post('/api/v1/detect?wait_seconds=0',files={'file':('same.exe',bytes(make_pe()))})
            self.assertEqual(repeat.status_code,502)
            self.assertEqual(repeat.json()['error_code'],'MODEL_MEMORY_LIMIT')
            queried = await self.client.get('/api/v1/detect/tasks/' + repeat.headers['X-Detection-ID'])
            self.assertEqual(queried.json(),repeat.json())
            self.assertEqual(list(self.uploads.iterdir()),[])
            scan.assert_not_called()
        with patch.object(settings,'model_revision', 'changed-version'):
            next_upload = await self.client.post('/api/v1/detect?wait_seconds=0',files={'file':('same.exe',bytes(make_pe()))})
            self.assertEqual(next_upload.status_code,202)

    async def test_queued_duplicate_is_blocked_then_other_sample_continues(self):
        for _ in range(2):
            response = await self.client.post('/api/v1/detect?wait_seconds=0',files={'file':('same.exe',bytes(make_pe()))})
            self.assertEqual(response.status_code,202)
        with patch.object(main,'scan_file', side_effect=runtime.ModelTaskFailure(runtime.MEMORY_MESSAGE,code='MODEL_MEMORY_LIMIT')) as scan:
            await self.process_one()
            await self.process_one()
            scan.assert_called_once()
        different = bytearray(make_pe())
        different[-1] = 33
        third = await self.client.post('/api/v1/detect?wait_seconds=0',files={'file':('different.exe',bytes(different))})
        with patch.object(main,'scan_file',return_value=model_result('Generic.ML.Low')):
            await self.process_one()
        result = await self.client.get('/api/v1/detect/tasks/'+third.json()['task_id'])
        self.assertEqual(result.json(),{'result':'Generic.ML.Low'})

    async def test_unknown_disconnect_is_not_misreported_as_memory_limit(self):
        response = await self.submit_and_process(error=runtime.ModelTaskFailure('连接中断'))
        self.assertEqual(response.json()['error_code'],'MODEL_CONNECTION_LOST')
        self.assertIs(response.json()['retryable'],False)
        self.assertNotIn('内存',response.json()['detail'])

    async def test_observed_oom_classifies_socket_failure(self):
        error = runtime.ModelTaskFailure('socket closed', endpoint='one',started_at=100,container_id='abc')
        with patch.object(settings,'model_monitor_path',Path('configured')), \
             patch.object(runtime,'node_evidence', return_value={'events':[{'kind':'oom','time':101,'container_id':'abc'}]}):
            response = await self.submit_and_process(error=error)
        self.assertEqual(response.json()['error_code'],'MODEL_MEMORY_LIMIT')


class UploadDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_closes_multipart_files_and_returns_one_terminal_response(self):
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse
        from app.http_guard import PublicAPIGuard
        import tempfile
        opened, sent = [], []
        original = tempfile.SpooledTemporaryFile
        def spool(*args, **kwargs):
            handle = original(*args,**kwargs)
            opened.append(handle)
            return handle
        async def upload(request):
            async with request.form():
                return JSONResponse({})
        guard = PublicAPIGuard(Starlette(routes=[Route('/detect',upload,methods=['POST'])]),10**6,upload_timeout=0.03)
        prefix = b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        count = 0
        async def receive():
            nonlocal count
            count += 1
            if count == 1:
                return {'type':'http.request','body':prefix+b'a','more_body':True}
            await asyncio.sleep(10)
        async def send(message):
            sent.append(message)
        scope = {'type':'http','method':'POST','path':'/detect','headers':[(b'content-type',b'multipart/form-data; boundary=boundary')],'client':('test',1)}
        with patch('starlette.formparsers.SpooledTemporaryFile',side_effect=spool):
            await guard(scope,receive,send)
        starts = [m for m in sent if m['type']=='http.response.start']
        self.assertEqual([m['status'] for m in starts],[408])
        self.assertTrue(opened)
        self.assertTrue(all(h.closed for h in opened))


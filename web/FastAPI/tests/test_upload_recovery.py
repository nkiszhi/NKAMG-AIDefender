"""Exercise incomplete uploads without production servers or model execution."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

import main
from app.detection_queue import DetectionTaskStore
from app.http_guard import PublicAPIGuard, BrowserUploadLimit
from test_pe_structure import make_pe


PREFIX = b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="sample.bin"\r\n\r\n'
SUFFIX = b'\r\n--boundary--\r\n'


def scope(task_id='a'*32):
    return {'type':'http', 'http_version':'1.1', 'method':'POST', 'scheme':'http',
            'path':'/api/v1/detect', 'raw_path':b'/api/v1/detect', 'query_string':b'wait_seconds=0',
            'headers':[(b'content-type', b'multipart/form-data; boundary=boundary'),
                       (b'x-detection-id', task_id.encode())],
            'client':('test',123), 'server':('test',80)}


async def collect(app, receive, request_scope=None):
    messages = []
    async def send(message): messages.append(message)
    request_scope = request_scope or scope()
    await app(request_scope, receive, send)
    return messages, request_scope


def response(messages):
    status = [m['status'] for m in messages if m['type']=='http.response.start']
    body = b''.join(m.get('body',b'') for m in messages if m['type']=='http.response.body')
    return status, json.loads(body) if body else None


class UploadRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        root = Path(self.folder.name)
        self.store = DetectionTaskStore(root/'tasks.sqlite3',3600)
        self.uploads = root/'uploads'
        self.patches = [patch.object(main,'task_store',self.store),
                        patch.object(main,'task_wakeup',asyncio.Event()),
                        patch.object(main.settings,'upload_dir',self.uploads),
                        patch.object(main,'_api_uploads_inflight',0)]
        for p in self.patches: p.start()
        app = FastAPI()
        app.add_api_route('/api/v1/detect', main.api_detect, methods=['POST'])
        async def passthrough(request, call_next): return await call_next(request)
        app.add_middleware(BaseHTTPMiddleware, dispatch=passthrough)
        self.guard = PublicAPIGuard(app,10**7,upload_timeout=5,upload_idle_timeout=0.12)

    async def asyncTearDown(self):
        for p in reversed(self.patches): p.stop()
        self.folder.cleanup()

    @staticmethod
    def stalled_receive(entered):
        first = True
        async def receive():
            nonlocal first
            if first:
                first=False
                entered.set()
                return {'type':'http.request','body':PREFIX+b'partial','more_body':True}
            await asyncio.Event().wait()
        return receive

    @staticmethod
    def complete_receive():
        first=True
        async def receive():
            nonlocal first
            if first:
                first=False
                return {'type':'http.request','body':PREFIX+bytes(make_pe())+SUFFIX,'more_body':False}
            await asyncio.Event().wait()
        return receive

    async def test_two_stalled_uploads_release_both_slots_and_third_is_accepted(self):
        entered = [asyncio.Event(),asyncio.Event()]
        opened=[]
        original=tempfile.SpooledTemporaryFile
        def spool(*a,**k):
            handle=original(*a,**k); opened.append(handle); return handle
        with patch('starlette.formparsers.SpooledTemporaryFile',side_effect=spool), \
             patch.object(main,'scan_file') as scan:
            tasks=[asyncio.create_task(collect(self.guard,self.stalled_receive(entered[i]),scope(str(i+1)*32))) for i in range(2)]
            try:
                await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered)),1)
                self.assertEqual(main._api_uploads_inflight,2)
                rejected,_=await collect(self.guard,self.complete_receive(),scope('3'*32))
                self.assertEqual(response(rejected)[0],[429])
                self.assertEqual(dict(rejected[0]['headers'])[b'retry-after'],b'60')
                finished=await asyncio.wait_for(asyncio.gather(*tasks),2)
                for messages, request_scope in finished:
                    statuses,payload=response(messages)
                    self.assertEqual(statuses,[408])
                    self.assertEqual(payload['error_code'],'UPLOAD_TIMEOUT')
                    self.assertEqual(payload['task_id'],dict(request_scope['headers'])[b'x-detection-id'].decode())
                    self.assertEqual(request_scope['state']['upload_receive']['phase'],'idle_timeout')
                self.assertEqual(main._api_uploads_inflight,0)
                self.assertTrue(opened)
                self.assertTrue(all(handle.closed for handle in opened))
                self.assertEqual(self.store.detection_summary()['received_total'],0)
                accepted,_=await collect(self.guard,self.complete_receive(),scope('4'*32))
                self.assertEqual(response(accepted)[0],[202])
                self.assertEqual(main._api_uploads_inflight,0)
                self.assertEqual(self.store.detection_summary()['received_total'],1)
                scan.assert_not_called()
            finally:
                for task in tasks:
                    if not task.done(): task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)

    async def test_disconnect_closes_partial_spool_and_releases_slot(self):
        parts=iter([{'type':'http.request','body':PREFIX+b'partial','more_body':True},
                    {'type':'http.disconnect'}])
        async def receive(): return next(parts)
        opened=[]
        original=tempfile.SpooledTemporaryFile
        def spool(*a,**k):
            handle=original(*a,**k);opened.append(handle);return handle
        with patch('starlette.formparsers.SpooledTemporaryFile',side_effect=spool):
            messages,request_scope=await collect(self.guard,receive)
        self.assertEqual(messages,[])
        self.assertEqual(request_scope['state']['upload_receive']['phase'],'disconnected')
        self.assertEqual(main._api_uploads_inflight,0)
        self.assertTrue(opened and all(handle.closed for handle in opened))
        self.assertEqual(self.store.detection_summary()['received_total'],0)

    async def test_cancellation_releases_slot_without_creating_detection(self):
        entered=asyncio.Event()
        opened=[]
        original=tempfile.SpooledTemporaryFile
        def spool(*a,**k):
            handle=original(*a,**k); opened.append(handle); return handle
        with patch('starlette.formparsers.SpooledTemporaryFile',side_effect=spool):
            task=asyncio.create_task(collect(self.guard,self.stalled_receive(entered)))
            await asyncio.wait_for(entered.wait(),1)
            for _ in range(30):
                if opened: break
                await asyncio.sleep(0)
            self.assertEqual(main._api_uploads_inflight,1)
            task.cancel()
            await asyncio.gather(task,return_exceptions=True)
        self.assertEqual(main._api_uploads_inflight,0)
        self.assertTrue(opened and all(handle.closed for handle in opened))
        self.assertEqual(self.store.detection_summary()['received_total'],0)


class ReceiveTimerTests(unittest.IsolatedAsyncioTestCase):
    async def test_browser_limit_keeps_two_slots_and_releases_on_cancel(self):
        entered=0
        async def app(request_scope,receive,send):
            nonlocal entered
            entered+=1
            await asyncio.Event().wait()
        limiter=BrowserUploadLimit(app)
        request_scope={**scope(),'path':'/detect'}
        async def receive(): await asyncio.Event().wait()
        tasks=[asyncio.create_task(collect(limiter,receive,dict(request_scope))) for _ in range(2)]
        try:
            for _ in range(20):
                if entered==2: break
                await asyncio.sleep(0)
            self.assertEqual(limiter.inflight,2)
            rejected,_=await collect(limiter,receive,dict(request_scope))
            self.assertEqual(response(rejected)[0],[429])
            self.assertEqual(dict(rejected[0]['headers'])[b'retry-after'],b'5')
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        self.assertEqual(limiter.inflight,0)

    @staticmethod
    async def consume(request_scope,receive,send):
        while (await receive()).get('more_body',False): pass
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'{}'})

    async def test_progress_resets_idle_timer_even_when_total_duration_exceeds_idle_limit(self):
        calls=0
        async def receive():
            nonlocal calls
            calls+=1
            await asyncio.sleep(0.025)
            return {'type':'http.request','body':b'bytes','more_body':calls<8}
        guard=PublicAPIGuard(self.consume,1000,upload_timeout=1,upload_idle_timeout=0.1)
        messages,request_scope=await collect(guard,receive)
        self.assertEqual(response(messages)[0],[200])
        self.assertEqual(request_scope['state']['upload_receive']['received_bytes'],40)

    async def test_total_deadline_still_limits_continuously_progressing_upload(self):
        async def receive():
            await asyncio.sleep(0.02)
            return {'type':'http.request','body':b'bytes','more_body':True}
        guard=PublicAPIGuard(self.consume,1000,upload_timeout=0.1,upload_idle_timeout=0.3)
        messages,request_scope=await collect(guard,receive)
        self.assertEqual(response(messages)[0],[408])
        self.assertEqual(request_scope['state']['upload_receive']['phase'],'total_timeout')

    async def test_zero_byte_messages_do_not_extend_idle_deadline(self):
        async def receive():
            await asyncio.sleep(0.01)
            return {'type':'http.request','body':b'','more_body':True}
        guard=PublicAPIGuard(self.consume,1000,upload_timeout=1,upload_idle_timeout=0.06)
        messages,request_scope=await collect(guard,receive)
        self.assertEqual(response(messages)[0],[408])
        self.assertEqual(request_scope['state']['upload_receive']['phase'],'idle_timeout')

    async def test_completed_body_disables_both_upload_timers_during_later_receive(self):
        first=True
        async def receive():
            nonlocal first
            if first:
                first=False
                return {'type':'http.request','body':b'body','more_body':False}
            await asyncio.sleep(0.09)
            return {'type':'http.disconnect'}
        async def app(request_scope,receive,send):
            await receive()
            await receive()
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'{}'})
        guard=PublicAPIGuard(app,1000,upload_timeout=0.04,upload_idle_timeout=0.02)
        messages,request_scope=await collect(guard,receive)
        self.assertEqual(response(messages)[0],[200])
        self.assertEqual(request_scope['state']['upload_receive']['phase'],'body_complete')

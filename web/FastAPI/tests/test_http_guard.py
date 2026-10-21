import asyncio
import unittest

from app.http_guard import PublicAPIGuard


class HTTPGuardTests(unittest.TestCase):
    def request(self, guard, chunks=(), headers=(), path='/detect', peer='client', method='POST'):
        async def run():
            messages = []
            parts = iter(chunks)
            async def receive():
                part = next(parts, None)
                if part is None:
                    return {'type': 'http.request', 'body': b'', 'more_body': False}
                return {'type': 'http.request', 'body': part, 'more_body': True}
            async def send(message):
                messages.append(message)
            scope = {'type': 'http', 'method': method, 'path': path,
                     'headers': headers, 'client': (peer, 123)}
            await guard(scope, receive, send)
            return messages
        return asyncio.run(run())

    @staticmethod
    async def consume(scope, receive, send):
        while True:
            message = await receive()
            if not message.get('more_body'):
                break
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'ok'})

    def test_oversized_content_length_rejected_before_app(self):
        async def forbidden(*args):
            self.fail('Application must not parse oversized request')
        messages = self.request(PublicAPIGuard(forbidden, 10), headers=[(b'content-length', b'11')])
        self.assertEqual(messages[0]['status'], 413)

    def test_chunked_and_underreported_body_cannot_bypass_limit(self):
        for headers in ([], [(b'content-length', b'1')]):
            messages = self.request(PublicAPIGuard(self.consume, 10), [b'a'*6, b'b'*6], headers)
            self.assertEqual(messages[0]['status'], 413)
            self.assertEqual(len([m for m in messages if m['type']=='http.response.start']), 1)

    def test_upload_rate_is_per_peer_and_does_not_block_polling(self):
        guard = PublicAPIGuard(self.consume, 10)
        for _ in range(60):
            self.assertEqual(self.request(guard)[0]['status'], 200)
        self.assertEqual(self.request(guard)[0]['status'], 429)
        self.assertEqual(self.request(guard, peer='other')[0]['status'], 200)
        self.assertEqual(self.request(guard, method='GET', path='/detect/tasks/a')[0]['status'], 200)

    def test_invalid_length_and_bounded_client_memory(self):
        guard = PublicAPIGuard(self.consume, 10, max_clients=2)
        self.assertEqual(self.request(guard, headers=[(b'content-length', b'-1')])[0]['status'], 400)
        self.assertEqual(self.request(guard, peer='other')[0]['status'], 429)
        self.assertEqual(len(guard.clients), 2)

    def test_browsers_on_shared_ip_have_separate_upload_quotas(self):
        guard = PublicAPIGuard(self.consume, 10)
        # Isolate the browser buckets here; production still has a shared IP
        # ceiling so rotating IDs cannot evade the public abuse limit.
        guard.IP_LIMITS = {**guard.IP_LIMITS, 'upload': 120}
        first = [(b'x-client-id', b'a' * 32)]
        second = [(b'x-client-id', b'b' * 32)]
        for _ in range(60):
            self.assertEqual(self.request(guard, headers=first)[0]['status'], 200)
        for _ in range(60):
            self.assertEqual(self.request(guard, headers=second)[0]['status'], 200)
        self.assertEqual(self.request(guard, headers=first)[0]['status'], 429)
        self.assertEqual(self.request(guard, headers=second)[0]['status'], 429)
        self.assertEqual(self.request(guard, headers=first, method='GET',
                                      path='/detect/tasks/a')[0]['status'], 200)

    def test_rotating_browser_ids_cannot_bypass_shared_ip_limit(self):
        guard = PublicAPIGuard(self.consume, 10)
        for index in range(60):
            headers = [(b'x-client-id', format(index, '032x').encode())]
            self.assertEqual(self.request(guard, headers=headers)[0]['status'], 200)
        headers = [(b'x-client-id', b'f' * 32)]
        self.assertEqual(self.request(guard, headers=headers)[0]['status'], 429)
        self.assertEqual(self.request(guard, headers=headers, peer='other')[0]['status'], 200)

    def test_invalid_browser_ids_and_raw_forwarded_header(self):
        guard = PublicAPIGuard(self.consume, 10)
        for value in (b'', b'bad', b'A' * 32, b'a' * 33):
            self.assertEqual(self.request(guard, headers=[(b'x-client-id', value)])[0]['status'], 400)
        for index in range(60):
            headers = [(b'x-forwarded-for', str(index).encode())]
            self.assertEqual(self.request(guard, headers=headers)[0]['status'], 200)
        self.assertEqual(self.request(guard, headers=[(b'x-forwarded-for', b'new')])[0]['status'], 429)

    def test_expired_rate_entries_release_capacity(self):
        from unittest.mock import patch
        guard = PublicAPIGuard(self.consume, 10, max_clients=2)
        with patch('app.http_guard.time.monotonic', return_value=100):
            self.assertEqual(self.request(guard)[0]['status'], 200)
            self.assertEqual(self.request(guard, peer='other')[0]['status'], 429)
        with patch('app.http_guard.time.monotonic', return_value=161):
            self.assertEqual(self.request(guard, peer='other')[0]['status'], 200)
        self.assertEqual(len(guard.clients), 2)

    def test_reports_are_not_cached_and_sniffing_disabled(self):
        messages = self.request(PublicAPIGuard(self.consume, 10))
        headers = dict(messages[0]['headers'])
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(headers[b'x-content-type-options'], b'nosniff')

    def test_multipart_overflow_closes_spooled_files(self):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from unittest.mock import patch
        import tempfile
        opened = []
        original = tempfile.SpooledTemporaryFile
        def spool(*args, **kwargs):
            handle = original(*args, **kwargs)
            opened.append(handle)
            return handle
        async def upload(request: Request):
            async with request.form() as form:
                return JSONResponse({'size': len(await form['file'].read())})
        app = Starlette(routes=[Route('/detect', upload, methods=['POST'])])
        guard = PublicAPIGuard(app, 180)
        prefix = b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        with patch('starlette.formparsers.SpooledTemporaryFile', side_effect=spool):
            messages = self.request(guard, [prefix + b'a'*10, b'b'*200],
                [(b'content-type', b'multipart/form-data; boundary=boundary')])
        self.assertEqual(messages[0]['status'], 413)
        self.assertTrue(opened)
        self.assertTrue(all(handle.closed for handle in opened))

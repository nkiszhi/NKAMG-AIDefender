"""Bound anonymous API traffic and request bodies before multipart parsing."""
import asyncio
import logging
import re
import time
from collections import OrderedDict, deque

from starlette.responses import JSONResponse
from starlette.formparsers import MultiPartException

logger = logging.getLogger('aidefender.upload')


class BodyLimitExceeded(MultiPartException):
    pass


class UploadDeadlineExceeded(MultiPartException):
    pass


class UploadDisconnected(MultiPartException):
    """Use the multipart cleanup path when an incomplete request disconnects."""
    pass


class BrowserUploadLimit:
    """Keep the existing two browser upload slots without BaseHTTPMiddleware."""
    def __init__(self, app):
        self.app = app
        self.inflight = 0

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST' or scope.get('path') != '/detect':
            return await self.app(scope, receive, send)
        if self.inflight >= 2:
            return await JSONResponse({'detail': '检测服务繁忙，请稍后重试'}, status_code=429,
                                      headers={'Retry-After': '5'})(scope, receive, send)
        self.inflight += 1
        try:
            return await self.app(scope, receive, send)
        finally:
            self.inflight -= 1


class PublicAPIGuard:
    # Browser IDs provide anonymous fairness, not authentication. Rotating IDs
    # still consumes the shared IP budget. Both kinds share bounded storage.
    # Upload requests are capped at the shared IP budget: hits also need a full
    # body transfer and database lookup, but should not have a stricter quota.
    CLIENT_LIMITS = {'upload': 60, 'lookup': 60, 'read': 240}
    IP_LIMITS = {'upload': 60, 'lookup': 300, 'read': 2400}

    def __init__(self, app, max_body_bytes, max_clients=4096, upload_timeout=900,
                 upload_idle_timeout=60):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_clients = max_clients
        self.clients = OrderedDict()
        self.upload_timeout = upload_timeout
        self.upload_idle_timeout = upload_idle_timeout

    def allow(self, key, group, limit, now):
        while self.clients and next(iter(self.clients.values()))['seen'] <= now - 60:
            self.clients.popitem(last=False)
        if key not in self.clients:
            if len(self.clients) >= self.max_clients:
                return False
            self.clients[key] = {'seen': now, 'buckets': {}}
        state = self.clients[key]
        state['seen'] = now
        self.clients.move_to_end(key)
        bucket = state['buckets'].setdefault(group, deque())
        while bucket and bucket[0] <= now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        path = scope.get('path', '').rstrip('/')
        api_upload = scope['method'] == 'POST' and path == '/api/v1/detect'
        upload = scope['method'] == 'POST' and (path == '/detect' or api_upload)
        lookup = path.startswith('/samples/') or path == '/sample-search'
        group = 'upload' if upload else 'lookup' if lookup else 'read'
        peer = (scope.get('client') or ('unknown', 0))[0]
        now = time.monotonic()
        headers = dict(scope.get('headers', []))
        client_id = headers.get(b'x-client-id')
        if client_id is not None and not re.fullmatch(rb'[0-9a-f]{32}', client_id):
            return await self.reject(scope, receive, send, 400, '浏览器标识格式无效，请刷新页面')
        if not self.allow(('ip', peer), group, self.IP_LIMITS[group], now):
            return await self.reject(scope, receive, send, 429, '请求过于频繁，请稍后重试')
        # Legacy clients without a browser ID retain a conservative per-IP quota.
        key = ('browser', peer, client_id) if client_id else ('anonymous', peer)
        if not self.allow(key, group, self.CLIENT_LIMITS[group], now):
            return await self.reject(scope, receive, send, 429, '请求过于频繁，请稍后重试')
        # The dedicated single-file API has no application-level byte ceiling.
        # Browser uploads retain their existing limit and both share rate limits.
        cap = None if api_upload else self.max_body_bytes if upload else 65536
        try:
            length = int(headers.get(b'content-length', b'0'))
            if length < 0:
                raise ValueError()
        except ValueError:
            return await self.reject(scope, receive, send, 400, '请求长度无效')
        if cap is not None and length > cap:
            return await self.reject(scope, receive, send, 413, '请求体超过大小限制')
        count, exceeded, timed_out = 0, False, False
        disconnected = body_complete = response_started = False
        started = last_progress = time.monotonic()
        deadline = started + self.upload_timeout
        identifier = headers.get(b'x-detection-id', b'').decode('ascii', errors='ignore')
        identifier = identifier if re.fullmatch(r'[0-9a-f]{32}', identifier) else '-'
        progress = {'received_bytes': 0, 'expected_bytes': length, 'phase': 'receiving'}
        if upload:
            scope.setdefault('state', {})['upload_receive'] = progress

        async def bounded_receive():
            nonlocal count, exceeded, timed_out, disconnected, body_complete, last_progress
            try:
                if upload and not body_complete:
                    receive_deadline = min(deadline, last_progress + self.upload_idle_timeout)
                    message = await asyncio.wait_for(receive(), max(0, receive_deadline-time.monotonic()))
                else:
                    # BaseHTTPMiddleware also receives disconnects after the body.
                    # Upload deadlines must not cancel later queueing or inference.
                    message = await receive()
            except asyncio.TimeoutError:
                timed_out = True
                progress['phase'] = ('total_timeout' if deadline <= last_progress + self.upload_idle_timeout
                                     else 'idle_timeout')
                # Starlette closes all multipart temporary files on this type.
                raise UploadDeadlineExceeded('Upload deadline exceeded')
            if upload and not body_complete and message['type'] == 'http.disconnect':
                disconnected = True
                progress['phase'] = 'disconnected'
                raise UploadDisconnected('Client disconnected before upload completed')
            if message['type'] == 'http.request':
                size = len(message.get('body', b''))
                count += size
                progress['received_bytes'] = count
                if size:
                    last_progress = time.monotonic()
                if cap is not None and count > cap:
                    exceeded = True
                    progress['phase'] = 'body_limit'
                    raise BodyLimitExceeded('Request body too large')
                if upload and not message.get('more_body', False):
                    body_complete = True
                    progress['phase'] = 'body_complete'
            return message

        async def protected_send(message):
            nonlocal response_started
            if not exceeded and not timed_out and not disconnected:
                if message['type'] == 'http.response.start':
                    response_started = True
                    message = dict(message)
                    message['headers'] = list(message.get('headers', [])) + [
                        (b'x-content-type-options', b'nosniff'),
                        (b'referrer-policy', b'no-referrer'),
                        (b'cache-control', b'no-store'),
                    ]
                await send(message)

        try:
            await self.app(scope, bounded_receive, protected_send)
        except Exception:
            if not exceeded and not timed_out and not disconnected:
                raise
        finally:
            if upload:
                logger.info('上传接收结束 task_id=%s phase=%s received_bytes=%s expected_bytes=%s elapsed_seconds=%.3f',
                            identifier, progress['phase'], count, length, time.monotonic()-started)
        if timed_out and not response_started:
            detail = ('上传连续无数据超时，未进入模型队列，请检查网络连接。'
                      if progress['phase'] == 'idle_timeout' else '上传超时，未进入模型队列，请检查网络连接。')
            await JSONResponse({'result': 'Failed', 'detail': detail, 'task_id': identifier if identifier != '-' else '',
                                'error_code': 'UPLOAD_TIMEOUT', 'retryable': True}, status_code=408,
                               headers={'X-Detection-ID': identifier if identifier != '-' else ''})(scope, receive, send)
        if exceeded and not response_started:
            await self.reject(scope, receive, send, 413, '请求体超过大小限制')

    @staticmethod
    async def reject(scope, receive, send, status, detail):
        headers = {'Retry-After': '60'} if status == 429 else {}
        await JSONResponse({'detail': detail}, status_code=status, headers=headers)(scope, receive, send)

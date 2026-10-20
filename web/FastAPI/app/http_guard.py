"""Bound anonymous API traffic and request bodies before multipart parsing."""
import time
from collections import OrderedDict, deque

from starlette.responses import JSONResponse
from starlette.formparsers import MultiPartException


class BodyLimitExceeded(MultiPartException):
    pass


class PublicAPIGuard:
    def __init__(self, app, max_body_bytes, max_clients=4096):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_clients = max_clients
        self.clients = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        path = scope.get('path', '')
        upload = scope['method'] == 'POST' and path == '/detect'
        lookup = path.startswith('/samples/')
        group = 'upload' if upload else 'lookup' if lookup else 'read'
        limit = 6 if upload else 60 if lookup else 240
        peer = (scope.get('client') or ('unknown', 0))[0]
        now = time.monotonic()
        while self.clients and next(iter(self.clients.values()))['seen'] <= now - 60:
            self.clients.popitem(last=False)
        if peer not in self.clients:
            if len(self.clients) >= self.max_clients:
                return await self.reject(scope, receive, send, 429, '请求过于频繁，请稍后重试')
            self.clients[peer] = {'seen': now, 'buckets': {}}
        state = self.clients[peer]
        state['seen'] = now
        self.clients.move_to_end(peer)
        bucket = state['buckets'].setdefault(group, deque())
        while bucket and bucket[0] <= now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return await self.reject(scope, receive, send, 429, '请求过于频繁，请稍后重试')
        bucket.append(now)
        headers = dict(scope.get('headers', []))
        cap = self.max_body_bytes if upload else 65536
        try:
            length = int(headers.get(b'content-length', b'0'))
            if length < 0:
                raise ValueError()
        except ValueError:
            return await self.reject(scope, receive, send, 400, '请求长度无效')
        if length > cap:
            return await self.reject(scope, receive, send, 413, '请求体超过大小限制')
        count, exceeded = 0, False

        async def bounded_receive():
            nonlocal count, exceeded
            message = await receive()
            if message['type'] == 'http.request':
                count += len(message.get('body', b''))
                if count > cap:
                    exceeded = True
                    raise BodyLimitExceeded('Request body too large')
            return message

        async def protected_send(message):
            if not exceeded:
                if message['type'] == 'http.response.start':
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
            if not exceeded:
                raise
        if exceeded:
            await self.reject(scope, receive, send, 413, '请求体超过大小限制')

    @staticmethod
    async def reject(scope, receive, send, status, detail):
        headers = {'Retry-After': '60'} if status == 429 else {}
        await JSONResponse({'detail': detail}, status_code=status, headers=headers)(scope, receive, send)

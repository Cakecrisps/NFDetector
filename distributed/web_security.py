"""Response hardening and a small request budget for browser administration."""
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse


class WebSecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message['type'] == 'http.response.start':
                headers = MutableHeaders(scope=message)
                headers['Cache-Control'] = 'no-store'
                headers['X-Content-Type-Options'] = 'nosniff'
                headers['X-Frame-Options'] = 'DENY'
                headers['Referrer-Policy'] = 'no-referrer'
                headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
                headers['Strict-Transport-Security'] = 'max-age=31536000'
                headers['Content-Security-Policy'] = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; "
                    "frame-ancestors 'none'; form-action 'self'; object-src 'none'")
            await send(message)

        if scope['path'].startswith('/admin/api/') and scope['method'] not in ('GET', 'HEAD', 'OPTIONS'):
            headers = dict(scope['headers'])
            if headers.get(b'content-type', b'').split(b';')[0] != b'application/json':
                return await JSONResponse({'detail': 'Use application/json'}, status_code=415)(scope, receive, secure_send)
            body = bytearray()
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                body.extend(message.get('body', b''))
                if len(body) > 8192:
                    return await JSONResponse({'detail': 'Request too large'}, status_code=413)(scope, receive, secure_send)
                if not message.get('more_body'):
                    break
            received = False

            async def replay():
                nonlocal received
                if not received:
                    received = True
                    return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                return await receive()
            return await self.app(scope, replay, secure_send)
        return await self.app(scope, receive, secure_send)

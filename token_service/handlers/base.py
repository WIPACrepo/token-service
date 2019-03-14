import logging

import tornado.web
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat
from rest_tools.client import json_encode, json_decode
from rest_tools.server import Auth

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, address, auth, identity_expiration):
        self.address = address
        self.auth = auth
        self.identity_expiration = identity_expiration

    def set_default_headers(self):
        self._headers['Server'] = 'IceCube Token Service'

    def get_current_url(self):
        return self.address + self.request.uri


class AuthzBaseHandler(BaseHandler):
    def initialize(self, authz, **kwargs):
        super(AuthzBaseHandler, self).initialize(**kwargs)
        self.authz = authz

    def create_token(self, secret):
        a = Auth(secret, issuer='authz')
        data = {k:self.identity[k] for k in ('sub','groups','institutions') if k in self.identity}
        return a.create_token('authz', payload=data)

    async def req(self, method, url, token=None, args=None):
        kwargs = {
            'method': method,
            'headers': {'Content-Type': 'application/json'},
        }
        if token:
            kwargs['headers']['Authorization'] = f'Bearer {token}'
        if args:
            if method in ('GET', 'HEAD'):
                url = url_concat(args)
            else:
                kwargs['body'] = json_encode(args)
        http = AsyncHTTPClient()
        ret = await http.fetch(url, **kwargs)
        try:
            return json_decode(ret.body)
        except Exception:
            logging.info('body: %s', ret.body)
            raise
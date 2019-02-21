import tornado.web

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, session, auth, identity_expiration):
        self.session = session
        self.auth = auth
        self.identity_expiration = identity_expiration

    def set_default_headers(self):
        self._headers['Server'] = 'IceCube Token Service'

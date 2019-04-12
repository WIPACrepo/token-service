"""
Website core.

Start up the server.
"""
import os
import asyncio

from rest_tools.client import AsyncSession
from rest_tools.server import Auth, RestServer
import tornado.web

from .handlers import (LoginHandler, TokenHandler, ServiceTokenHandler,
                       RefreshHandler, AuthzRegistrationHandler,
                       RevocationViewHandler, RevocationListHandler)
from .authz_server import AuthzServer
from .revocation_server import RevocationListServer

def get_template_path():
    return os.path.join(os.path.dirname(__file__),'templates')

def get_static_path():
    return os.path.join(os.path.dirname(__file__),'static')

class WebServer:
    def __init__(self, config):
        self.config = config

        # set up Auth
        alg = 'RS512' if config['auth_pub_secret'] else 'HS512'
        auth = Auth(
            secret=config['auth_secret'],
            pub_secret=config['auth_pub_secret'],
            issuer=config["address"],
            algorithm=alg,
            expiration=config['refresh_token_expiration'],
            expiration_temp=config['access_token_expiration'],
        )
        service_auth = Auth(
            secret=config['auth_secret'],
            pub_secret=config['auth_pub_secret'],
            issuer=config["address"],
            algorithm=alg,
            expiration=config['service_token_expiration'],
            expiration_temp=config['access_token_expiration'],
        )

        # set up authz
        authz = AuthzServer(
            mongodb_uri=config['mongodb_uri'],
            admin_authz_secret=config['admin_authz_secret'],
            admin_authz_url=config['admin_authz_url'],
        )

        # set up revocation list
        revocation_list = RevocationListServer(
            mongodb_uri=config['mongodb_uri'],
        )

        self.server = RestServer(
            static_path=get_static_path(),
            template_path=get_template_path(),
            cookie_secret=config['cookie_secret'],
            debug=config['debug'],
            template_whitespace='all' if config['debug'] else 'oneline',
            autoescape=None,
            login_url=f'{config["address"]}/login',
        )
        handler_settings = {
            'address': config['address'],
            'auth': auth,
            'identity_expiration': config['identity_expiration'],
            'authz': authz,
            'revocation_list': revocation_list,
        }
        login_handler_settings = handler_settings.copy()
        del login_handler_settings['authz']
        del login_handler_settings['revocation_list']
        login_handler_settings.update({
            'oauth_authorize_uri': config['oauth_authorize_uri'],
            'oauth_token_uri': config['oauth_token_uri'],
            'oauth_userinfo_uri': config['oauth_userinfo_uri'],
            'oauth_client_id': config['oauth_client_id'],
            'oauth_client_secret': config['oauth_client_secret'],
        })
        service_handler_settings = handler_settings.copy()
        service_handler_settings['auth'] = service_auth

        self.server.add_route(r'/login', LoginHandler, login_handler_settings)
        self.server.add_route(r'/token', TokenHandler, handler_settings, 'token')
        self.server.add_route(r'/service_token', ServiceTokenHandler, service_handler_settings)
        self.server.add_route(r'/refresh', RefreshHandler, handler_settings)
        self.server.add_route(r'/manage_authz', AuthzRegistrationHandler, handler_settings)
        self.server.add_route(r'/revocation', RevocationViewHandler, handler_settings)
        self.server.add_route(r'/revocation_api', RevocationListHandler, handler_settings)

    def start(self):
        self.server.startup(port=self.config['port'], address='0.0.0.0')
        loop = asyncio.get_event_loop()
        loop.run_forever()

class TestWebServer(WebServer):
    def __init__(self, config):
        super(TestWebServer, self).__init__(config)
        for route in self.server.routes:
            route[2]['testing'] = True
        class TestHandler(tornado.web.RequestHandler):
            def get(self):
                self.write('OK')
        self.server.add_route(r'/', TestHandler, {})

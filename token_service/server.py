"""
Website core.

Start up the server.
"""
import os
import asyncio

from rest_tools.client import AsyncSession
from rest_tools.server import Auth, RestServer

from .handlers import LoginHandler, TokenHandler, ServiceTokenHandler, RefreshHandler

def get_template_path():
    return os.path.join(os.path.dirname(__file__),'templates')

def get_static_path():
    return os.path.join(os.path.dirname(__file__),'static')

class WebServer:
    def __init__(self, config):
        self.config = config

        # set up Auth
        auth = Auth(
            secret=config['auth_secret'],
            issuer='https://tokens.icecube.wisc.edu',
            expiration=config['refresh_token_expiration'],
            expiration_temp=config['access_token_expiration'],
        )
        service_auth = Auth(
            secret=config['auth_secret'],
            issuer='https://tokens.icecube.wisc.edu',
            expiration=config['service_token_expiration'],
            expiration_temp=config['access_token_expiration'],
        )
        
        self.server = RestServer(
            static_path=os.path.join(os.getcwd(), 'static'),
            template_path=os.path.join(os.getcwd(), 'templates'),
            cookie_secret=config['cookie_secret'],
            debug=config['debug'],
            template_whitespace='all' if config['debug'] else 'oneline',
            autoescape=None,
            login_url='http://localhost:{}/login'.format(config['port']),
        )
        handler_settings = {
            'session': AsyncSession(),
            'auth': auth,
            'identity_expiration': config['identity_expiration'],
        }
        login_handler_settings = handler_settings.copy()
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
        self.server.add_route(r'/token', TokenHandler, handler_settings)
        self.server.add_route(r'/service_token', ServiceTokenHandler, service_handler_settings)
        self.server.add_route(r'/refresh', RefreshHandler, handler_settings)

    def start(self):
        self.server.startup(port=self.config['port'], address='0.0.0.0')
        loop = asyncio.get_event_loop()
        loop.run_forever()

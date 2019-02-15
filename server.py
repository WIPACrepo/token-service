"""
A `Tornado <http://tornado.readthedocs.io>`_ server
to generate access and refresh tokens, and maintain a revocation list.
"""

import os
import sys
import random
import logging
import asyncio
import hmac
import urllib.parse
from collections import OrderedDict

from tornado.httpclient import HTTPError

import requests
import tornado.web
import tornado.auth
from tornado.httpclient import HTTPClient
from tornado.escape import utf8

from rest_tools.client import AsyncSession, json_decode
from rest_tools.server import RestServer, catch_error

def gen_secret(length):
    """
    Make a secret string

    Args:
        length (int): length of secret
    Returns:
        str: secret
    """
    return ''.join(hex(random.randint(0,15))[-1] for _ in range(length))


EXPECTED_CONFIG = {
    'cookie_secret': gen_secret(64),
    'debug': False,
    'oauth_uri': None,
    'oauth_client_id': None,
    'oauth_client_secret': None,
    'port': 8888,
}


def get_config():
    """
    Get config from environment

    Returns:
        dict: config
    """
    ret = {}
    for k in EXPECTED_CONFIG:
        ret[k] = os.environ.get(k, EXPECTED_CONFIG[k])
        if ret[k] is None:
            print(k, 'is required')
            sys.exit(1)
        if isinstance(EXPECTED_CONFIG[k], bool):
            if ret[k] is True:
                ret[k] = True
            elif isinstance(ret[k], str) and ret[k].lower() in ('true','t','1','yes','y'):
                ret[k] = True
            else:
                ret[k] = False
        elif isinstance(EXPECTED_CONFIG[k], int):
            ret[k] = int(ret[k])
        elif isinstance(EXPECTED_CONFIG[k], float):
            ret[k] = float(ret[k])
    return ret

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, session):
        self.session = session

    def set_default_headers(self):
        self._headers['Server'] = 'IceCube Token Service'

    def get_current_user(self):
        # ~ try:
            # ~ type,token = self.request.headers['Authorization'].split(' ', 1)
            # ~ if type.lower() != 'bearer':
                # ~ raise Exception('bad header type')
            # ~ logging.debug('token: %r', token)
            # ~ data = self.auth.validate(token)
            # ~ self.auth_data = data
            # ~ self.auth_key = token
            # ~ return data['sub']
        # ~ except Exception:
            # ~ if self.settings['debug'] and 'Authorization' in self.request.headers:
                # ~ logging.info('Authorization: %r', self.request.headers['Authorization'])
            # ~ logging.info('failed auth', exc_info=True)
        return None

    async def req(self, method, url, args=None):
        kwargs = {}
        if method in ('GET', 'HEAD'):
            kwargs['params'] = args
        else:
            kwargs['json'] = args
        r = await asyncio.wrap_future(self.session.request(method, url, **kwargs))
        r.raise_for_status()
        return json_decode(r.content)

class LoginHandler(BaseHandler, tornado.auth.OAuth2Mixin):
    def initialize(self, oauth_authorize_uri, oauth_token_uri, oauth_userinfo_uri,
                   oauth_client_id, oauth_client_secret, **kwargs):
        super(LoginHandler, self).initialize(**kwargs)
        self._OAUTH_AUTHORIZE_URL = oauth_authorize_uri
        self._OAUTH_ACCESS_TOKEN_URL = oauth_token_uri
        self._OAUTH_USERINFO_TOKEN_URL = oauth_userinfo_uri
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret

    async def get_authenticated_user(self, redirect_uri, code):
        http = self.get_auth_http_client()
        body = urllib.parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.oauth_client_id,
#            "client_secret": self.oauth_client_secret,
            "grant_type": "authorization_code",
        })

        ret = await http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                               method="POST",
                               auth_username=self.oauth_client_id,
                               auth_password=self.oauth_client_secret,
                               headers={'Content-Type': 'application/x-www-form-urlencoded'},
                               body=body)
        # ~ url = self._oauth_request_token_url(
                # ~ redirect_uri=redirect_uri,
                # ~ client_id=self.oauth_client_id,
                # ~ client_secret=self.oauth_client_secret,
                # ~ code=code,
                # ~ extra_params={'grant_type': 'authorization_code'}
        # ~ )
        # ~ ret = await http.fetch(url, method="POST",
                               # ~ auth_username=self.oauth_client_id,
                               # ~ auth_password=self.oauth_client_secret)
        user = json_decode(ret.body)

        # get json identity token
        ret = await http.fetch(self._OAUTH_USERINFO_TOKEN_URL,
                               headers={'Authorization': f'Bearer {user["access_token"]}'})
        user['jwt'] = json_decode(ret.body)
        return user

    def compare_state(self, state):
        _, token, _ = self._decode_xsrf_token(state)
        _, expected_token, _ = self._get_raw_xsrf_token()
        if not token:
            raise HTTPError(403, "'state' argument has invalid format")
        if not hmac.compare_digest(utf8(token), utf8(expected_token)):
            raise HTTPError(403, "XSRF cookie does not match state argument")

    async def get(self):
        if self.get_argument('code', False):
            self.compare_state(self.get_argument('state'))
            user = await self.get_authenticated_user(
                redirect_uri=self.get_login_url(),
                code=self.get_argument('code'))
            # Save the user with e.g. set_secure_cookie
            self.set_secure_cookie('access_token', user['access_token'],
                                   expires_days=1.0*user['expires_in']/3600/24)
            self.set_secure_cookie('refresh_token', user['refresh_token'],
                                   expires_days=1)
            
            self.write(user)
            #self.redirect('/')
        else:
            await self.authorize_redirect(
                redirect_uri=self.get_login_url(),
                client_id=self.oauth_client_id,
                scope=['offline','name','groups','institutions'],
                extra_params={"state": self.xsrf_token.decode('utf-8')},
                response_type='code')


class MainHandler(BaseHandler):
    @catch_error
    async def get(self):
        self.write(self.get_login_url()+'|'+self.xsrf_token.decode('utf-8'))
        self.write('<br>')
        refresh_token = self.get_secure_cookie('refresh_token')
        self.write(f'{refresh_token}')

def main():
    config = get_config()
    logging.basicConfig(level=logging.DEBUG if config['debug'] else logging.INFO)

    # do self-discovery for oauth uris
    try:
        http = HTTPClient()
        ret = http.fetch(config['oauth_uri']+'/.well-known/openid-configuration')
        ret = json_decode(ret.body)
        config['oauth_authorize_uri'] = ret['authorization_endpoint']
        config['oauth_token_uri'] = ret['token_endpoint']
        config['oauth_userinfo_uri'] = ret['userinfo_endpoint']
    except Exception:
        logging.error("failed to do OAuth self-discovery")
        raise

    server = RestServer(
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
    }
    login_handler_settings = handler_settings.copy()
    login_handler_settings.update({
        'oauth_authorize_uri': config['oauth_authorize_uri'],
        'oauth_token_uri': config['oauth_token_uri'],
        'oauth_userinfo_uri': config['oauth_userinfo_uri'],
        'oauth_client_id': config['oauth_client_id'],
        'oauth_client_secret': config['oauth_client_secret'],
    })

    server.add_route(r'/login', LoginHandler, login_handler_settings)
    server.add_route(r'/', MainHandler, handler_settings)

    server.startup(port=config['port'], address='0.0.0.0')
    loop = asyncio.get_event_loop()
    loop.run_forever()

if __name__ == '__main__':
    main()

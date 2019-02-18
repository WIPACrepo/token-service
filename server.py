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
import base64
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timedelta

import requests
import tornado.web
import tornado.auth
from tornado.httpclient import HTTPClient, HTTPError
from tornado.escape import utf8
from tornado.httputil import url_concat

from rest_tools.client import AsyncSession, json_encode, json_decode
from rest_tools.server import Auth, RestServer, authenticated, catch_error

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
    'auth_secret': gen_secret(64),
    'debug': False,
    'oauth_uri': None,
    'oauth_client_id': None,
    'oauth_client_secret': None,
    'access_token_expiration': 3600, # 1 hour
    'refresh_token_expiration': 86400, # 1 day
    'identity_expiration': 86400*90, # 90 days
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

def get_exp_date(seconds):
    """
    Get an ISO-8601 timestamp for expiration date.

    Args:
        seconds (float): number of seconds from now to expire
    Returns:
        str: timestamp in UTC
    """
    return (datetime.utcnow()+timedelta(seconds=seconds)).isoformat()

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, session, auth, identity_expiration):
        self.session = session
        self.auth = auth
        self.identity_expiration = identity_expiration

    def set_default_headers(self):
        self._headers['Server'] = 'IceCube Token Service'

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
        user = json_decode(ret.body)

        # get json identity token
        ret = await http.fetch(self._OAUTH_USERINFO_TOKEN_URL,
                               headers={'Authorization': f'Bearer {user["access_token"]}'})
        user['jwt'] = json_decode(ret.body)
        user['jwt']['expiration'] = get_exp_date(self.identity_expiration)
        return user

    def decode_state(self, state):
        data = json_decode(base64.b64decode(state))
        _, token, _ = self._decode_xsrf_token(data['xsrf'])
        _, expected_token, _ = self._get_raw_xsrf_token()
        if not token:
            raise HTTPError(403, "'state' argument has invalid format")
        if not hmac.compare_digest(utf8(token), utf8(expected_token)):
            raise HTTPError(403, "XSRF cookie does not match state argument")
        return data

    def encode_state(self, data):
        return base64.b64encode(json_encode(data).encode('utf-8'))

    @catch_error
    async def get(self):
        if self.get_argument('code', False):
            data = self.decode_state(self.get_argument('state'))
            user = await self.get_authenticated_user(
                redirect_uri=self.get_login_url(),
                code=self.get_argument('code'))
            # Save the user with e.g. set_secure_cookie
            self.set_secure_cookie('access_token', user['access_token'],
                                   expires_days=1.0*user['expires_in']/3600/24)
            self.set_secure_cookie('refresh_token', user['refresh_token'],
                                   expires_days=1)
            self.set_secure_cookie('identity', json_encode(user['jwt']),
                                   expires_days=1)
            if data['redirect']:
                url = data['redirect']
                if 'state' in data:
                    url = url_concact(url, {'state': data['state']})
                self.redirect(url)
            elif self.settings['debug']:
                self.write(user)
            else:
                raise HTTPError(400, 'missing redirect')
        else:
            state = {'xsrf': self.xsrf_token.decode('utf-8')}
            if self.get_argument('redirect', False):
                state['redirect'] = self.get_argument('redirect')
            elif not self.settings['debug']:
                raise HTTPError(400, 'missing redirect')
            if self.get_argument('state', False):
                state['state'] = self.get_argument('state')
            await self.authorize_redirect(
                redirect_uri=self.get_login_url(),
                client_id=self.oauth_client_id,
                scope=['offline','name','groups','institutions'],
                extra_params={"state": self.encode_state(state)},
                response_type='code')

class HumanHandler(BaseHandler):
    def get_current_user(self):
        try:
            self.identity = json_decode(self.get_secure_cookie('identity'))
            return self.identity['sub']
        except Exception:
            logging.info('failed auth', exc_info=True)
        return None

class TokenHandler(HumanHandler):
    """
    Handler for user-interacting token request.

    Checks with the IDP as necessary, and validates access to scopes.

    Parameters:
        scope: space separated scopes
        redirect: (optional) where to redirect the request back to
        state: (optional) any state to pass through to the redirect
    """
    @catch_error
    async def get(self):
        if not self.current_user:
            url = url_concat(self.get_login_url(), {'redirect': self.request.full_url()})
            if self.get_argument('state', False):
                url = url_concact(url, {'state': self.get_argument('state')})
            self.redirect(url)
            return

        # scope checks
        scopes = []
        if self.get_argument('scopes', False):
            scopes = self.get_argument('scopes').split()
        data = {
            'aud': 'ANY',
            'ver': 'scitoken:2.0',
            'name': self.identity['name'],
            'refresh_lifetime': self.identity['expiration'],
        }
        # TODO: should check authz here
        data['scopes'] = ' '.join(scopes)

        # authz all done, make a token
        token = self.auth.create_token(self.identity['sub'], type='refresh', payload=data)

        if self.get_argument('redirect', False):
            url = self.get_argument('redirect')
            if self.get_argument('state', False):
                url = url_concact(url, {'state': self.get_argument('state')})
            self.redirect(url)
        else:
            self.write(token)

class BotHandler(BaseHandler):
    def get_current_user(self):
        try:
            type,token = self.request.headers['Authorization'].split(' ', 1)
            if type.lower() != 'bearer':
                raise Exception('bad header type')
            logging.debug('token: %r', token)
            host_uri = self.request.protocol + "://" + self.request.host
            data = self.auth.validate(token, audience=['ANY',host_uri])
            self.auth_data = data
            self.auth_key = token
            return data['sub']
        except Exception:
            if self.settings['debug'] and 'Authorization' in self.request.headers:
                logging.info('Authorization: %r', self.request.headers['Authorization'])
            logging.info('failed auth', exc_info=True)
        return None

class RefreshHandler(BotHandler):
    """
    Handler for refresh token request.

    Checks with the IDP as necessary, and validates access to scopes.

    Parameters:
        scope: space separated scopes
        redirect: (optional) where to redirect the request back to
        state: (optional) any state to pass through to the redirect
    """
    @authenticated
    @catch_error
    async def get(self):
        data = {}
        for key in ('aud', 'ver', 'name', 'refresh_lifetime', 'scopes'):
            data[key] = self.auth_data[key]
        token = self.auth.create_token(self.auth_data['sub'], type='refresh', payload=data)
        self.write(token)


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

    # set up Auth
    auth = Auth(
        secret=config['auth_secret'],
        issuer='https://tokens.icecube.wisc.edu',
        expiration=config['refresh_token_expiration'],
        expiration_temp=config['access_token_expiration'],
    )

    # set up server
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

    server.add_route(r'/login', LoginHandler, login_handler_settings)
    server.add_route(r'/token', TokenHandler, handler_settings)
    server.add_route(r'/refresh', RefreshHandler, handler_settings)

    server.startup(port=config['port'], address='0.0.0.0')
    loop = asyncio.get_event_loop()
    loop.run_forever()

if __name__ == '__main__':
    main()

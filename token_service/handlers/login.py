import time
import hmac
import base64
import urllib.parse
import logging

import tornado.auth
from tornado.httpclient import HTTPError
from tornado.escape import utf8
from rest_tools.client import json_encode, json_decode
from rest_tools.server import catch_error

from .base import BaseHandler


def get_exp_date(seconds):
    """
    Get a timestamp for expiration.

    Use unix time in seconds.

    Args:
        seconds (float): number of seconds from now to expire
    Returns:
        int: timestamp in unix time
    """
    return time.time()+seconds


class LoginHandler(BaseHandler, tornado.auth.OAuth2Mixin):
    """Handle login with OAuth2 / OpenID Connect endpoint"""
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
        if self.testing:
            logging.info('testing mode')
            user = {
                'sub': 'testing',
                'name': 'test testing',
                'groups': 'testing',
                'expiration': get_exp_date(10000),
            }
            self.set_secure_cookie('identity', json_encode(user),
                                   expires_days=1)
            if self.get_argument('redirect', False):
                url = self.get_argument('redirect')
                if self.get_argument('state', False):
                    url = url_concat(url, {'state': self.get_argument('state')})
                self.redirect(url)
                return
            else:
                raise HTTPError(400, 'missing redirect')

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

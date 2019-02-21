"""
A `Tornado <http://tornado.readthedocs.io>`_ server
to generate access and refresh tokens, and maintain a revocation list.
"""

import os
import time
import logging
import asyncio

from tornado.httpclient import HTTPError
from tornado.httputil import url_concat
from rest_tools.client import AsyncSession, json_encode, json_decode
from rest_tools.server import Auth, RestServer, authenticated, catch_error

from .base import BaseHandler


class TokenBaseHandler(BaseHandler):
    async def req(self, method, url, args=None):
        kwargs = {}
        if method in ('GET', 'HEAD'):
            kwargs['params'] = args
        else:
            kwargs['json'] = args
        r = await asyncio.wrap_future(self.session.request(method, url, **kwargs))
        r.raise_for_status()
        return json_decode(r.content)

class HumanHandler(TokenBaseHandler):
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

        # authz all done, make tokens
        access = self.auth.create_token(self.identity['sub'], type='temp',
                                        payload=data)
        refresh = self.auth.create_token(self.identity['sub'], type='refresh',
                                         payload=data)

        if self.get_argument('redirect', False):
            url = self.get_argument('redirect')
            args = {'access': access, 'refresh': refresh}
            if self.get_argument('state', False):
                args['state'] = self.get_argument('state')
            self.redirect(url_concact(url, args))
        else:
            self.write({'access':access,'refresh':refresh})

class ServiceTokenHandler(HumanHandler):
    """
    Handler for user-interacting service token request.

    These act like refresh tokens, but for services.

    Checks with the IDP as necessary, and validates access to scopes.

    Parameters:
        scope: space separated scopes
        expiration: requested expiration length in seconds (must be less than max expiration)
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
        }
        # TODO: should check authz here
        data['scopes'] = ' '.join(scopes)

        # authz all done, make a token
        exp = None
        if self.get_argument('expiration', False):
            exp = int(self.get_argument('expiration'))
        token = self.auth.create_token(self.identity['sub'], type='service',
                                       expiration=exp, payload=data)

        self.write(token)


class BotHandler(TokenBaseHandler):
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
        if self.auth_data['type'] != 'refresh':
            raise HTTPError(400, 'bad token type')

        data = {}
        for key in ('aud', 'ver', 'name', 'refresh_lifetime', 'scopes'):
            data[key] = self.auth_data[key]

        access = self.auth.create_token(self.auth_data['sub'], type='temp',
                                        payload=data)
        refresh = self.auth.create_token(self.auth_data['sub'], type='refresh',
                                         payload=data)
        self.write({'access':access,'refresh':refresh})


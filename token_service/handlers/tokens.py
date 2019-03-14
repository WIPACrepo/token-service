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

from .base import AuthzBaseHandler
from .mixins import HumanHandlerMixin, BotHandlerMixin


class TokenHandler(HumanHandlerMixin, AuthzBaseHandler):
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
            url = url_concat(self.get_login_url(), {'redirect': self.get_current_url()})
            if self.get_argument('state', False):
                url = url_concact(url, {'state': self.get_argument('state')})
            self.redirect(url)
            return

        # scope checks
        scopes = []
        if self.get_argument('scope', False):
            scopes = self.get_argument('scope').split()
        data = {
            'aud': 'ANY',
            'ver': 'scitoken:2.0',
            'name': self.identity['name'],
            'refresh_lifetime': self.identity['expiration'],
        }
        scope_ret = []
        for s in scopes:
            logging.info('checking scope %s', s)
            try:
                ret = await self.authz.get_by_scope(s)
                try:
                    token = self.create_token(ret['secret'])
                    ret = await self.req('GET', ret['url'], token=token)
                except Exception:
                    logging.info('denied scope %s', s, exc_info=True)
                else:
                    if ret:
                        if 'scope' in ret:
                            scope_ret.append(ret.pop('scope'))
                        else:
                            scope_ret.append(s)
                        for k in ret:
                            if k in data:
                                raise KeyError(f'{k} already in data')
                            data[k] = ret[k]
                    else:
                        scope_ret.append(s)
            except Exception:
                logging.warning('error checking scope %s', s, exc_info=True)
                raise HTTPError(400, 'bad scope')
        data['scope'] = ' '.join(scope_ret)

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


class ServiceTokenHandler(HumanHandlerMixin, AuthzBaseHandler):
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
            url = url_concat(self.get_login_url(), {'redirect': self.get_current_url()})
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
        scope_ret = []
        for s in scopes:
            logging.info('checking scope %s', s)
            ret = await self.authz.get_by_scope(s)
            try:
                token = self.create_token(ret['secret'])
                ret = await self.req('GET', ret['url'], token=token)
            except Exception:
                logging.info('denied scope %s', s, exc_info=True)
            else:
                if ret:
                    scope_ret.append(ret)
                else:
                    scope_ret.append(s)
        data['scopes'] = ' '.join(scope_ret)

        # authz all done, make a token
        exp = None
        if self.get_argument('expiration', False):
            exp = int(self.get_argument('expiration'))
        token = self.auth.create_token(self.identity['sub'], type='service',
                                       expiration=exp, payload=data)

        self.write(token)


class RefreshHandler(BotHandlerMixin, AuthzBaseHandler):
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


"""
Authz registration/removal handler.
"""

import os
import time
import logging
import asyncio

from tornado.httpclient import AsyncHTTPClient, HTTPError
from tornado.httputil import url_concat
from rest_tools.client import AsyncSession, json_encode, json_decode
from rest_tools.server import Auth, RestServer, authenticated, catch_error

from .base import AuthzBaseHandler
from .mixins import HumanHandlerMixin, BotHandlerMixin


class AuthzRegistrationHandler(HumanHandlerMixin, AuthzBaseHandler):
    """
    Handler for user-interacting authz registrations.

    Checks with the IDP as necessary, and validates access to scopes.
    """
    @catch_error
    async def get(self):
        await self.post()

    @catch_error
    async def post(self):
        # login
        if not self.current_user:
            url = url_concat(self.get_login_url(), {'redirect': self.get_current_url()})
            logging.info('redirecting to %s', url)
            self.redirect(url)
            return

        # check admin authz
        ret = await self.authz.get_by_scope('token_service_admin')
        try:
            token = self.create_token(ret['secret'])
            await self.req('GET', ret['url'], token=token)
        except Exception:
            logging.info('not authorized', exc_info=True)
            self.set_status(401)
            self.render('authz_error.html')
            return

        err = ''
        try:
            name = self.get_arguments('name')
            logging.info('name: %r', name)
            if name:
                delete = self.get_argument('delete', False)
                if delete:
                    logging.info('deleting %r', name)
                    for n in name:
                        await self.authz.delete(n)
                else:
                    scopes = [x.strip() for x in self.get_argument('scopes').split(',')]
                    secret = self.get_argument('secret')
                    url = self.get_argument('url')
                    data = {'name': name[0], 'scopes': scopes, 'secret': secret, 'url': url}
                    logging.info('adding %r', data)
                    await self.authz.set(name[0], data)
        except Exception as e:
            err = str(e)

        ret = await self.authz.list()
        self.render('authz.html', endpoints=ret, error_message=err)

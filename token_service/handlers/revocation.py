"""
Revocation handler.
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


class RevocationBaseHandler(AuthzBaseHandler):
    def initialize(self, revocation_list, **kwargs):
        super(RevocationBaseHandler, self).initialize(**kwargs)
        self.revocation_list = revocation_list


class RevocationViewHandler(HumanHandlerMixin, RevocationBaseHandler):
    """
    Handler for user-interacting revocations.
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
            sub = self.current_user
        else:
            # we are admin, show all users
            sub = None

        err = ''
        try:
            token_hashes = self.get_arguments('hash')
            logging.info('hash: %r', token_hashes)
            if token_hashes:
                logging.info('revoking %r', token_hashes)
                for h in token_hashes:
                    await self.revocation_list.revoke(h)
        except Exception as e:
            err = str(e)

        revoked = await self.revocation_list.list(revoked=True, sub=sub)
        alive = await self.revocation_list.list(revoked=False, sub=sub)
        self.render('revocation.html', revoked=revoked, tokens=alive, error_message=err)


class RevocationListHandler(RevocationBaseHandler):
    """
    Handler for retrieving the revocation list as json.

    Returns as {"result": [token_hash, token_hash, ... ]}
    """
    @catch_error
    async def get(self):
        ret = await self.revocation_list.list(revoked=True)
        result = [t['hash'] for t in ret]
        self.write({'result': result})

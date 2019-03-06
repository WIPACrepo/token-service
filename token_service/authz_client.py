"""
Authz client common code.
"""
import asyncio
import inspect

from tornado.web import HTTPError
from rest_tools.server import (Auth, RestHandler, RestServer, authenticated,
                               catch_error)


class AuthzHandler(RestHandler):
    def initialize(self, func, **kwargs):
        super(AuthzHandler, self).initialize(**kwargs)
        self.func = func

    @authenticated
    @catch_error
    async def get(self):
        try:
            if inspect.iscoroutinefunction(self.func):
                ret = await self.func(self.auth_data)
            else:
                ret = self.func(self.auth_data)
        except Exception:
            raise HTTPError(401, 'denied')
        if not ret:
            ret = {}
        self.write(ret)


def run(client_secret, handler_func, address=None, port=None, **kwargs):
    """
    Run an Authz client.

    Starts a web server that responds to authz requests from the
    token service.  This function blocks.

    Notes on handler_func:
        This callable should expect a dict argument with additional data.
        Any information returned is embedded in the valid token.
        It should raise an error to deny the authz request.

    Args:
        client_secret (str): a secret string used to validate/sign requests
        handler_func (callable): a function to handle the authz request
        address (str): bind address
        port (int): bind port
    """
    auth = Auth(client_secret, issuer='authz')

    server = RestServer(**kwargs)
    server.add_route('/', AuthzHandler, {'auth': auth, 'func': handler_func})

    startup_args = {}
    if address:
        startup_args['address'] = address
    if port:
        startup_args['port'] = port
    server.startup(**startup_args)
    loop = asyncio.get_event_loop()
    loop.run_forever()
    server.stop()

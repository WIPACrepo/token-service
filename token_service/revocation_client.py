"""
Token service revocation client.

To be used by end services, to verify a token and check it
is not on the revocation list.

The `Validator` class can be used as a library::

    from token_service.revocation_client import Validator
    v = Validator('secret')
    data = v.valid('my.token.here')

This can also be called directly from the command line via::

    python -m token_service.revocation_client --secret secret my.token.here
"""

import time

import requests
from rest_tools.server import Auth


class Validator:
    """
    Validate a token

    Args:
        secret (str): auth secret
        issuer (str): auth issuer
        audience (str): token audience
        update_interval (int): seconds between revocation updates
    """
    def __init__(self, secret, issuer='https://tokens.icecube.wisc.edu',
                 audience='ANY', update_interval=3600):
        self._auth = Auth(secret, issuer=issuer)
        self._audience = audience
        self._revocation_update_interval = update_interval
        self._revocations = set()
        self._revocation_list_time = -1

    def _update_revocation_list(self):
        """Update the cached revocation list"""
        r = requests.get('https://tokens.icecube.wisc.edu/revocation_api')
        r.raise_for_status()
        ret = r.json()
        if 'result' in ret and ret['result']:
            self._revocations = set(ret['result'])
        self._revocation_list_time = time.time()

    def valid(self, token):
        """
        Validate a token.

        Returns:
            dict: token contents
        """
        ret = self._auth.validate(token, audience=self._audience)

        if self._revocation_list_time + self._revocation_update_interval < time.time():
            self._update_revocation_list()
        token_hash = token.rsplit('.',1)[-1]
        if token_hash in self._revocations:
            raise Exception('token revoked!')

        return ret


def main():
    """cmdline usage"""
    import argparse
    parser = argparse.ArgumentParser(description='Token validator')
    parser.add_argument('--secret', help='auth secret')
    parser.add_argument('--issuer', help='auth issuer')
    parser.add_argument('--audience', help='token audience')
    parser.add_argument('--update_interval', type=int, help='seconds between revocation updates')
    parser.add_argument('token', help='token to validate')
    args = vars(parser.parse_args())
    if not args['secret']:
        raise Exception('must specify secret')
    kwargs = {'secret': args['secret']}
    for k in ('issuer', 'audience', 'update_interval'):
        if k in args and args[k]:
            kwargs[k] = args[k]
    v = Validator(**kwargs)
    ret = v.valid(args['token'])
    print(ret)

if __name__ == '__main__':
    main()

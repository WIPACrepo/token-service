"""
Start the token service admin authz.

This authz is bundled with the token service (for obvious reasons),
but runs in a separate process.
"""
import os
import sys
import logging

from token_service.authz_client import run

def validate(data):
    """Validate that a person is a token administrator"""
    logging.debug('%r',data)
    assert 'admin' in data['groups']

def main():
    secret = os.environ.get('secret', False)
    if not secret:
        print('"secret" environment variable is required')
        sys.exit(1)
    port = os.environ.get('port', None)
    debug = True if os.environ.get('debug', False) else False

    logfmt = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, format=logfmt)

    kwargs = {'debug': debug}
    if port:
        kwargs['port'] = int(port)
    run(secret, validate, **kwargs)

if __name__ == '__main__':
    main()
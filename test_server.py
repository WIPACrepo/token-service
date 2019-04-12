"""
A `Tornado <http://tornado.readthedocs.io>`_ server
to generate access and refresh tokens, and maintain a revocation list.

This is a test server that always grants tokens to everyone,
no login or checking required.
"""

import os
import sys
import random
import logging

from tornado.httpclient import HTTPClient, HTTPError

from rest_tools.client import json_decode

from token_service.server import TestWebServer

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
    'auth_pub_secret': '',
    'mongodb_uri': 'mongodb://localhost:27017/',
    'oauth_uri': '',
    'oauth_client_id': '',
    'oauth_client_secret': '',
    'access_token_expiration': 3600, # 1 hour
    'refresh_token_expiration': 86400, # 1 day
    'service_token_expiration': 86400*365, # 1 year
    'identity_expiration': 86400*90, # 90 days
    'admin_authz_secret': gen_secret(64),
    'admin_authz_url': '',
    'address': '', # leave empty for localhost
    'port': 8888,
    'debug': False,
    'loglevel': 'info',
    'force_fail': False, # force a bad response
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


def main():
    config = get_config()

    # set up logging
    levels = ['error','warning','info','debug']
    if config['loglevel'].lower() not in levels:
        raise Exception('invalid loglevel')
    config['loglevel'] = getattr(logging, config['loglevel'].upper())

    logfmt = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(level=config['loglevel'], format=logfmt)

    logging.critical('*** this is a test server ***')

    # don't do self-discovery for oauth uris
    config['oauth_authorize_uri'] = ''
    config['oauth_token_uri'] = ''
    config['oauth_userinfo_uri'] = ''

    # set up server
    if not config['address']:
        config['address'] = f'http://localhost:{config["port"]}'
    server = TestWebServer(config)
    server.start()

if __name__ == '__main__':
    main()

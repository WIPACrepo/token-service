"""
A `Tornado <http://tornado.readthedocs.io>`_ server
to generate access and refresh tokens, and maintain a revocation list.
"""

import os
import sys
import random
import logging

from tornado.httpclient import HTTPClient, HTTPError

from rest_tools.client import json_decode

from token_service.server import WebServer

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
    'oauth_uri': None,
    'oauth_client_id': None,
    'oauth_client_secret': None,
    'access_token_expiration': 3600, # 1 hour
    'refresh_token_expiration': 86400, # 1 day
    'service_token_expiration': 86400*365, # 1 year
    'identity_expiration': 86400*90, # 90 days
    'port': 8888,
    'debug': False,
    'loglevel': 'info',
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

    logger = logging.getLogger('setup')
    logfmt = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'
    logging.basicConfig(level=config['loglevel'], format=logfmt)

    # do self-discovery for oauth uris
    try:
        http = HTTPClient()
        ret = http.fetch(config['oauth_uri']+'/.well-known/openid-configuration')
        ret = json_decode(ret.body)
        config['oauth_authorize_uri'] = ret['authorization_endpoint']
        config['oauth_token_uri'] = ret['token_endpoint']
        config['oauth_userinfo_uri'] = ret['userinfo_endpoint']
    except Exception:
        logger.error("failed to do OAuth self-discovery")
        raise

    # set up server
    server = WebServer(config)
    server.start()

if __name__ == '__main__':
    main()

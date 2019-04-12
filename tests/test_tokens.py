import os
import time
import subprocess
import logging

import pytest
import requests

from test_server import gen_secret

@pytest.fixture
def server():
    secret = gen_secret(64)
    env = os.environ.copy()
    env['port'] = '34685'
    env['auth_secret'] = secret
    proc = subprocess.Popen(['python','test_server.py'], env=env)
    logging.info(f'server is starting at port {env["port"]}')
    try:
        for _ in range(100):
            time.sleep(0.01)
            try:
                r = requests.get('http://localhost:34685/')
                r.raise_for_status()
                break
            except Exception:
                pass
        else:
            logging.info('server did not start')
            raise Exception('server did not start')
        logging.info(f'server is up at port {env["port"]}')
        yield {'secret': secret, 'port': env['port']}
    finally:
        proc.kill()
        logging.info('server is stopped')
    

def test_tokens(server):
    r = requests.get(f'http://localhost:{server["port"]}/token', params={'scope': 'foo'})
    r.raise_for_status()
    data = r.json()
    assert 'access' in data
    assert 'refresh' in data
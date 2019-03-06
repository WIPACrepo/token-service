import logging

from rest_tools.client import json_decode

class HumanHandlerMixin:
    def get_current_user(self):
        try:
            self.identity = json_decode(self.get_secure_cookie('identity'))
            return self.identity['sub']
        except Exception:
            logging.info('failed auth', exc_info=True)
        return None

class BotHandlerMixin:
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
"""
Authz server code.
"""
import logging

from motor.motor_tornado import MotorClient, MotorDatabase  # type: ignore
import pymongo  # type: ignore
from pymongo import MongoClient

logger = logging.getLogger('authz')

class AuthzServer:
    """
    Authz server.

    Store the list of authz endpoints in MongoDB.

    Args:
        mongodb_uri (str): uri for mongodb
    """
    def __init__(self, mongodb_uri, admin_authz_secret, admin_authz_url):
        # set up indexes
        db = MongoClient(mongodb_uri).token_service
        if 'authz_name_index' not in db.authz.index_information():
            logger.info(f"Creating index for authz.name")
            db.authz.create_index('name', name='authz_name_index', unique=True)
        if 'authz_scopes_index' not in db.authz.index_information():
            logger.info(f"Creating index for authz.scopes")
            db.authz.create_index('scopes', name='authz_scopes_index', unique=True)

        # bootstrap admin authz
        db.authz.replace_one({'name': 'token_service_admin'}, {
            'name': 'token_service_admin',
            'scopes': ['token_service_admin'],
            'secret': admin_authz_secret,
            'url': admin_authz_url,
        }, upsert=True)

        # allow only async access to the db
        self.db = MotorClient(mongodb_uri).token_service

    async def list(self):
        """
        List all authz endpoints.

        Returns:
            list: list of dict objects
        """
        return await self.db.authz.find({'name':{'$ne':'token_service_admin'}}).limit(100000).to_list(100000)

    async def get(self, name):
        """
        Get an authz endpoint by name.

        Args:
            name (str): authz endpoint name
        Returns:
            dict: authz endpoint information
        """
        ret = await self.db.authz.find_one({'name': name})
        if not ret:
            raise KeyError(f'{name} not found')
        return ret

    async def get_by_scope(self, scope):
        """
        Get an authz endpoint by scope.

        Args:
            scope (str): scope to search by
        Returns:
            dict: authz endpoint information
        """
        ret = await self.db.authz.find_one({'scopes': scope})
        if not ret:
            raise KeyError(f'{scope} not found')
        return ret

    async def set(self, name, value):
        """
        Set an authz endpoint by name.

        Args:
            name (str): authz endpoint name
            value (dict): authz endpoint info
        Returns:
            dict: authz endpoint information
        """
        assert 'name' in value and value['name'] == name
        assert 'secret' in value
        assert 'scopes' in value and isinstance(value['scopes'], list)
        assert 'url' in value
        ret = await self.db.authz.replace_one({'name': name}, value, upsert=True)
        if ret.matched_count != 1 and ret.modified_count != 1 and not ret.upserted_id:
            raise Exception(f'{name} not modified')

    async def delete(self, name):
        """
        Delete an authz endpoint by name.

        Args:
            name (str): authz endpoint name
        """
        ret = await self.db.authz.delete_one({'name': name})
        if ret.deleted_count != 1:
            raise KeyError(f'{name} not found')

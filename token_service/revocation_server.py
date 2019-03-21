"""
Revocation list server code.
"""
import logging
import asyncio
import time

from motor.motor_tornado import MotorClient, MotorDatabase  # type: ignore
import pymongo  # type: ignore
from pymongo import MongoClient

logger = logging.getLogger('revocation')

class RevocationListServer:
    """
    Revocation list server.

    Store the list of active and revoked tokens in MongoDB.

    Args:
        mongodb_uri (str): uri for mongodb
    """
    def __init__(self, mongodb_uri):
        # set up indexes
        db = MongoClient(mongodb_uri).token_service
        if 'hash_index' not in db.tokens.index_information():
            logger.info(f"Creating index for tokens.hash")
            db.tokens.create_index('hash', name='hash_index', unique=True)
        if 'revoked_sub_index' not in db.tokens.index_information():
            logger.info(f"Creating index for tokens.revoked,tokens.sub")
            db.tokens.create_index([('revoked', pymongo.ASCENDING),
                                    ('sub', pymongo.ASCENDING)],
                                   name='revoked_sub_index', unique=False)
        if 'exp_index' not in db.tokens.index_information():
            logger.info(f"Creating index for tokens.exp")
            db.tokens.create_index('exp', name='exp_index', unique=False)

        # allow only async access to the db
        self.db = MotorClient(mongodb_uri).token_service

        # start background cleaning task
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(self._clean(), loop=loop)

    async def _clean(self):
        """
        Clean expired tasks from db.
        """
        while True:
            await self.db.tokens.delete_many({'exp':{'$lt':time.time()}})
            await asyncio.sleep(60)

    async def list(self, revoked=None, sub=None, exp=None, type=None):
        """
        List all tokens.

        Args:
            revoked: True/False/None for revoked, not-revoked, and all tokens
            sub (str): subject of user
            exp (int): max expiration
            type (str): token type
        Returns:
            list: list of dict objects
        """
        filt = {}
        if revoked is not None:
            filt['revoked'] = revoked
        if sub:
            filt['sub'] = sub
        if exp:
            filt['exp'] = {'$lte': exp}
        if type:
            filt['type'] = type
        return await self.db.tokens.find(filt).limit(100000).to_list(100000)

    async def get(self, token_hash):
        """
        Get a token by hash.

        Args:
            token_hash (str): hash of token
        Returns:
            dict: token information
        """
        ret = await self.db.tokens.find_one({'hash': token_hash})
        if not ret:
            raise KeyError(f'{token_hash} not found')
        return ret

    async def add(self, token_hash, sub, scopes, exp, type):
        """
        Add a token by hash.

        Args:
            token_hash (str): hash of token
            sub (str): subject of user
            exp (int): expiration (unix time)
            scopes (list): list of scopes
            type (str): token type
        """
        assert isinstance(scopes, list)
        value = {
            'hash': token_hash,
            'revoked': False,
            'sub': sub,
            'scopes': scopes,
            'exp': exp,
            'type': type,
        }
        ret = await self.db.tokens.insert_one(value)
        if not ret.inserted_id:
            raise Exception(f'{token_hash} not added')

    async def revoke(self, token_hash):
        """
        Revoke a token by hash.

        Args:
            token_hash (str): hash of token
        """
        await self.db.tokens.update_one({'hash': token_hash}, {'$set': {'revoked': True}})

    async def delete(self, token_hash):
        """
        Delete a token by hash.

        Args:
            token_hash (str): hash of token
        """
        ret = await self.db.tokens.delete_one({'hash': token_hash})
        if ret.deleted_count != 1:
            raise KeyError(f'{token_hash} not found')

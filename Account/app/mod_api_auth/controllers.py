# -*- coding: utf-8 -*-

"""
Minimum viable account - API Auth module

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 26.5.2016
"""
import base64
from functools import wraps
from uuid import uuid4

from flask import request

from app import ApiError
from app.mod_api_auth.services import get_sqlite_connection, get_sqlite_cursor, store_api_key_to_db, get_api_key, \
    get_account_id
from app.mod_blackbox.helpers import append_description_to_exception, get_custom_logger

logger = get_custom_logger('mod_api_auth_controllers')


def store_api_key(account_id=None, account_api_key=None):
    """
    Stores API key

    :param account_id: User account ID
    :param account_api_key: API Key
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if account_api_key is None:
        raise AttributeError("Provide account_api_key as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor = store_api_key_to_db(account_id=account_id, account_api_key=account_api_key, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not store API Key to database')
        logger.error('Could not store API Key to database: ' + repr(exp))
        connection.rollback()
        raise
    else:
        connection.commit()
        connection.close()
        logger.debug('API Key and account_id stored')


def gen_account_api_key(account_id=None):
    """
    Generate API Key for account ID

    :param account_id:
    :return: API Key
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    account_api_key = "account-api-key-" + str(uuid4())
    account_api_key = base64.b64encode(account_api_key)
    logger.debug('Generated account_api_key: ' + str(account_api_key))

    try:
        store_api_key(account_id=account_id, account_api_key=account_api_key)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Failed to store generated Api key. Key must be regenerated.')
        logger.error('Failed to store generated api key: ' + repr(exp))
        raise
    else:
        logger.info('For account with id: ' + str(account_id) + ' has been generated Api Key: ' + str(account_api_key))
        return account_api_key


def get_account_api_key(account_id=None):
    """
    Get API Key by account ID

    :param account_id:
    :return: API Key
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor, api_key = get_api_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not API key from database')
        logger.error('Could not get API key from database: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.close()
        logger.debug('API key fetched')
        return api_key


def get_account_id_by_api_key(api_key=None):
    """
    Get User account ID by Api Key

    :param api_key:
    :return: User account ID
    """
    if api_key is None:
        raise AttributeError("Provide api_key as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor, account_id = get_account_id(api_key=api_key, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not Account ID from database')
        logger.error('Could not get Account ID from database: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.close()
        logger.debug('Account ID fetched')
        return account_id


def check_api_auth_user(api_key):
    try:
        logger.debug("Fetching Account ID")
        account_id = get_account_id_by_api_key(api_key=api_key)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Fetching Account ID failed')
        logger.error('Fetching Account ID failed: ' + repr(exp))
        return False
    else:
        logger.debug("Found account_id: " + str(account_id) + " with api_key: " + str(api_key))
        return True


def get_api_key_sdk():
    """
    Get API Key for internal use

    :return: API Key
    """

    api_key = "682adc10-10e3-478f-8c53-5176d109d7ec"
    return api_key

def check_api_auth_sdk(api_key):
    if api_key == get_api_key_sdk():
        logger.info("Correct ApiKey")
        return True
    else:
        logger.error("Incorrect ApiKey")
        return False


def provideApiKey(endpoint="provideApiKey()"):
    """Sends a 401 response"""
    try:
        endpoint = str(endpoint)
    except Exception as exp:
        logger.debug("Could not convert endpoint to str. Using default value.")
    error_detail = {'0': 'ApiKey MUST be provided for authentication.'}
    raise ApiError(code=401, title="No ApiKey in Request Headers", detail=error_detail, source=endpoint)


def wrongApiKey():
    """Sends a 401 response"""
    error_detail = {'0': 'Correct ApiKey MUST be provided for authentication.'}
    raise ApiError(code=401, title="Invalid ApiKey", detail=error_detail, source="wrongApiKey()")


def requires_api_auth_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None
        try:
            api_key = request.headers.get('Api-Key')
            if api_key is None:
                raise AttributeError('No API Key in Request Headers')
        except Exception as exp:
            logger.debug("No ApiKey in headers: " + repr(exp))
            return provideApiKey()
        else:
            if not check_api_auth_user(api_key=api_key):
                logger.debug("Wrong API Key")
                return wrongApiKey()
            return f(*args, **kwargs)
    return decorated


def requires_api_auth_sdk(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None
        try:
            api_key = request.headers.get('Api-Key')
            if api_key is None:
                raise AttributeError('No API Key in Request Headers')
        except Exception as exp:
            logger.debug("No ApiKey in headers: " + repr(exp))
            return provideApiKey()
        else:
            if not check_api_auth_sdk(api_key=api_key):
                logger.debug("Wrong API Key")
                return wrongApiKey()
            return f(*args, **kwargs)
    return decorated
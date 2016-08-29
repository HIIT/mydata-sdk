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
import json
import os

import sqlite3

from app.mod_api_auth.helpers import get_custom_logger, append_description_to_exception, ApiKeyNotFoundError, \
    AccountIdNotFoundError

logger = get_custom_logger('mod_api_auth_services')

DELIMITTER = '/'
DATABASE = os.path.dirname(os.path.abspath(__file__)) + DELIMITTER + 'apiauth.sqlite'


def log_dict_as_json(data=None, pretty=0, lineno=None):
    """
    Writes dictionary to log entry as JSON

    :param data: Dictionary to log
    :param pretty: 0 or 1 defining if JSON should be pretty printed to log, Defaults to 0
    """
    if data is None:
        raise AttributeError("Provide data as parameter")
    if lineno is not None:
        data['lineno'] = str(lineno)

    if pretty == 0:
        try:
            logger.debug(json.dumps(data).replace('u\'', '\''))
        except Exception:
            logger.debug("Could not log json presentation of data")
    elif pretty == 1:
        try:
            logger.debug(json.dumps(data, indent=4, sort_keys=True).replace('u\'', '\''))
        except Exception:
            logger.debug("Could not log pretty json presentation of data")
    else:
        raise AttributeError("Illegal value for pretty")


def init_sqlite_db(connection=None):
    """
    Initializes SQLite database.

    :param connection: Database connection object
    :return: Database connection object
    """
    if connection is None:
        raise AttributeError("Provide connection as parameter")

    sql_query = '''CREATE TABLE api_keys (
              id            INTEGER   PRIMARY KEY AUTOINCREMENT,
              account_id    INTEGER  UNIQUE NOT NULL,
              api_key       BLOB  NOT NULL
          );'''

    try:
        logger.debug('Initializing database')
        connection.execute(sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not initialize database')
        logger.error('connection.execute(sql): ' + repr(exp))
        connection.rollback()
        raise
    else:
        connection.commit()
        logger.debug('Database initialized')
        return connection


def get_sqlite_connection():
    """
    Get connection for SQLite Database

    :return: Database connection object
    """

    if(os.path.exists(DATABASE) and os.path.isfile(DATABASE)):
        logger.debug("init_db = False")
        init_db = False
    else:
        logger.debug("init_db = True")
        init_db = True

    try:
        connection = sqlite3.connect(DATABASE)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description="Could not get database connection. Could not open db file.")
        logger.error('sqlite3.connect(' + DATABASE + '): ' + repr(exp))
        raise
    else:
        if init_db:
            try:
                connection = init_sqlite_db(connection=connection)
            except Exception:
                raise

        logger.debug('DB connection at ' + repr(connection))
        return connection


def get_sqlite_cursor(connection=None):
    """
    Get cursor for SQLite database connection.

    :param connection: Database connection object
    :return: Database cursor object and Database connection object
    """
    if connection is None:
        raise AttributeError("Provide connection as parameter")

    try:
        cursor = connection.cursor()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get database cursor')
        logger.error('connection.cursor(): ' + repr(exp))
        raise
    else:
        logger.debug('DB cursor at ' + repr(cursor))
        return cursor, connection


def execute_sql_insert(cursor, sql_query):
    """
    Executes SQL INSERT queries.

    :param cursor: Database cursor
    :param sql_query: SQl query to execute
    :return: Database cursor and last inserted row id
    """

    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if sql_query is None:
        raise AttributeError("Provide sql_query as parameter")

    last_id = ""

    try:
        cursor.execute(sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Error in SQL INSERT query execution')
        logger.error('Error in SQL query execution: ' + repr(exp))
        raise
    else:
        logger.debug('SQL query executed')

    try:
        last_id = str(cursor.lastrowid)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='lastrowid not found')
        logger.error('cursor.lastrowid not found: ' + repr(exp))
        logger.info('cursor.lastrowid not found. Using None instead')
        last_id = None
    else:
        logger.debug('cursor.lastrowid: ' + last_id)

    return cursor, last_id


def execute_sql_select(cursor=None, sql_query=None):
    """
    Executes SQL SELECT queries.

    :param cursor: Database cursor
    :param sql_query: SQl query to execute
    :return: Database cursor and result of database query
    """

    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if sql_query is None:
        raise AttributeError("Provide sql_query as parameter")

    try:
        cursor.execute(sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Error in SQL SELECT query execution')
        logger.error('Error in SQL query execution: ' + repr(exp))
        raise
    else:
        logger.debug('SQL query executed')

    try:
        data = cursor.fetchall()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='cursor.fetchall() failed')
        logger.error('cursor.fetchall() failed: ' + repr(exp))
        raise
    else:
        logger.debug('Data fetched')

    return cursor, data


def store_api_key_to_db(account_id=None, account_api_key=None, cursor=None):
    """
    Store API Key to DB

    :param account_id: User account ID
    :param account_api_key: API Key
    :param cursor: Database cursor
    :return: Database cursor and last inserted row id
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if account_api_key is None:
        raise AttributeError("Provide account_api_key as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    sql_query = "INSERT INTO api_keys (account_id, api_key) VALUES ('%s', '%s')" % \
                (account_id, account_api_key)

    try:
        cursor, last_id = execute_sql_insert(cursor=cursor, sql_query=sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not store API Key to Database')
        logger.error('Could not store API Key to Database: ' + repr(exp))
        logger.debug('sql_query: ' + repr(sql_query))
        raise
    else:
        return cursor, last_id


def get_api_key(account_id=None, cursor=None):
    """
    Get API key from DB

    :param account_id: ID of user account
    :param cursor: Database cursor
    :return: Database cursot, JWK Object and Key ID
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    api_key_dict = {}

    sql_query = "SELECT id, account_id, api_key FROM api_keys WHERE account_id='%s' ORDER BY id DESC LIMIT 1" % (account_id)

    try:
        cursor, data = execute_sql_select(sql_query=sql_query, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fetch APi Key from database')
        logger.error('Could not fetch APi Key from database: ' + repr(exp))
        logger.debug('sql_query: ' + repr(sql_query))
        raise
    else:
        logger.debug("APi Key fetched from database")

        try:
            api_key_dict['id'] = data[0][0]
            api_key_dict['account_id'] = data[0][1]
            api_key_dict['api_key'] = data[0][2]
        except Exception as exp:
            exp = append_description_to_exception(exp=exp, description='Could not move database response to new dict')
            logger.error('APi Key for account not found from database: ' + repr(exp))
            raise ApiKeyNotFoundError("Api Key for account not found from database")
        else:
            logger.info("API Key Fetched")
            log_dict_as_json(data=api_key_dict)
            return cursor, api_key_dict['api_key']


def get_account_id(api_key=None, cursor=None):
    """
    Get User account ID from DB

    :param api_key: Api Key
    :param cursor: Database cursor
    :return: Database User account ID
    """
    if api_key is None:
        raise AttributeError("Provide api_key as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    api_key_dict = {}

    sql_query = "SELECT id, account_id, api_key FROM api_keys WHERE api_key='%s' ORDER BY id DESC LIMIT 1" % (api_key)

    try:
        cursor, data = execute_sql_select(sql_query=sql_query, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fetch Account ID from database')
        logger.error('Could not fetch Account ID from database: ' + repr(exp))
        logger.debug('sql_query: ' + repr(sql_query))
        raise
    else:
        logger.debug("Account ID fetched from database")

        try:
            api_key_dict['id'] = data[0][0]
            api_key_dict['account_id'] = data[0][1]
            api_key_dict['api_key'] = data[0][2]
        except Exception as exp:
            exp = append_description_to_exception(exp=exp, description='Could not move database response to new dict')
            logger.error('Account ID for Api Key not found from database: ' + repr(exp))
            raise AccountIdNotFoundError("Account ID for Api Key not found")
        else:
            logger.info("Account ID Fetched")
            log_dict_as_json(data=api_key_dict)
            return cursor, api_key_dict['account_id']


def clear_apikey_sqlite_db():
    """
    Initializes SQLite database.

    :param connection: Database connection object
    :return: Database connection object
    """
    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get database connection')
        logger.error('get_sqlite_connection: ' + repr(exp))
        raise

    sql_query = '''DELETE FROM api_keys WHERE account_id > 3;'''

    try:
        logger.info('Clearing database')
        logger.debug('Executing: ' + str(sql_query))
        connection.execute(sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not clear database')
        logger.error('connection.execute(sql): ' + repr(exp))
        connection.rollback()
        raise
    else:
        connection.commit()
        connection.close()
        logger.info('Database cleared')
        return True


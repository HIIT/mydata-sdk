# -*- coding: utf-8 -*-

"""
Minimum viable Key management. NOT FOR PRODUCTION USE.


__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

# Import dependencies
import json
import os
import sqlite3
from jwcrypto import jwk, jws

# create logger with 'spam_application'
from app.mod_blackbox.helpers import append_description_to_exception, KeyNotFoundError, get_custom_logger, jws_header_fix, \
    get_current_line_no

logger = get_custom_logger('mod_blackbox_services')

DELIMITTER = '/'
DATABASE = os.path.dirname(os.path.abspath(__file__)) + DELIMITTER + 'blackbox.sqlite'
#DATABASE = 'blackbox.sqlite'


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

    sql_query = '''CREATE TABLE account_keys (
              id            INTEGER   PRIMARY KEY AUTOINCREMENT,
              kid           TEXT  UNIQUE NOT NULL,
              account_id    INTEGER  UNIQUE NOT NULL,
              jwk       BLOB  NOT NULL
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


def store_jwk_to_db(account_id=None, account_kid=None, account_key=None, cursor=None):
    """
    Stores JWK to database.

    :param account_id: User account ID
    :param account_kid: Key ID
    :param account_key: Key
    :param cursor: Database cursor
    :return: Database cursor and last inserted row id
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if account_kid is None:
        raise AttributeError("Provide account_kid as parameter")
    if account_key is None:
        raise AttributeError("Provide account_key as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    sql_query = "INSERT INTO account_keys (kid, account_id, jwk) VALUES ('%s', '%s', '%s')" % \
                (account_kid, account_id, account_key)

    try:
        cursor, last_id = execute_sql_insert(cursor=cursor, sql_query=sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not store JWK to Database')
        logger.error('Could not store JWK to Database: ' + repr(exp))
        logger.debug('sql_query: ' + repr(sql_query))
        raise
    else:
        return cursor, last_id


def get_key(account_id=None, cursor=None):
    """
    Fetches JSON presentation of JWK object from database and converts JSON presentation to JWK object.

    :param account_id: ID of user account
    :param cursor: Database cursor
    :return: Database cursot, JWK Object and Key ID
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    jwk_dict = {}

    sql_query = "SELECT id, kid, account_id, jwk FROM account_keys WHERE account_id='%s' ORDER BY id DESC LIMIT 1" % (account_id)

    try:
        cursor, data = execute_sql_select(sql_query=sql_query, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fetch key from database')
        logger.error('Could not fetch key from database: ' + repr(exp))
        logger.debug('sql_query: ' + repr(sql_query))
        raise
    else:
        logger.debug("JWK json fetched from database")

        try:
            jwk_dict['id'] = data[0][0]
            jwk_dict['kid'] = data[0][1]
            jwk_dict['account_id'] = data[0][2]
            jwk_dict['jwk_key'] = data[0][3]
        except Exception as exp:
            exp = append_description_to_exception(exp=exp, description='Could not move database response to new dict')
            logger.error('Key for account not found from database: ' + repr(exp))
            raise KeyNotFoundError("Key for account not found from database")

        log_dict_as_json(data=jwk_dict, pretty=0)
        try:
            jwk_object = jwk_json_to_object(jwk_json=jwk_dict['jwk_key'])
        except Exception as exp:
            exp = append_description_to_exception(exp=exp, description='Could not convert JWK json to JWK object')
            logger.error('Could not convert JWK json to JWK object: ' + repr(exp))
            raise
        else:
            logger.debug('jwk_object: ' + str(jwk_object.__dict__))
            logger.debug('kid: ' + str(jwk_dict['kid']))
            return cursor, jwk_object, jwk_dict['kid']


def get_public_key_by_account_id(account_id=None, cursor=None):
    """
    Gets public Key by user account ID

    :param account_id: ID of user account
    :param cursor: Database cursor
    :return: Database cursor, JSON presentation of public Key and Key ID
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    try:
        cursor, jwk_object, kid = get_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get JWK object')
        logger.error('Could not get JWK object: ' + repr(exp))
        raise

    try:
        jwk_json_public = jwk_object_to_json_public_part(jwk_object=jwk_object)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not export public part of the key from JWK object')
        logger.error('Could not export public part of the key from JWK object: ' + repr(exp))
        raise
    else:
        logger.debug('kid: ' + str(kid))
        logger.debug('jwk_json_public: ' + repr(jwk_json_public))
        return cursor, jwk_json_public, kid


def get_key_by_account_id(account_id=None, cursor=None):
    """
    Gets Key by user account ID

    :param account_id: ID of user account
    :param cursor: Database cursor
    :return: Database cursor, JSON presentation of Key and Key ID
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")

    try:
        cursor, jwk_object, kid = get_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get JWK object')
        logger.error('Could not get JWK object: ' + repr(exp))
        raise

    try:
        jwk_json = jwk_object_to_json(jwk_object=jwk_object)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not export key from JWK object')
        logger.error('Could not export key from JWK object: ' + repr(exp))
        raise
    else:
        logger.debug('kid: ' + str(kid))
        logger.debug('jwk_object_public: ' + repr(jwk_object))
        return cursor, jwk_json, kid


#####################
# JWK
#####################
def jwk_json_to_object(jwk_json=None):
    """
    Converts JWK json presentation to JWK object

    :param jwk_json:
    :return: JWK object
    """
    if jwk_json is None:
        raise AttributeError("Provide jwk_json as parameter")
    else:
        logger.debug("As parameter jwk_json: " + repr(jwk_json).replace('u\'', '\''))

    try:
        jwk_dict = json.loads(jwk_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWK json to dict')
        logger.error('Could not convert JWK json to JWK dict: ' + repr(exp))
        raise
    else:
        logger.debug("jwk_json: " + repr(jwk_json))
        logger.info("JWK json converted to JWK dict")

    try:
        jwk_object = jwk.JWK(**jwk_dict)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWK json to JWK object')
        logger.error('Could not convert JWK json to JWK object: ' + repr(exp))
        raise
    else:
        logger.debug('JWK json converted to JWK object')
        logger.debug('jwk_object: ' + repr(jwk_object.__dict__))
        return jwk_object


def jwk_object_to_json(jwk_object=None):
    """
    Exports JWK object to JSON presentation

    :param jwk_object:
    :return: JSON presentation of JWK object
    """
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")

    try:
        jwk_json = jwk_object.export()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not export JWK')
        logger.error('Could not export JWK: ' + repr(exp))
        raise
    else:
        logger.debug('JWK exported')
        logger.debug('jwk_json: ' + repr(jwk_json))
        return jwk_json


def jwk_object_to_json_public_part(jwk_object=None):
    """
    Exports JWK object's public part to JSON presentation

    :param jwk_object:
    :return: JSON presentation of JWK object
    """
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")

    try:
        jwk_json_public = jwk_object.export_public()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not export public part of JWK')
        logger.error('Could not export public part of JWK: ' + repr(exp))
        raise
    else:
        logger.debug('JWK exported')
        logger.debug('jwk_json: ' + repr(jwk_json_public))
        return jwk_json_public


def gen_key_as_jwk(account_kid=None):
    """
    Generates JWK (JSON Web Key) object with JWCrypto's jwk module.
    - Module documentation: http://jwcrypto.readthedocs.io/en/stable/jwk.html

    :param account_kid: Key ID, https://tools.ietf.org/html/rfc7517#section-4.5
    :return: Generated JWK object
    """
    if account_kid is None:
        raise AttributeError("Provide account_kid as parameter")

    gen = {"generate": "EC", "cvr": "P-256", "kid": account_kid}

    try:
        account_key = jwk.JWK(**gen)
        account_key = jwk_object_to_json(jwk_object=account_key)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not generate JWK')
        logger.error('Could not generate JWK: ' + repr(exp))
        raise
    else:
        logger.debug('JWK for account generated')
        logger.debug('account_key: ' + repr(account_key))
        return account_key


#####################
# JWS
#####################
def jws_generate(payload=None):
    if payload is None:
        raise AttributeError("Provide payload as parameter")

    logger.debug('payload: ' + payload)

    try:
        jws_object = jws.JWS(payload=payload)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not generate JWS object with payload')
        logger.error('Could not generate JWS object with payload: ' + repr(exp))
        log_dict_as_json(data={'payload': repr(payload)})
        raise
    else:
        logger.debug('jws_object: ' + str(jws_object))
        log_dict_as_json(lineno=get_current_line_no(), data={'jws_object': jws_object.__dict__})
        logger.info('JWS object created')
        return jws_object


def jws_object_to_json(jws_object=None):
    """
    Converts JWS object to JWS JSON presentation
    - http://jwcrypto.readthedocs.io/en/stable/jws.html

    :param jws_object: JSON object
    :return: JSON presentation of JWS object
    """
    if jws_object is None:
        raise AttributeError("Provide jws_object as parameter")
    else:
        logger.debug("As parameter jws_object: " + repr(jws_object.__dict__).replace('u\'', '\''))

    try:
        jws_json = jws_object.serialize(compact=False)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS object to JWS json')
        logger.error('Could not convert JWS object to JWS json: ' + repr(exp))
        raise
    else:
        logger.debug('jws_json: ' + str(jws_json))
        logger.info('JWS object converted to JWS json')

    try:
        jws_json_fixed = jws_header_fix(malformed_jws_json=jws_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fix header in JWS json')
        logger.error('Could not fix header in JWS json: ' + repr(exp))
        raise
    else:
        logger.debug('jws_json_fixed: ' + str(jws_json_fixed))
        logger.info('Header fixed in JWS json')
        return jws_json_fixed


def jws_json_to_object(jws_json=None):
    """
    Converts JWS json presentation to JWS object
    - http://jwcrypto.readthedocs.io/en/stable/jws.html

    :param jws_json: JSON presentation of JWS object
    :return: JWS object
    """
    if jws_json is None:
        raise AttributeError("Provide jws_json as parameter")
    else:
        logger.debug("As parameter jws_json: " + repr(jws_json).replace('u\'', '\''))

    try:
        jws_object = jws.JWS()
        jws_object.deserialize(raw_jws=jws_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS json to JWS object')
        logger.error('Could not convert JWS json to JWS object: ' + repr(exp))
        raise
    else:
        logger.info('JWS json converted to JWS object')
        logger.debug('jws_object: ' + repr(jws_object.__dict__))
        return jws_object


def jws_sign(account_id=None, account_kid=None, jws_object=None, jwk_object=None, jwk_public_json=None, alg="ES256"):
    """
    Signs JWS with JWK.

    :param account_id: User account ID
    :param account_kid: Key ID for user's key
    :param jws_object: JWS object
    :param jwk_object: JWK object
    :param jwk_public_json: JSON presentation of public part of JWK
    :param alg: Signature algorithm to use, Defaults to ES256
    :return: Signed JWS object
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if account_kid is None:
        raise AttributeError("Provide account_kid as parameter")
    if jws_object is None:
        raise AttributeError("Provide jws_object as parameter")
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")
    if jwk_public_json is None:
        raise AttributeError("Provide jwk_public_json as parameter")
    if alg is None:
        raise AttributeError("Provide alg as parameter")

    try:
        unprotected_header = {'kid': account_kid}
        protected_header = {'alg': alg}
        unprotected_header_json = json.dumps(unprotected_header)
        protected_header_json = json.dumps(protected_header)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not create headers')
        logger.error('Could not create headers: ' + repr(exp))
        raise
    else:
        logger.info("Created headers")
        log_dict_as_json(data=unprotected_header)
        log_dict_as_json(data=protected_header)

    try:
        logger.debug("Signing JWS with following")
        log_dict_as_json(lineno=get_current_line_no(), data={'jws_object': repr(jws_object.__dict__)})
        log_dict_as_json(lineno=get_current_line_no(), data={'alg': alg})
        log_dict_as_json(lineno=get_current_line_no(), data={'unprotected_header_json': unprotected_header})
        log_dict_as_json(lineno=get_current_line_no(), data={'protected_header_json': protected_header})

        jws_object.add_signature(jwk_object, alg=alg, header=unprotected_header_json, protected=protected_header_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not sign JWS with JWK')
        logger.error('Could not sign JWS with JWK: ' + repr(exp))
        #log_dict_as_json(data={'msg': 'Could not sign JWS with JWK', 'unprotected_header': unprotected_header, 'protected_header': protected_header})
        raise
    else:
        logger.info("Signed JWS with JWK")
        logger.debug("Signed jws_object: " + str(jws_object.__dict__))
        return jws_object


def jws_verify(jws_object=None, jwk_object=None):
    """
    Verifies signature of JWS.

    :param jws_object: JWS object to verify
    :param jwk_object: JWK onject to use in verification
    :return: Boolean, presenting if verification passed
    """
    if jws_object is None:
        raise AttributeError("Provide jws_json as parameter")
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")

    try:
        jws_object.verify(jwk_object)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Signature verification failed')
        logger.error('Signature verification failed: ' + repr(exp))
        return False
    else:
        logger.info("JWS verified")
        return True


def clear_blackbox_sqlite_db():
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

    sql_query = '''DELETE FROM account_keys WHERE account_id > 3;'''

    try:
        logger.info('Clearing database')
        logger.debug('Executing: ' + str(sql_query))
        connection.execute(sql_query)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not clear database')
        logger.error('connection.execute(sql): ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.commit()
        connection.close()
        logger.info('Database cleared')
        return True

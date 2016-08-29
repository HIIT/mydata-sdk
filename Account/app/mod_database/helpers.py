# -*- coding: utf-8 -*-

# Import dependencies
import logging

# Import the database object from the main app module
from app import db, app

# create logger with 'spam_application'
from app.helpers import get_custom_logger

logger = get_custom_logger('mod_database_helpers')


def get_db_cursor():
    try:
        cursor = db.connection.cursor()
    except Exception as exp:
        logger.debug('db.connection.cursor(): ' + repr(exp))
        raise RuntimeError('Could not get cursor for database connection')
    else:
        logger.debug('DB cursor at ' + repr(cursor))
        return cursor


def execute_sql_insert(cursor, sql_query):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    INSERT to MySQL
    """

    last_id = ""

    if app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        last_id = str(cursor.lastrowid)
    except Exception as exp:
        logger.debug('cursor.lastrowid not found: ' + repr(exp))
        raise
    else:
        logger.debug('cursor.lastrowid: ' + last_id)

        return cursor, last_id


def execute_sql_insert_2(cursor, sql_query, arguments):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    INSERT to MySQL
    """

    last_id = ""

    logger.debug('sql_query: ' + str(sql_query))

    for index in range(len(arguments)):
        logger.debug("arguments[" + str(index) + "]: " + str(arguments[index]))

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query, (arguments))

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        last_id = str(cursor.lastrowid)
    except Exception as exp:
        logger.debug('cursor.lastrowid not found: ' + repr(exp))
        raise
    else:
        logger.debug('cursor.lastrowid: ' + last_id)

        return cursor, last_id


def execute_sql_select(cursor=None, sql_query=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """

    if app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchall()
    except Exception as exp:
        logger.debug('cursor.fetchall() failed: ' + repr(exp))
        data = 'No content'

    if app.config["SUPER_DEBUG"]:
        logger.debug('data ' + repr(data))

    return cursor, data


def execute_sql_select_2(cursor=None, sql_query=None, arguments=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """

    if app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        cursor.execute(sql_query, (arguments))

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchall()
    except Exception as exp:
        logger.debug('cursor.fetchall() failed: ' + repr(exp))
        data = 'No content'

    if app.config["SUPER_DEBUG"]:
        logger.debug('data ' + repr(data))

    return cursor, data


def execute_sql_count(cursor=None, sql_query=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """

    consent_count = 0

    if app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchone()
        if app.config["SUPER_DEBUG"]:
            logger.debug('data: ' + repr(data))

        consent_count = int(data[0])

    except Exception as exp:
        logger.debug('cursor.fetchone() failed: ' + repr(exp))

    if app.config["SUPER_DEBUG"]:
        logger.debug('data ' + repr(data))

    return cursor, consent_count


def drop_table_content():
    """
    http://stackoverflow.com/questions/5452760/truncate-foreign-key-constrained-table/5452798#5452798

    Drop table content
    """

    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.debug('Could not get db cursor: ' + repr(exp))
        raise

    sql_query = "SELECT Concat('TRUNCATE TABLE ',table_schema,'.',TABLE_NAME, ';') " \
                "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    sql_query1 = "SELECT Concat('DELETE FROM ',table_schema,'.',TABLE_NAME, '; ALTER TABLE ',table_schema,'.',TABLE_NAME, ' AUTO_INCREMENT = 1;') " \
                "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    try:
        cursor.execute(sql_query)
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        db.connection.rollback()
        raise
    else:
        sql_queries = cursor.fetchall()
        logger.debug("Fetched sql_queries: " + repr(sql_queries))

        try:
            logger.debug("SET FOREIGN_KEY_CHECKS = 0;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")

            for query in sql_queries:
                logger.debug("Executing: " + str(query[0]))
                sql_query = str(query[0])
                cursor.execute(sql_query)
        except Exception as exp:
            logger.debug('Error in SQL query execution: ' + repr(exp))
            db.connection.rollback()

            logger.debug("SET FOREIGN_KEY_CHECKS = 1;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")

            raise
        else:
            db.connection.commit()
            logger.debug("Committed")

            logger.debug("SET FOREIGN_KEY_CHECKS = 1;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")

            return True

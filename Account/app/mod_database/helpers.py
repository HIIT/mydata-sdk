# -*- coding: utf-8 -*-

# Import dependencies
import logging

# Import the database object from the main app module
from app import db, app

# create logger with 'spam_application'
from app.helpers import get_custom_logger

logger = get_custom_logger(__name__)


def log_query(sql_query=None, arguments=None):
    logger.info("Executing")
    if sql_query is None:
        raise AttributeError("Provide sql_query as parameter")
    if arguments is None:
        raise AttributeError("Provide arguments as parameter")

    logger.debug('sql_query: ' + repr(sql_query))

    for index in range(len(arguments)):
        logger.debug("arguments[" + str(index) + "]: " + str(arguments[index]))

    logger.debug('SQL query to execute: ' + repr(sql_query % arguments))


def get_db_cursor():
    logger.info("Executing")
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
    logger.info("Executing")

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
    logger.info("Executing")

    last_id = ""

    log_query(sql_query=sql_query, arguments=arguments)

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows: " + str(cursor.rowcount))
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


def execute_sql_update(cursor, sql_query, arguments):
    """
    :param arguments:
    :param cursor:
    :param sql_query:
    :return: cursor:

    INSERT to MySQL
    """
    logger.info("Executing")

    logger.debug('sql_query: ' + str(sql_query))

    for index in range(len(arguments)):
        logger.debug("arguments[" + str(index) + "]: " + str(arguments[index]))

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows SQL query: " + str(cursor.rowcount))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise
    else:
        logger.debug('db entry updated')
        return cursor


def execute_sql_select(cursor=None, sql_query=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """
    logger.info("Executing")

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
    logger.info("Executing")

    log_query(sql_query=sql_query, arguments=arguments)

    try:

        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows: " + str(cursor.rowcount))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchall()
    except Exception as exp:
        logger.debug('cursor.fetchall() failed: ' + repr(exp))
        data = 'No content'

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
    logger.info("Executing")

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
    logger.info("Executing")

    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.debug('Could not get db cursor: ' + repr(exp))
        raise

    sql_query = "SELECT Concat('TRUNCATE TABLE ',table_schema,'.',TABLE_NAME, ';') " \
                "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    # sql_query1 = "SELECT Concat('DELETE FROM ',table_schema,'.',TABLE_NAME, '; ALTER TABLE ',table_schema,'.',TABLE_NAME, ' AUTO_INCREMENT = 1;') " \
    #             "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"
    # TODO: Remove two upper rows

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


def get_primary_keys_by_account_id(cursor=None, account_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT id " \
                "FROM " + table_name + " " \
                "WHERE Accounts_id LIKE %s;"

    arguments = (
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_slr_ids(cursor=None, account_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkRecordId " \
                "FROM " + table_name + " " \
                "WHERE Accounts_id LIKE %s;"

    arguments = (
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_slsr_ids(cursor=None, slr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkStatusRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceLinkRecordId LIKE %s;"

    arguments = (
        '%' + str(slr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_cr_ids(cursor=None, slr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT consentRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceLinkRecordId LIKE %s;"

    arguments = (
        '%' + str(slr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_csr_ids(cursor=None, cr_id=None, csr_primary_key=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")
    if csr_primary_key is None:
        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s;"

        arguments = (
            '%' + str(cr_id) + '%',
        )
    else:
        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s AND id > %s;"

        arguments = (
            '%' + str(cr_id) + '%',
            int(csr_primary_key),
        )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][-1])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))
        return cursor, id_list


def get_last_csr_id(cursor=None, cr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT consentStatusRecordId " \
                "FROM " + table_name + " " \
                "WHERE consentRecordId LIKE %s " \
                "ORDER BY id DESC " \
                "LIMIT 1;"

    arguments = (
        '%' + str(cr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        entry_id = str(data_list[0])
        logger.info("Got entry_id: " + repr(entry_id))

        return cursor, entry_id


def get_account_id_by_csr_id(cursor=None, cr_id=None, acc_table_name=None, slr_table_name=None, cr_table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if acc_table_name is None:
        raise AttributeError("Provide acc_table_name as parameter")
    if slr_table_name is None:
        raise AttributeError("Provide slr_table_name as parameter")
    if cr_table_name is None:
        raise AttributeError("Provide cr_table_name as parameter")


    sql_query = "SELECT `Accounts`.`id` " \
                "FROM " + acc_table_name + " " \
                "INNER JOIN " + slr_table_name + " on " + acc_table_name + ".`id` = " + slr_table_name + ".`Accounts_id` " \
                "INNER JOIN " + cr_table_name + " on " + slr_table_name + ".`id` = " + cr_table_name + ".`ServiceLinkRecords_id` " \
                "WHERE " + cr_table_name + ".`consentRecordId` LIKE %s " \
                "LIMIT 1;"

    arguments = (
        '%' + str(cr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        entry_id = str(data_list[0])
        logger.info("Got entry_id: " + repr(entry_id))

        return cursor, entry_id






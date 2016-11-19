# -*- coding: utf-8 -*-

# Import dependencies
import uuid
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0

# Import the database object from the main app module
from flask import json

from app import login_manager, app

# create logger with 'spam_application'
from app.helpers import get_custom_logger
from app.mod_auth.models import User
from app.mod_database.helpers import get_db_cursor

logger = get_custom_logger('mod_auth_helpers')


def get_account_by_id(cursor=None, account_id=None):

    try:
        ###
        # User info by acoount_id
        logger.debug('User info by acoount_id')
        if app.config["SUPER_DEBUG"]:
            logger.debug('account_id: ' + repr(account_id))

        sql_query = "SELECT " \
                    "MyDataAccount.Accounts.id, " \
                    "MyDataAccount.LocalIdentities.id, " \
                    "MyDataAccount.LocalIdentities.username, " \
                    "MyDataAccount.Particulars.firstname, " \
                    "MyDataAccount.Particulars.lastname, " \
                    "MyDataAccount.Emails.email, " \
                    "MyDataAccount.Particulars.img_url, " \
                    "MyDataAccount.Particulars.dateOfBirth " \
                    "FROM MyDataAccount.Accounts " \
                    "INNER JOIN MyDataAccount.LocalIdentities " \
                    "ON MyDataAccount.Accounts.id = MyDataAccount.LocalIdentities.Accounts_id " \
                    "INNER JOIN MyDataAccount.Particulars " \
                    "ON MyDataAccount.Accounts.id = MyDataAccount.Particulars.Accounts_id " \
                    "INNER JOIN MyDataAccount.Emails " \
                    "ON MyDataAccount.Accounts.id = MyDataAccount.Emails.Accounts_id " \
                    "WHERE MyDataAccount.Accounts.id = '%s' AND MyDataAccount.Emails.prime = 1" % (account_id)

        if app.config["SUPER_DEBUG"]:
            logger.debug('sql_query: ' + repr(sql_query))

        cursor.execute(sql_query)

        data = cursor.fetchone()
        if app.config["SUPER_DEBUG"]:
            logger.debug('data: ' + repr(data))

        account_id_from_db = unicode(data[0])
        identity_id_from_db = str(data[1])
        username_from_db = str(data[2])
        firstname_from_db = str(data[3])
        lastname_from_db = str(data[4])
        email_from_db = str(data[5])
        img_url_from_db = str(data[6])
        data_of_birth_from_db = str(data[7])

    except Exception as exp:
        logger.debug('Account not found: ' + repr(exp))

        if app.config["SUPER_DEBUG"]:
            logger.debug('Exception: ' + repr(exp))

        return cursor, None

    else:
        logger.debug('Account found with given id: ' + str(account_id))
        if app.config["SUPER_DEBUG"]:
            logger.debug('account_id_from_db: ' + str(account_id_from_db))
            logger.debug('identity_id_from_db: ' + str(identity_id_from_db))
            logger.debug('username_from_db: ' + str(username_from_db))
            logger.debug('firstname_from_db: ' + str(firstname_from_db))
            logger.debug('lastname_from_db: ' + str(lastname_from_db))
            logger.debug('email_from_db: ' + str(email_from_db))
            logger.debug('img_url_from_db: ' + str(img_url_from_db))
            logger.debug('data_of_birth_from_db: ' + str(data_of_birth_from_db))

        user = User(
            account_id=account_id_from_db,
            identity_id=identity_id_from_db,
            username=username_from_db,
            firstname=firstname_from_db,
            lastname=lastname_from_db,
            email=email_from_db,
            img_url=img_url_from_db,
            date_of_birth=data_of_birth_from_db
        )

        return cursor, user


def get_account_by_username_and_password(cursor=None, username=None, password=None):
    username_to_check = str(username)
    logger.debug('username_to_check: ' + username_to_check)

    password_to_check = str(password)
    logger.debug('password_to_check: ' + password_to_check)

    try:
        ###
        # User info by username
        logger.debug('credentials')
        sql_query = "SELECT " \
                    "MyDataAccount.LocalIdentities.Accounts_id, " \
                    "MyDataAccount.LocalIdentities.id, " \
                    "MyDataAccount.LocalIdentities.username, " \
                    "MyDataAccount.LocalIdentityPWDs.password, " \
                    "MyDataAccount.Salts.salt  " \
                    "FROM MyDataAccount.LocalIdentities " \
                    "INNER JOIN MyDataAccount.LocalIdentityPWDs " \
                    "ON MyDataAccount.LocalIdentityPWDs.id = MyDataAccount.LocalIdentities.LocalIdentityPWDs_id " \
                    "INNER JOIN MyDataAccount.Salts " \
                    "ON MyDataAccount.Salts.LocalIdentities_id = MyDataAccount.LocalIdentities.id " \
                    "WHERE MyDataAccount.LocalIdentities.username = '%s'" % (username_to_check)

        if app.config["SUPER_DEBUG"]:
            logger.debug('sql_query: ' + repr(sql_query))

        cursor.execute(sql_query)

        data = cursor.fetchone()
        account_id_from_db = str(data[0])
        identity_id_from_db = str(data[1])
        username_from_db = str(data[2])
        password_from_db = str(data[3])
        salt_from_db = str(data[4])

    except Exception as exp:
        logger.debug('Authentication failed: ' + repr(exp))

        if app.config["SUPER_DEBUG"]:
            logger.debug('Exception: ' + repr(exp))

        return cursor, None

    else:
        logger.debug('User found with given username: ' + username)
        if app.config["SUPER_DEBUG"]:
            logger.debug('account_id_from_db: ' + account_id_from_db)
            logger.debug('identity_id_from_db: ' + identity_id_from_db)
            logger.debug('username_from_db: ' + username_from_db)
            logger.debug('password_from_db: ' + password_from_db)
            logger.debug('salt_from_db: ' + salt_from_db)

    if bcrypt.hashpw(password_to_check, salt_from_db) == password_from_db:
        if app.config["SUPER_DEBUG"]:
            logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
            logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Authenticated')
        cursor, user = get_account_by_id(cursor=cursor, account_id=int(account_id_from_db))
        return cursor, user

    else:
        if app.config["SUPER_DEBUG"]:
            logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
            logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Not Authenticated')
        return cursor, None


# user_loader callback for Flask-Login.
# https://flask-login.readthedocs.org/en/latest/#how-it-works
@login_manager.user_loader
def load_user(account_id):
    if app.config["SUPER_DEBUG"]:
        logger.debug("load_user(account_id), account_id=" + account_id)

    cursor = get_db_cursor()

    cursor, loaded_user = get_account_by_id(cursor=cursor, account_id=unicode(account_id))
    return loaded_user


# For API Auth module
def get_account_id_by_username_and_password(username=None, password=None):
    username_to_check = str(username)
    logger.debug('username_to_check: ' + username_to_check)

    password_to_check = str(password)
    logger.debug('password_to_check: ' + password_to_check)

    try:
        ###
        # User info by username
        logger.debug('User info by username from DB')
        sql_query = "SELECT " \
                    "MyDataAccount.LocalIdentities.Accounts_id, " \
                    "MyDataAccount.LocalIdentities.id, " \
                    "MyDataAccount.LocalIdentities.username, " \
                    "MyDataAccount.LocalIdentityPWDs.password, " \
                    "MyDataAccount.Salts.salt  " \
                    "FROM MyDataAccount.LocalIdentities " \
                    "INNER JOIN MyDataAccount.LocalIdentityPWDs " \
                    "ON MyDataAccount.LocalIdentityPWDs.id = MyDataAccount.LocalIdentities.LocalIdentityPWDs_id " \
                    "INNER JOIN MyDataAccount.Salts " \
                    "ON MyDataAccount.Salts.LocalIdentities_id = MyDataAccount.LocalIdentities.id " \
                    "WHERE MyDataAccount.LocalIdentities.username = '%s'" % (username_to_check)

        if app.config["SUPER_DEBUG"]:
            logger.debug('sql_query: ' + repr(sql_query))

        # DB cursor
        cursor = get_db_cursor()

        cursor.execute(sql_query)

        data = cursor.fetchone()
        account_id_from_db = str(data[0])
        identity_id_from_db = str(data[1])
        username_from_db = str(data[2])
        password_from_db = str(data[3])
        salt_from_db = str(data[4])

    except Exception as exp:
        logger.debug('Authentication failed: ' + repr(exp))

        if app.config["SUPER_DEBUG"]:
            logger.debug('Exception: ' + repr(exp))

        return None

    else:
        logger.debug('User found with given username: ' + username)
        logger.debug('account_id_from_db: ' + account_id_from_db)
        logger.debug('identity_id_from_db: ' + identity_id_from_db)
        logger.debug('username_from_db: ' + username_from_db)
        logger.debug('password_from_db: ' + password_from_db)
        logger.debug('salt_from_db: ' + salt_from_db)

    logger.info("Checking password")
    if bcrypt.hashpw(password_to_check, salt_from_db) == password_from_db:
        logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
        logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Authenticated')
        #cursor, user = get_account_by_id(cursor=cursor, account_id=int(account_id_from_db))
        user = {'account_id': account_id_from_db, 'username': username_from_db}
        logger.debug('User dict created')
        return user

    else:
        logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
        logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Not Authenticated')
        return None

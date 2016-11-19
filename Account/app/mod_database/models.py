# -*- coding: utf-8 -*-

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0

# Import the database object from the main app module
import datetime
from flask import json

from app import db, api, login_manager, app

# create logger with 'spam_application'
from app.helpers import get_custom_logger
from app.mod_database.helpers import execute_sql_insert, execute_sql_insert_2, execute_sql_select_2, execute_sql_update

logger = get_custom_logger(__name__)


##########################################
##########################################
##########################################
class Account():
    id = None
    global_identifier = None
    activated = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", global_identifyer="", activated="", deleted=0, table_name="MyDataAccount.Accounts"):
        if id is not None:
            self.id = id
        if global_identifyer is not None:
            self.global_identifier = global_identifyer
        if activated is not None:
            self.activated = activated
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def global_identifier(self):
        return self.global_identifier

    @global_identifier.setter
    def global_identifier(self, value):
        self.global_identifier = value

    @property
    def activated(self):
        return self.activated

    @activated.setter
    def activated(self, value):
        self.activated = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['deleted']
        del dictionary['table_name']
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (globalIdentifier) VALUES (%s)"

        arguments = (
            str(self.global_identifier),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, globalIdentifier, activated " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND globalIdentifier LIKE %s AND activated LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.global_identifier) + '%',
            '%' + str(self.activated) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.global_identifier = data[0][1]
                self.activated = data[0][2]
            else:
                self.id = data[0]
                self.global_identifier = data[1]
                self.activated = data[2]

            return cursor


##########################################
##########################################
##########################################
class LocalIdentity():
    id = None
    username = None
    pwd_id = None
    accounts_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", username="", pwd_id="", accounts_id="", deleted=0, table_name="MyDataAccount.LocalIdentities"):
        if id is not None:
            self.id = id
        if username is not None:
            self.username = username
        if pwd_id is not None:
            self.pwd_id = pwd_id
        if accounts_id is not None:
            self.accounts_id = accounts_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def username(self):
        return self.username

    @username.setter
    def username(self, value):
        self.username = value

    @property
    def pwd_id(self):
        return self.pwd_id

    @pwd_id.setter
    def pwd_id(self, value):
        self.pwd_id = value

    @property
    def accounts_id(self):
        return self.accounts_id

    @accounts_id.setter
    def accounts_id(self, value):
        self.accounts_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['accounts_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (username, Accounts_id, LocalIdentityPWDs_id) " \
                    "VALUES (%s, %s, %s)"

        arguments = (
            str(self.username),
            int(self.accounts_id),
            str(self.pwd_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, username, LocalIdentityPWDs_id, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND username LIKE %s AND LocalIdentityPWDs_id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.username) + '%',
            '%' + str(self.pwd_id) + '%',
            '%' + str(self.accounts_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.username = data[0][1]
                self.pwd_id = data[0][2]
                self.accounts_id = data[0][3]
            else:
                self.id = data[0]
                self.username = data[1]
                self.pwd_id = data[2]
                self.accounts_id = data[3]

            return cursor


#####################
class LocalIdentityPWD():
    id = None
    password = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", password="", deleted=0, table_name="MyDataAccount.LocalIdentityPWDs"):
        if id is not None:
            self.id = id
        if password is not None:
            self.password = password
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, value):
        self.password = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (password) VALUES (%s)"

        arguments = (
            str(self.password),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, password " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND password LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.password) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.password = data[0][1]
            else:
                self.id = data[0]
                self.password = data[1]

            return cursor


#####################
class OneTimeCookie():
    id = None
    cookie = None
    used = None
    created = None
    updated = None
    identity_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", cookie="", used="", created="", updated="", identity_id="", deleted=0, table_name="MyDataAccount.OneTimeCookies"):
        if id is not None:
            self.id = id
        if cookie is not None:
            self.cookie = cookie
        if used is not None:
            self.used = used
        if created is not None:
            self.created = created
        if updated is not None:
            self.updated = updated
        if identity_id is not None:
            self.identity_id = identity_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def cookie(self):
        return self.cookie

    @cookie.setter
    def cookie(self, value):
        self.cookie = value

    @property
    def used(self):
        return self.used

    @used.setter
    def used(self, value):
        self.used = value

    @property
    def created(self):
        return self.created

    @created.setter
    def created(self, value):
        self.created = value

    @property
    def updated(self):
        return self.updated

    @updated.setter
    def updated(self, value):
        self.updated = value

    @property
    def identity_id(self):
        return self.identity_id

    @identity_id.setter
    def identity_id(self, value):
        self.identity_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (oneTimeCookie, LocalIdentities_id) " \
                    "VALUES (%s, %s)"

        arguments = (
            str(self.cookie),
            int(self.identity_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, oneTimeCookie, used, created, updated, LocalIdentities_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND oneTimeCookie LIKE %s AND used LIKE %s AND created LIKE %s " \
                    "AND updated LIKE %s AND LocalIdentities_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.cookie) + '%',
            '%' + str(self.used) + '%',
            '%' + str(self.created) + '%',
            '%' + str(self.updated) + '%',
            '%' + str(self.identity_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.cookie = data[0][1]
                self.used = data[0][2]
                self.created = data[0][3]
                self.updated = data[0][4]
                self.identity_id = data[0][5]
            else:
                self.id = data[0]
                self.cookie = data[1]
                self.used = data[2]
                self.created = data[3]
                self.updated = data[4]
                self.identity_id = data[5]

            return cursor


#####################
class Salt():
    id = None
    salt = None
    identity_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", salt="", identity_id="", deleted=0, table_name="MyDataAccount.Salts"):
        if id is not None:
            self.id = id
        if salt is not None:
            self.salt = salt
        if identity_id is not None:
            self.identity_id = identity_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def salt(self):
        return self.salt

    @salt.setter
    def salt(self, value):
        self.salt = value

    @property
    def identity_id(self):
        return self.identity_id

    @identity_id.setter
    def identity_id(self, value):
        self.identity_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (salt, LocalIdentities_id) VALUES (%s, %s)"

        arguments = (
            str(self.salt),
            int(self.identity_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, salt, LocalIdentities_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND salt LIKE %s AND LocalIdentities_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.salt) + '%',
            '%' + str(self.identity_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.salt = data[0][1]
                self.identity_id = data[0][2]
            else:
                self.id = data[0]
                self.salt = data[1]
                self.identity_id = data[2]

            return cursor


##########################################
##########################################
##########################################
class Particulars():
    id = ""
    firstname = None
    lastname = None
    date_of_birth = None
    img_url = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", firstname="", lastname="", date_of_birth="", img_url=app.config['AVATAR_URL'], account_id="", deleted=0, table_name="MyDataAccount.Particulars"):
        if id is not None:
            self.id = id
        if firstname is not None:
            self.firstname = firstname
        if lastname is not None:
            self.lastname = lastname
        if date_of_birth is not None:
            self.date_of_birth = date_of_birth
        if img_url is not None:
            self.img_url = str(img_url)
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def firstname(self):
        return self.firstname

    @firstname.setter
    def firstname(self, value):
        self.firstname = value

    @property
    def lastname(self):
        return self.lastname

    @lastname.setter
    def lastname(self, value):
        self.lastname = value

    @property
    def date_of_birth(self):
        return self.date_of_birth

    @date_of_birth.setter
    def date_of_birth(self, value):
        self.date_of_birth = value

    @property
    def img_url(self):
        return self.img_url

    @img_url.setter
    def img_url(self, value):
        self.img_url = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self._account_id = value

    @property
    def full_name(self):
        return self.firstname + " " + self.lastname

    @property
    def to_dict(self):
        if isinstance(self.date_of_birth, datetime.date):
            self.date_of_birth = self.date_of_birth.strftime("%Y-%m-%d")
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Particular"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def __repr__(self):
        return 'User < id=%s, firstname=%s, lastname=%s, date_of_birth=%s, img_url=%s, account_id=%s >' % \
               (self.id, self.firstname, self.lastname, self.date_of_birth, self.img_url, self.account_id)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (firstname, lastname, dateOfBirth, img_url, Accounts_id) " \
                    "VALUES (%s, %s, STR_TO_DATE(%s, '%%Y-%%m-%%d'), %s, %s)"

        arguments = (
            str(self.firstname),
            str(self.lastname),
            str(self.date_of_birth),
            str(self.img_url),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def update_db(self, cursor=""):

        sql_query = "UPDATE " + self.table_name + " SET firstname=%s, lastname=%s, dateOfBirth=STR_TO_DATE(%s, '%%Y-%%m-%%d'), img_url=%s " \
                    "WHERE id=%s AND Accounts_id=%s"

        arguments = (
            str(self.firstname),
            str(self.lastname),
            str(self.date_of_birth),
            str(self.img_url),
            str(self.id),
            str(self.account_id),
        )

        try:
            cursor = execute_sql_update(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.info("SQL query executed")
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # Querying with all data disabled due formatting problems
        # TODO: Enable Querying with Date
        # sql_query = "SELECT id, firstname, lastname, dateOfBirth, img_url, Accounts_id " \
        #             "FROM " + self.table_name + " " \
        #             "WHERE id LIKE %s AND firstname LIKE %s AND lastname LIKE %s AND dateOfBirth LIKE %s " \
        #             "AND img_url LIKE %s AND Accounts_id LIKE %s;"
        #
        # arguments = (
        #     '%' + str(self.id) + '%',
        #     '%' + str(self.firstname) + '%',
        #     '%' + str(self.lastname) + '%',
        #     '%' + str(self.date_of_birth) + '%',
        #     '%' + str(self.img_url) + '%',
        #     '%' + str(self.account_id) + '%',
        # )

        sql_query = "SELECT id, firstname, lastname, dateOfBirth, img_url, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.firstname = data[0][1]
                self.lastname = data[0][2]
                self.date_of_birth = data[0][3]
                self.img_url = data[0][4]
                self.account_id = data[0][5]
            else:
                self.id = data[0]
                self.firstname = data[1]
                self.lastname = data[2]
                self.date_of_birth = data[0][3]
                self.img_url = data[0][4]
                self.account_id = data[0][5]

            return cursor


#####################
class Email():
    id = None
    email = None
    type = None
    prime = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", email="", type="Personal", prime="", account_id="", deleted=0, table_name="MyDataAccount.Emails"):
        if id is not None:
            self.id = id
        if email is not None:
            self.email = email
        if type is not None:
            self.type = type
        if prime is not None:
            if prime == "True":
                self.prime = 1
            else:
                self.prime = 0
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def email(self):
        return self.email

    @email.setter
    def email(self, value):
        self.email = value

    @property
    def type(self):
        return self.type

    @type.setter
    def type(self, value):
        self.type = value

    @property
    def prime(self):
        return self.prime

    @prime.setter
    def prime(self, value):
        self.prime = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        if dictionary['prime'] == 1:
            dictionary['prime'] = "True"
        elif dictionary['prime'] == 0:
            dictionary['prime'] = "False"
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Email"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (email, entryType, prime, Accounts_id) " \
                    "VALUES (%s, %s, %s, %s)"

        arguments = (
            str(self.email),
            str(self.type),
            str(self.prime),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, email, entryType, prime, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.email = data[0][1]
                self.type = data[0][2]
                self.prime = data[0][3]
                self.account_id = data[0][4]
            else:
                self.id = data[0]
                self.email = data[1]
                self.type = data[2]
                self.prime = data[0][3]
                self.account_id = data[4]

            return cursor

    def update_db(self, cursor=""):

        sql_query = "UPDATE " + self.table_name + " SET email=%s, entryType=%s, prime=%s " \
                                                  "WHERE id=%s AND Accounts_id=%s"

        arguments = (
            str(self.email),
            str(self.type),
            str(self.prime),
            str(self.id),
            str(self.account_id),
        )

        try:
            cursor = execute_sql_update(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.info("SQL query executed")
            return cursor


#####################
class Telephone():
    id = None
    tel = None
    type = None
    prime = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", tel="", type="Personal", prime="", account_id="", deleted=0, table_name="MyDataAccount.Telephones"):
        if id is not None:
            self.id = id
        if tel is not None:
            self.tel = tel
        if type is not None:
            self.type = type
        if prime is not None:
            if prime == "True":
                self.prime = 1
            else:
                self.prime = 0
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def tel(self):
        return self.tel

    @tel.setter
    def tel(self, value):
        self.tel = value

    @property
    def type(self):
        return self.type

    @type.setter
    def type(self, value):
        self.type = value

    @property
    def prime(self):
        return self.prime

    @prime.setter
    def prime(self, value):
        self.prime = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        if dictionary['prime'] == 1:
            dictionary['prime'] = "True"
        elif dictionary['prime'] == 0:
            dictionary['prime'] = "False"
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Telephone"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (tel, entryType, prime, Accounts_id) " \
                    "VALUES (%s, %s, %s, %s)"

        arguments = (
            str(self.tel),
            str(self.type),
            str(self.prime),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, tel, entryType, prime, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.tel = data[0][1]
                self.type = data[0][2]
                self.prime = data[0][3]
                self.account_id = data[0][4]
            else:
                self.id = data[0]
                self.tel = data[1]
                self.type = data[2]
                self.prime = data[0][3]
                self.account_id = data[4]

            return cursor

    def update_db(self, cursor=""):

        sql_query = "UPDATE " + self.table_name + " SET tel=%s, entryType=%s, prime=%s " \
                                                  "WHERE id=%s AND Accounts_id=%s"

        arguments = (
            str(self.tel),
            str(self.type),
            str(self.prime),
            str(self.id),
            str(self.account_id),
        )

        try:
            cursor = execute_sql_update(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.info("SQL query executed")
            return cursor


#####################
class Settings():
    id = None
    key = None
    value = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", key="", value="", account_id="", deleted=0, table_name="MyDataAccount.Settings"):
        if id is not None:
            self.id = id
        if key is not None:
            self.key = key
        if key is not None:
            self.key = key
        if value is not None:
            self.value = value
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def key(self):
        return self.key

    @key.setter
    def key(self, value):
        self.key = value

    @property
    def value(self):
        return self.value

    @value.setter
    def value(self, value):
        self.value = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Setting"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (setting_key, setting_value, Accounts_id) " \
                    "VALUES (%s, %s, %s)"

        arguments = (
            str(self.key),
            str(self.value),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, setting_key, setting_value, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.key = data[0][1]
                self.value = data[0][2]
                self.account_id = data[0][3]
            else:
                self.id = data[0]
                self.key = data[1]
                self.value = data[2]
                self.account_id = data[3]

            return cursor

    def update_db(self, cursor=""):

        sql_query = "UPDATE " + self.table_name + " SET setting_key=%s, setting_value=%s " \
                                                  "WHERE id=%s AND Accounts_id=%s"

        arguments = (
            str(self.key),
            str(self.value),
            str(self.id),
            str(self.account_id),
        )

        try:
            cursor = execute_sql_update(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.info("SQL query executed")
            return cursor


#####################
class EventLog():
    id = None
    actor = None
    event = None
    created = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", actor="", event="", created="", account_id="", deleted=0, table_name="MyDataAccount.EventLogs"):
        if id is not None:
            self.id = id
        if actor is not None:
            self.actor = actor
        if event is not None:
            self.event = event
        if created is not None:
            self.created = created
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def actor(self):
        return self.actor

    @actor.setter
    def actor(self, value):
        self.actor = value

    @property
    def event(self):
        return self.event

    @event.setter
    def event(self, value):
        self.event = value

    @property
    def created(self):
        return self.created

    @created.setter
    def created(self, value):
        self.created = value

    @property
    def table_name(self):
        return self.table_name

    @table_name.setter
    def table_name(self, value):
        self._table_name = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Event"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (actor, event, created, Accounts_id) " \
                    "VALUES (%s, %s, %s, %s)"

        arguments = (
            str(self.actor),
            str(self.event),
            int(self.created),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, actor, event, created, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.actor = data[0][1]
                self.event = data[0][2]
                self.created = data[0][3]
                self.account_id = data[0][4]
            else:
                self.id = data[0]
                self.actor = data[1]
                self.event = data[2]
                self.created = data[0][3]
                self.account_id = data[4]

            try:
                event_copy = self.event
                logger.info("event to dict")
                self.event = json.loads(self.event)
            except Exception as exp:
                logger.info("Could not event consent_status_record to dict. Using original")
                self.event = event_copy

            return cursor


#####################
class Contacts():
    id = None
    address1 = None
    address2 = None
    postal_code = None
    city = None
    state = None
    country = None
    entryType = None
    prime = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", address1="", address2="", postal_code="", city="", state="", country="", type="Personal", prime="", account_id="", deleted=0, table_name="MyDataAccount.Contacts"):
        if id is not None:
            self.id = id
        if address1 is not None:
            self.address1 = address1
        if address2 is not None:
            self.address2 = address2
        if postal_code is not None:
            self.postal_code = postal_code
        if city is not None:
            self.city = city
        if state is not None:
            self.state = state
        if country is not None:
            self.country = country
        if type is not None:
            self.type = type
        if prime is not None:
            if prime == "True":
                self.prime = 1
            else:
                self.prime = 0
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def address1(self):
        return self.address1

    @address1.setter
    def address1(self, value):
        self.address1 = value

    @property
    def address2(self):
        return self.address2

    @address2.setter
    def address2(self, value):
        self.address2 = value

    @property
    def postal_code(self):
        return self.postal_code

    @postal_code.setter
    def postal_code(self, value):
        self.postal_code = value

    @property
    def city(self):
        return self.city

    @city.setter
    def city(self, value):
        self.city = value

    @property
    def state(self):
        return self.state

    @state.setter
    def state(self, value):
        self.state = value

    @property
    def country(self):
        return self.country

    @country.setter
    def country(self, value):
        self.country = value

    @property
    def type(self):
        return self.type

    @type.setter
    def type(self, value):
        self.type = value

    @property
    def prime(self):
        return self.prime

    @prime.setter
    def prime(self, value):
        self.prime = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        if dictionary['prime'] == 1:
            dictionary['prime'] = "True"
        elif dictionary['prime'] == 0:
            dictionary['prime'] = "False"
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "Contact"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (address1, address2, postalCode, city, state, country, entryType, prime, Accounts_id) " \
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"

        arguments = (
            str(self.address1),
            str(self.address2),
            str(self.postal_code),
            str(self.city),
            str(self.state),
            str(self.country),
            str(self.type),
            str(self.prime),
            int(self.account_id),
        )

        try:
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def update_db(self, cursor=""):

        sql_query = "UPDATE " + self.table_name + " SET address1=%s, address2=%s, postalCode=%s, city=%s, state=%s, " \
                                                  "country=%s, entryType=%s, prime=%s " \
                                                  "WHERE id=%s AND Accounts_id=%s"

        arguments = (
            str(self.address1),
            str(self.address2),
            str(self.postal_code),
            str(self.city),
            str(self.state),
            str(self.country),
            str(self.type),
            str(self.prime),
            str(self.id),
            str(self.account_id),
        )

        try:
            cursor = execute_sql_update(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.info("SQL query executed")
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        sql_query = "SELECT id, address1, address2, postalCode, city, state, country, entryType, prime, Accounts_id " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.address1 = data[0][1]
                self.address2 = data[0][2]
                self.postal_code = data[0][3]
                self.city = data[0][4]
                self.state = data[0][5]
                self.country = data[0][6]
                self.type = data[0][7]
                self.prime = data[0][8]
                self.account_id = data[0][9]
            else:
                self.id = data[0]
                self.address1 = data[1]
                self.address2 = data[2]
                self.postal_code = data[3]
                self.city = data[4]
                self.state = data[5]
                self.country = data[6]
                self.type = data[7]
                self.prime = data[8]
                self.account_id = data[9]

            return cursor


#####################
class ServiceLinkRecord():
    id = None
    service_link_record = None
    service_link_record_id = None
    service_id = None
    surrogate_id = None
    operator_id = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", service_link_record="", service_link_record_id="", service_id="", surrogate_id="", operator_id="", account_id="", deleted=0, table_name="MyDataAccount.ServiceLinkRecords"):
        if id is not None:
            self.id = id
        if service_link_record is not None:
            self.service_link_record = service_link_record
        if service_link_record_id is not None:
            self.service_link_record_id = service_link_record_id
        if service_id is not None:
            self.service_id = service_id
        if operator_id is not None:
            self.operator_id = operator_id
        if surrogate_id is not None:
            self.surrogate_id = surrogate_id
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def service_link_record(self):
        return self.service_link_record

    @service_link_record.setter
    def service_link_record(self, value):
        self.service_link_record = value

    @property
    def service_link_record_id(self):
        return self.service_link_record_id

    @service_link_record_id.setter
    def service_link_record_id(self, value):
        self.service_link_record_id = value

    @property
    def service_id(self):
        return self.service_id

    @service_id.setter
    def service_id(self, value):
        self.service_id = value

    @property
    def operator_id(self):
        return self.operator_id

    @operator_id.setter
    def operator_id(self, value):
        self.operator_id = value

    @property
    def surrogate_id(self):
        return self.surrogate_id

    @surrogate_id.setter
    def surrogate_id(self, value):
        self.surrogate_id = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['account_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "ServiceLinkRecord"
        dictionary['id'] = str(self.service_link_record_id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_record_dict_external(self):
        dictionary = {}
        dictionary["slr"] = self.service_link_record
        return dictionary

    @property
    def to_record_dict(self):
        dictionary = {}
        dictionary['type'] = "ServiceLinkRecord"
        dictionary['id'] = str(self.service_link_record_id)
        dictionary['attributes'] = self.to_record_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        # http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        # sql_query = "INSERT INTO ServiceLinkRecords (serviceLinkRecord, serviceLinkRecordId, serviceId, surrogateId, operatorId, Accounts_id) " \
        #             "VALUES (%s, %s, %s, %s, %s, %s)" % \
        #             (self.service_link_record, self.service_link_record_id, self.service_id, self.surrogate_id, self.operator_id, self.account_id)

        sql_query = "INSERT INTO " + self.table_name + " (" \
                    "serviceLinkRecord, " \
                    "serviceLinkRecordId, " \
                    "serviceId, " \
                    "surrogateId, " \
                    "operatorId, " \
                    "Accounts_id" \
                    ") VALUES (%s, %s, %s, %s, %s, %s)"

        arguments = (
            json.dumps(self.service_link_record),
            str(self.service_link_record_id),
            str(self.service_id),
            str(self.surrogate_id),
            str(self.operator_id),
            int(self.account_id),
        )

        try:
            logger.info("Inserting to ServiceLinkRecords")
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=""):

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, serviceLinkRecord, Accounts_id, serviceLinkRecordId, serviceId, surrogateId, operatorId  " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND serviceLinkRecord LIKE %s AND serviceLinkRecordId LIKE %s AND " \
                    "serviceId LIKE %s AND surrogateId LIKE %s AND operatorId LIKE %s AND Accounts_id LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.service_link_record) + '%',
            '%' + str(self.service_link_record_id) + '%',
            '%' + str(self.service_id) + '%',
            '%' + str(self.surrogate_id) + '%',
            '%' + str(self.operator_id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("ServiceLinkRecord could not be found with provided information")
            if len(data[0]):
                self.id = data[0][0]
                self.service_link_record = data[0][1]
                self.account_id = data[0][2]
                self.service_link_record_id = data[0][3]
                self.service_id = data[0][4]
                self.surrogate_id = data[0][5]
                self.operator_id = data[0][6]
            else:
                self.id = data[0]
                self.service_link_record = data[1]
                self.account_id = data[2]
                self.service_link_record_id = data[3]
                self.service_id = data[4]
                self.surrogate_id = data[5]
                self.operator_id = data[6]

            try:
                slr_copy = self.service_link_record
                logger.info("service_link_record to dict")
                self.service_link_record = json.loads(self.service_link_record)
            except Exception as exp:
                attribute_type = type(self.service_link_record)
                logger.info("Could not convert service_link_record to dict. Type of attribute: " + repr(attribute_type) + " Using original" + repr(attribute_type) + " Using original: " + repr(exp))
                self.service_link_record = slr_copy

            return cursor


class ServiceLinkStatusRecord():
    id = None
    service_link_status_record_id = None
    status = None
    service_link_status_record = None
    service_link_record_id = None
    issued_at = None
    prev_record_id = None
    service_link_records_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", service_link_status_record_id="", status="", service_link_status_record="", service_link_record_id="", issued_at="", prev_record_id="", service_link_records_id="", deleted=0, table_name="MyDataAccount.ServiceLinkStatusRecords"):
        if id is not None:
            self.id = id
        if service_link_status_record_id is not None:
            self.service_link_status_record_id = service_link_status_record_id
        if status is not None:
            self.status = status
        if service_link_status_record is not None:
            self.service_link_status_record = service_link_status_record
        if service_link_record_id is not None:
            self.service_link_record_id = service_link_record_id
        if issued_at is not None:
            self.issued_at = issued_at
        if prev_record_id is not None:
            self.prev_record_id = prev_record_id
        if service_link_records_id is not None:
            self.service_link_records_id = service_link_records_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def service_link_status_record_id(self):
        return self.service_link_status_record_id

    @service_link_status_record_id.setter
    def service_link_status_record_id(self, value):
        self.service_link_status_record_id = value

    @property
    def status(self):
        return self.status

    @status.setter
    def status(self, value):
        self.status = value

    @property
    def service_link_status_record(self):
        return self.service_link_status_record

    @service_link_status_record.setter
    def service_link_status_record(self, value):
        self.service_link_status_record = value

    @property
    def service_link_record_id(self):
        return self.service_link_record_id

    @service_link_record_id.setter
    def service_link_record_id(self, value):
        self.service_link_record_id = value

    @property
    def issued_at(self):
        return self.issued_at

    @issued_at.setter
    def issued_at(self, value):
        self.issued_at = value

    @property
    def prev_record_id(self):
        return self.prev_record_id

    @prev_record_id.setter
    def prev_record_id(self, value):
        self.prev_record_id = value

    @property
    def service_link_records_id(self):
        return self.service_link_records_id

    @service_link_records_id.setter
    def service_link_records_id(self, value):
        self.service_link_records_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['service_link_records_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "ServiceLinkStatusRecord"
        dictionary['id'] = str(self.service_link_status_record_id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_record_dict_external(self):
        dictionary = {}
        dictionary["slsr"] = self.service_link_status_record
        return dictionary

    @property
    def to_record_dict(self):
        dictionary = {}
        dictionary['type'] = "ServiceLinkStatusRecord"
        dictionary['id'] = str(self.service_link_status_record_id)
        dictionary['attributes'] = self.to_record_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        # sql_query = "INSERT INTO ServiceLinkRecords (serviceLinkStatusRecordId, status, serviceLinkStatusRecord, ServiceLinkRecords_id, serviceLinkRecordId, issued_at, prevRecordId) " \
        #             "VALUES (%s,%s, %s, %s, %s, %s, %s)" % \
        #             (self.service_link_status_record_id, self.status, self.service_link_status_record, self.service_link_records_id, self.service_link_record_id, self.issued_at, self.prev_record_id)

        sql_query = "INSERT INTO " + self.table_name + " (" \
                    "serviceLinkStatusRecordId, " \
                    "serviceLinkStatus, " \
                    "serviceLinkStatusRecord, " \
                    "ServiceLinkRecords_id, " \
                    "serviceLinkRecordId, " \
                    "issued_at, " \
                    "prevRecordId" \
                    ") VALUES (%s, %s, %s, %s, %s, %s, %s)"

        arguments = (
            str(self.service_link_status_record_id),
            str(self.status),
            json.dumps(self.service_link_status_record),
            int(self.service_link_records_id),
            str(self.service_link_record_id),
            int(self.issued_at),
            str(self.prev_record_id),
        )

        try:
            logger.info("Inserting to ServiceLinkStatusRecords")
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, serviceLinkStatus, serviceLinkStatusRecord, ServiceLinkRecords_id, serviceLinkRecordId, " \
                    "issued_at, prevRecordId, serviceLinkStatusRecordId " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND serviceLinkStatus LIKE %s AND serviceLinkStatusRecord LIKE %s AND " \
                    "ServiceLinkRecords_id LIKE %s AND serviceLinkRecordId LIKE %s AND issued_at LIKE %s AND " \
                    "prevRecordId LIKE %s AND serviceLinkStatusRecordId LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.status) + '%',
            '%' + str(self.service_link_status_record) + '%',
            '%' + str(self.service_link_records_id) + '%',
            '%' + str(self.service_link_record_id) + '%',
            '%' + str(self.issued_at) + '%',
            '%' + str(self.prev_record_id) + '%',
            '%' + str(self.service_link_status_record_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.status = data[0][1]
                self.service_link_status_record = data[0][2]
                self.service_link_records_id = data[0][3]
                self.service_link_record_id = data[0][4]
                self.issued_at = data[0][5]
                self.prev_record_id = data[0][6]
                self.service_link_status_record_id = data[0][7]
            else:
                self.id = data[0]
                self.status = data[1]
                self.service_link_status_record = data[2]
                self.service_link_records_id = data[3]
                self.service_link_record_id = data[4]
                self.issued_at = data[5]
                self.prev_record_id = data[6]
                self.service_link_status_record_id = data[7]

            try:
                slsr_copy = self.service_link_status_record
                logger.info("service_link_status_record to dict")
                self.service_link_status_record = json.loads(self.service_link_status_record)
            except Exception as exp:
                attribute_type = type(self.service_link_status_record)
                logger.info("Could not convert service_link_status_record to dict. Type of attribute: " + repr(attribute_type) + " Using original" + repr(attribute_type) + " Using original: " + repr(exp))
                self.service_link_status_record = slsr_copy

            return cursor


class SurrogateId():
    # TODO: Rename to SlrIDs or similar
    # TODO: How to react if slr is deleted?
    surrogate_id = None
    servicelinkrecord_id = None
    service_id = None
    account_id = None
    table_name = ""
    deleted = ""

    def __init__(self, service_id=None, account_id=None, deleted=0, table_name="MyDataAccount.ServiceLinkRecords"):
        if service_id is not None:
            self.service_id = service_id
        if account_id is not None:
            self.account_id = account_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def surrogate_id(self):
        return self.surrogate_id

    @surrogate_id.setter
    def surrogate_id(self, value):
        self.surrogate_id = value

    @property
    def service_id(self):
        return self.service_id

    @service_id.setter
    def service_id(self, value):
        self.service_id = value

    @property
    def account_id(self):
        return self.account_id

    @account_id.setter
    def account_id(self, value):
        self.account_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "SurrogateId"
        dictionary['id'] = str(self.id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def from_db(self, cursor=""):

        sql_query = "SELECT surrogateId, serviceLinkRecordId " \
                    "FROM " + self.table_name + " " \
                    "WHERE serviceId LIKE %s AND Accounts_id LIKE %s ORDER BY id DESC LIMIT 1;"

        arguments = (
            '%' + str(self.service_id) + '%',
            '%' + str(self.account_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("Surrogate Id and serviceLinkRecordId could not be found with provided information")
            if len(data[0]):
                self.surrogate_id = data[0][0]
                self.servicelinkrecord_id = data[0][1]
            else:
                self.surrogate_id = data[0]
                self.servicelinkrecord_id = data[1]
            return cursor


#####################
class ConsentRecord():
    id = ""
    consent_record = None
    consent_id = None
    surrogate_id = None
    resource_set_id = None
    service_link_record_id = None
    subject_id = None
    service_link_records_id = None
    role = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", consent_record="", consent_id="", surrogate_id="", resource_set_id="", service_link_record_id="", subject_id="", service_link_records_id="", role="", deleted=0, table_name="MyDataAccount.ConsentRecords"):
        self.id = id
        self.consent_record = consent_record
        self.surrogate_id = surrogate_id
        self.consent_id = consent_id
        self.resource_set_id = resource_set_id
        self.service_link_record_id = service_link_record_id
        self.subject_id = subject_id
        self.service_link_records_id = service_link_records_id
        self.role = role
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def consent_record(self):
        return self.consent_record

    @consent_record.setter
    def consent_record(self, value):
        self.consent_record = value

    @property
    def consent_id(self):
        return self.consent_id

    @consent_id.setter
    def consent_id(self, value):
        self.consent_id = value

    @property
    def surrogate_id(self):
        return self.surrogate_id

    @surrogate_id.setter
    def surrogate_id(self, value):
        self.surrogate_id = value

    @property
    def resource_set_id(self):
        return self.resource_set_id

    @resource_set_id.setter
    def resource_set_id(self, value):
        self.resource_set_id = value

    @property
    def service_link_record_id(self):
        return self.service_link_record_id

    @service_link_record_id.setter
    def service_link_record_id(self, value):
        self.service_link_record_id = value

    @property
    def subject_id(self):
        return self.subject_id

    @subject_id.setter
    def subject_id(self, value):
        self.subject_id = value

    @property
    def service_link_records_id(self):
        return self.service_link_records_id

    @service_link_records_id.setter
    def service_link_records_id(self, value):
        self.service_link_records_id = value

    @property
    def role(self):
        return self.role

    @role.setter
    def role(self, value):
        self.role = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['service_link_records_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "ConsentRecord"
        dictionary['id'] = str(self.consent_id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_record_dict_external(self):
        dictionary = {}
        dictionary["cr"] = self.consent_record
        return dictionary

    @property
    def to_record_dict(self):
        dictionary = {}
        dictionary['type'] = "ConsentRecord"
        dictionary['id'] = str(self.consent_id)
        dictionary['attributes'] = self.to_record_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (" \
                    "consentRecord, " \
                    "surrogateId, " \
                    "consentRecordId, " \
                    "ResourceSetId, " \
                    "serviceLinkRecordId, " \
                    "subjectId, " \
                    "ServiceLinkRecords_id," \
                    "role" \
                    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"

        arguments = (
            json.dumps(self.consent_record),
            str(self.surrogate_id),
            str(self.consent_id),
            str(self.resource_set_id),
            str(self.service_link_record_id),
            str(self.subject_id),
            int(self.service_link_records_id),
            str(self.role),
        )

        try:
            logger.info("Inserting to ConsentRecords")
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=""):

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, consentRecord, ServiceLinkRecords_id, surrogateId, consentRecordId, ResourceSetId, serviceLinkRecordId, subjectId, role " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND ServiceLinkRecords_id LIKE %s AND surrogateId LIKE %s AND " \
                    "consentRecordId LIKE %s AND ResourceSetId LIKE %s AND serviceLinkRecordId LIKE %s AND " \
                    "subjectId LIKE %s AND role LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.service_link_records_id) + '%',
            '%' + str(self.surrogate_id) + '%',
            '%' + str(self.consent_id) + '%',
            '%' + str(self.resource_set_id) + '%',
            '%' + str(self.service_link_record_id) + '%',
            '%' + str(self.subject_id) + '%',
            '%' + str(self.role) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("Consent Record could not be found with provided information")
            if len(data[0]):
                self.id = data[0][0]
                self.consent_record = data[0][1]
                self.service_link_records_id = data[0][2]
                self.surrogate_id = data[0][3]
                self.consent_id = data[0][4]
                self.resource_set_id = data[0][5]
                self.service_link_record_id = data[0][6]
                self.subject_id = data[0][7]
                self.role = data[0][8]
            else:
                self.id = data[0]
                self.consent_record = data[1]
                self.service_link_records_id = data[2]
                self.surrogate_id = data[3]
                self.consent_id = data[4]
                self.resource_set_id = data[5]
                self.service_link_record_id = data[6]
                self.subject_id = data[7]
                self.role = data[8]

            try:
                cr_copy = self.consent_record
                logger.info("consent_record to dict")
                self.consent_record = json.loads(self.consent_record)
            except Exception as exp:
                attribute_type = type(self.consent_record)
                logger.error("Could not convert consent_record to dict. Type of attribute: " + repr(attribute_type) + " Using original: " + repr(exp))
                self.consent_record = cr_copy

            return cursor


class ConsentStatusRecord():
    id = None
    status = None
    consent_status_record_id = None
    consent_status_record = None
    consent_records_id = None
    consent_record_id = None
    issued_at = None
    prev_record_id = None
    table_name = ""
    deleted = ""

    def __init__(self, id="", consent_status_record_id="", status="", consent_status_record="", consent_records_id="", consent_record_id="", issued_at="", prev_record_id="", deleted=0, table_name="MyDataAccount.ConsentStatusRecords"):
        if id is not None:
            self.id = id
        if consent_status_record_id is not None:
            self.consent_status_record_id = consent_status_record_id
        if status is not None:
            self.status = status
        if consent_status_record is not None:
            self.consent_status_record = consent_status_record
        if consent_records_id is not None:
            self.consent_records_id = consent_records_id
        if consent_record_id is not None:
            self.consent_record_id = consent_record_id
        if issued_at is not None:
            self.issued_at = issued_at
        if prev_record_id is not None:
            self.prev_record_id = prev_record_id
        if table_name is not None:
            self.table_name = table_name
        if deleted is not None:
            self.deleted = deleted

    @property
    def table_name(self):
        return self.table_name

    @property
    def id(self):
        return self.id

    @id.setter
    def id(self, value):
        self.id = value

    @property
    def consent_status_record_id(self):
        return self.consent_status_record_id

    @consent_status_record_id.setter
    def consent_status_record_id(self, value):
        self.consent_status_record_id = value

    @property
    def status(self):
        return self.status

    @status.setter
    def status(self, value):
        self.status = value

    @property
    def consent_status_record(self):
        return self.consent_status_record

    @consent_status_record.setter
    def consent_status_record(self, value):
        self.consent_status_record = value

    @property
    def consent_records_id(self):
        return self.consent_records_id

    @consent_records_id.setter
    def consent_records_id(self, value):
        self.consent_records_id = value

    @property
    def consent_record_id(self):
        return self.consent_record_id

    @consent_record_id.setter
    def consent_record_id(self, value):
        self.consent_record_id = value

    @property
    def issued_at(self):
        return self.issued_at

    @issued_at.setter
    def issued_at(self, value):
        self.issued_at = value

    @property
    def prev_record_id(self):
        return self.prev_record_id

    @prev_record_id.setter
    def prev_record_id(self, value):
        self.prev_record_id = value

    @property
    def to_dict(self):
        return self.__dict__

    @property
    def to_dict_external(self):
        dictionary = self.to_dict
        del dictionary['id']
        del dictionary['consent_records_id']
        del dictionary['table_name']
        del dictionary['deleted']
        return dictionary

    @property
    def to_api_dict(self):
        dictionary = {}
        dictionary['type'] = "ConsentStatusRecord"
        dictionary['id'] = str(self.consent_status_record_id)
        dictionary['attributes'] = self.to_dict_external
        return dictionary

    @property
    def to_record_dict_external(self):
        dictionary = {}
        dictionary["csr"] = self.consent_status_record
        return dictionary

    @property
    def to_record_dict(self):
        dictionary = {}
        dictionary['type'] = "ConsentStatusRecord"
        dictionary['id'] = str(self.consent_status_record_id)
        dictionary['attributes'] = self.to_record_dict_external
        return dictionary

    @property
    def to_json(self):
        return json.dumps(self.to_dict)

    @property
    def log_entry(self):
        return str(self.__class__.__name__) + " object " + str(self.to_json)

    def to_db(self, cursor=""):

        sql_query = "INSERT INTO " + self.table_name + " (" \
                    "consentStatusRecordId, " \
                    "consentStatus, " \
                    "consentStatusRecord, " \
                    "ConsentRecords_id, " \
                    "consentRecordId, " \
                    "issued_at, " \
                    "prevRecordId" \
                    ") VALUES (%s, %s, %s, %s, %s, %s, %s)"

        arguments = (
            str(self.consent_status_record_id),
            str(self.status),
            json.dumps(self.consent_status_record),
            int(self.consent_records_id),
            str(self.consent_record_id),
            int(self.issued_at),
            str(self.prev_record_id),
        )

        try:
            logger.info("Inserting to ConsentStatusRecords")
            cursor, last_id = execute_sql_insert_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            self.id = last_id
            return cursor

    def from_db(self, cursor=None):
        if cursor is None:
            raise AttributeError("Provide cursor as parameter")

        # TODO: Don't allow if role is only criteria

        sql_query = "SELECT id, consentStatusRecordId, consentStatus, consentStatusRecord, ConsentRecords_id, " \
                    "consentRecordId, issued_at, prevRecordId " \
                    "FROM " + self.table_name + " " \
                    "WHERE id LIKE %s AND consentStatusRecordId LIKE %s AND consentStatus LIKE %s " \
                    "AND consentStatusRecord LIKE %s AND  ConsentRecords_id LIKE %s AND " \
                    "consentRecordId LIKE %s AND issued_at LIKE %s AND prevRecordId LIKE %s;"

        arguments = (
            '%' + str(self.id) + '%',
            '%' + str(self.consent_status_record_id) + '%',
            '%' + str(self.status) + '%',
            '%' + str(self.consent_status_record) + '%',
            '%' + str(self.consent_records_id) + '%',
            '%' + str(self.consent_record_id) + '%',
            '%' + str(self.issued_at) + '%',
            '%' + str(self.prev_record_id) + '%',
        )

        try:
            cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
        except Exception as exp:
            logger.debug('sql_query: ' + repr(exp))
            raise
        else:
            logger.debug("Got data: " + repr(data))
            if len(data) == 0:
                raise IndexError("DB query returned no results")
            if len(data[0]):
                self.id = data[0][0]
                self.consent_status_record_id = data[0][1]
                self.status = data[0][2]
                self.consent_status_record = data[0][3]
                self.consent_records_id = data[0][4]
                self.consent_record_id = data[0][5]
                self.issued_at = data[0][6]
                self.prev_record_id = data[0][7]
            else:
                self.id = data[0]
                self.consent_status_record_id = data[1]
                self.status = data[2]
                self.consent_status_record = data[3]
                self.consent_records_id = data[4]
                self.consent_record_id = data[5]
                self.issued_at = data[6]
                self.prev_record_id = data[7]

            try:
                csr_copy = self.consent_status_record
                logger.info("consent_status_record to dict")
                self.consent_status_record = json.loads(self.consent_status_record)
            except Exception as exp:
                attribute_type = type(self.consent_status_record)
                logger.error("Could not convert consent_status_record to dict. Type of attribute: " + repr(attribute_type) + " Using original: " + repr(exp))
                self.consent_status_record = csr_copy

            return cursor


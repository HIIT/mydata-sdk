# -*- coding: utf-8 -*-

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0


# Import the database object from the main app module
from app import db, api, login_manager, app

# create logger with 'spam_application'
from app.helpers import get_custom_logger
from app.mod_database.helpers import execute_sql_select
from app.mod_database.models import Contacts, Email, Telephone

logger = get_custom_logger('mod_account_services')

#
# def get_service_link_record_count_by_account(cursor=None, account_id=None):
#     if app.config["SUPER_DEBUG"]:
#         logger.debug('account_id: ' + repr(account_id))
#
#     ###
#     logger.debug('get_consent_record_count(account_id)')
#     if app.config["SUPER_DEBUG"]:
#         logger.debug('account_id: ' + repr(account_id))
#
#     sql_query = "SELECT count(MyDataAccount.ServiceLinkRecords.id) " \
#                 "FROM MyDataAccount.ServiceLinkRecords " \
#                 "WHERE MyDataAccount.ServiceLinkRecords.Accounts_id = '%s'" % (account_id)
#
#     try:
#         cursor, count = execute_sql_select(cursor=cursor, sql_query=sql_query)
#         count = count[0][0]
#     except Exception as exp:
#         logger.error('Failed')
#         logger.debug('sql_query: ' + repr(exp))
#         raise
#     else:
#         if app.config["SUPER_DEBUG"]:
#             logger.debug('contacts: ' + repr(count))
#
#         return cursor, count
#
#
# def get_consent_record_count_by_account(cursor=None, account_id=None):
#     if app.config["SUPER_DEBUG"]:
#         logger.debug('account_id: ' + repr(account_id))
#
#     ###
#     logger.debug('get_consent_record_count(account_id)')
#     if app.config["SUPER_DEBUG"]:
#         logger.debug('account_id: ' + repr(account_id))
#
#     sql_query = "SELECT count(MyDataAccount.ConsentRecords.id) " \
#                 "FROM MyDataAccount.ConsentRecords " \
#                 "WHERE MyDataAccount.ConsentRecords.Accounts_id = '%s'" % (account_id)
#
#     try:
#         cursor, count = execute_sql_select(cursor=cursor, sql_query=sql_query)
#         count = count[0][0]
#     except Exception as exp:
#         logger.error('Failed')
#         logger.debug('sql_query: ' + repr(exp))
#         raise
#     else:
#         if app.config["SUPER_DEBUG"]:
#             logger.debug('contacts: ' + repr(count))
#
#         return cursor, count
#
#
# def get_contacts_by_account(cursor=None, account_id=None):
#
#     sql_query = "SELECT " \
#                 "MyDataAccount.Contacts.id, " \
#                 "MyDataAccount.Contacts.address1, " \
#                 "MyDataAccount.Contacts.address2, " \
#                 "MyDataAccount.Contacts.postalCode, " \
#                 "MyDataAccount.Contacts.city, " \
#                 "MyDataAccount.Contacts.state, " \
#                 "MyDataAccount.Contacts.country, " \
#                 "MyDataAccount.Contacts.typeEnum, " \
#                 "MyDataAccount.Contacts.prime " \
#                 "FROM MyDataAccount.Contacts " \
#                 "WHERE Accounts_id = ('%s')" % (account_id)
#
#     try:
#         cursor, data = execute_sql_select(cursor=cursor, sql_query=sql_query)
#
#         contacts = []
#
#         for entry in data:
#             contact_obj = Contacts(
#                 id=entry[0],
#                 address1=entry[1],
#                 address2=entry[2],
#                 postal_code=entry[3],
#                 city=entry[4],
#                 state=entry[5],
#                 country=entry[6],
#                 type=entry[7],
#                 prime=entry[8]
#             )
#
#             contacts.append(contact_obj.to_dict)
#
#
#     except Exception as exp:
#         logger.error('Failed')
#         logger.debug('sql_query: ' + repr(exp))
#         raise
#     else:
#         if app.config["SUPER_DEBUG"]:
#             logger.debug('contacts: ' + repr(contacts))
#
#         return cursor, contacts
#
#
# def get_emails_by_account(cursor=None, account_id=None):
#
#     sql_query = "SELECT " \
#                 "MyDataAccount.Emails.id, " \
#                 "MyDataAccount.Emails.email, " \
#                 "MyDataAccount.Emails.typeEnum, " \
#                 "MyDataAccount.Emails.prime " \
#                 "FROM MyDataAccount.Emails " \
#                 "WHERE Accounts_id = ('%s')" % (account_id)
#
#     try:
#         cursor, data = execute_sql_select(cursor=cursor, sql_query=sql_query)
#
#         emails = []
#
#         for entry in data:
#             email_obj = Email(
#                 id=entry[0],
#                 email=entry[1],
#                 type=entry[2],
#                 prime=entry[3]
#             )
#
#             emails.append(email_obj.to_dict)
#
#
#     except Exception as exp:
#         logger.error('Failed')
#         logger.debug('sql_query: ' + repr(exp))
#         raise
#     else:
#         if app.config["SUPER_DEBUG"]:
#             logger.debug('contacts: ' + repr(emails))
#
#         return cursor, emails
#
#
# def get_telephones_by_account(cursor=None, account_id=None):
#
#     sql_query = "SELECT " \
#                 "MyDataAccount.Telephones.id, " \
#                 "MyDataAccount.Telephones.tel, " \
#                 "MyDataAccount.Telephones.typeEnum, " \
#                 "MyDataAccount.Telephones.prime " \
#                 "FROM MyDataAccount.Telephones " \
#                 "WHERE Accounts_id = ('%s')" % (account_id)
#
#     try:
#         cursor, data = execute_sql_select(cursor=cursor, sql_query=sql_query)
#
#         telephones = []
#
#         for entry in data:
#             telephone_obj = Telephone(
#                 id=entry[0],
#                 tel=entry[1],
#                 type=entry[2],
#                 prime=entry[3]
#             )
#
#             telephones.append(telephone_obj.to_dict)
#
#
#     except Exception as exp:
#         logger.error('Failed')
#         logger.debug('sql_query: ' + repr(exp))
#         raise
#     else:
#         if app.config["SUPER_DEBUG"]:
#             logger.debug('contacts: ' + repr(telephones))
#
#         return cursor, telephones
#

# -*- coding: utf-8 -*-

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger
from app.mod_database.helpers import get_db_cursor
from app.mod_account.services import get_contacts_by_account, get_emails_by_account, get_telephones_by_account, \
    get_service_link_record_count_by_account, get_consent_record_count_by_account


# create logger with 'spam_application'
logger = get_custom_logger('mod_account_controllers')


def check_account_id(account_id=None):
    # TODO: check that session[account_id] and account_id from path are matching
    if account_id is None:
        logger.debug('Account ID must be provided as call parameter.')
        raise AttributeError('Account ID must be provided as call parameter.')
    else:
        return True


def get_potential_services_count(cursor=None, account_id=None):
    data = randint(10, 100)
    return cursor, data


def get_potential_consents_count(cursor=None, account_id=None):
    data = randint(10, 100)
    return cursor, data


def get_passive_services_count(cursor=None, account_id=None):
    data = randint(10, 100)
    return cursor, data


def get_passive_consents_count(cursor=None, account_id=None):
    data = randint(10, 100)
    return cursor, data


def get_service_link_record_count(cursor=None, account_id=None):

    check_account_id(account_id=account_id)

    if cursor is None:
        cursor = get_db_cursor()
        logger.debug('No DB cursor provided as call parameter. Getting new one.')

    cursor, data = get_service_link_record_count_by_account(cursor=cursor, account_id=account_id)

    return cursor, data


def get_consent_record_count(cursor=None, account_id=None):

    check_account_id(account_id=account_id)

    if cursor is None:
        cursor = get_db_cursor()
        logger.debug('No DB cursor provided as call parameter. Getting new one.')

    cursor, data = get_consent_record_count_by_account(cursor=cursor, account_id=account_id)

    return cursor, data


def get_contacts(cursor=None, account_id=None):

    check_account_id(account_id=account_id)

    if cursor is None:
        cursor = get_db_cursor()
        logger.debug('No DB cursor provided as call parameter. Getting new one.')

    cursor, data = get_contacts_by_account(cursor=cursor, account_id=account_id)

    return cursor, data


def get_emails(cursor=None, account_id=None):

    check_account_id(account_id=account_id)

    if cursor is None:
        cursor = get_db_cursor()
        logger.debug('No DB cursor provided as call parameter. Getting new one.')

    cursor, data = get_emails_by_account(cursor=cursor, account_id=account_id)

    return cursor, data


def get_telephones(cursor=None, account_id=None):

    check_account_id(account_id=account_id)

    if cursor is None:
        cursor = get_db_cursor()
        logger.debug('No DB cursor provided as call parameter. Getting new one.')

    cursor, data = get_telephones_by_account(cursor=cursor, account_id=account_id)

    return cursor, data



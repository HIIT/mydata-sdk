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
from app.mod_account.controllers import get_service_link_record_count, get_consent_record_count, get_telephones, \
    get_emails, get_contacts, get_passive_consents_count, get_potential_services_count, get_potential_consents_count
from app.mod_api_auth.controllers import get_account_api_key
from app.mod_database.helpers import get_db_cursor

mod_account_html = Blueprint('account_html', __name__, template_folder='templates')

# create logger with 'spam_application'
logger = get_custom_logger('mod_account_view_html')


# Resources
class Home(Resource):
    @login_required
    def get(self):

        account_id = session['user_id']
        logger.debug('Account id: ' + account_id)

        apikey = get_account_api_key(account_id=account_id)

        content_data = {
            'apikey': apikey
        }

        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('profile/index.html', content_data=content_data), 200, headers)


class Details(Resource):
    @login_required
    def get(self):

        account_id = session['user_id']
        logger.debug('Account id: ' + account_id)

        cursor = get_db_cursor()

        cursor, service_link_record_count = get_service_link_record_count(cursor=cursor, account_id=account_id)
        cursor, consent_count = get_consent_record_count(cursor=cursor, account_id=account_id)

        cursor, contacts = get_contacts(cursor=cursor, account_id=account_id)
        cursor, emails = get_emails(cursor=cursor, account_id=account_id)
        cursor, telephones = get_telephones(cursor=cursor, account_id=account_id)

        cursor, potential_services = get_potential_services_count(cursor=cursor, account_id=account_id)
        cursor, potential_consents = get_potential_consents_count(cursor=cursor, account_id=account_id)
        cursor, passive_services = get_potential_services_count(cursor=cursor, account_id=account_id)
        cursor, passive_consents = get_passive_consents_count(cursor=cursor, account_id=account_id)

        content_data = {
            'service_link_record_count': service_link_record_count,
            'consent_count': consent_count,
            'contacts': contacts,
            'emails': emails,
            'telephones': telephones,
            'potential_services': potential_services,
            'potential_consents': potential_consents,
            'passive_services': passive_services,
            'passive_consents': passive_consents
        }

        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('profile/details.html', content_data=content_data), 200, headers)


class Settings(Resource):
    @login_required
    def get(self):
        account_id = session['user_id']
        logger.debug('Account id: ' + account_id)

        content_data = {
            'service_link_record_count': None,
            'consent_count': None,
            'contacts': None,
            'emails': None,
            'telephones': None,
            'potential_services': None,
            'potential_consents': None,
            'passive_services': None,
            'passive_consents': None
        }

        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('profile/settings.html', content_data=content_data), 200, headers)


# Register resources
api.add_resource(Home, '/html/account/home/', '/', endpoint='home')
api.add_resource(Details, '/html/account/details/', endpoint='details')
api.add_resource(Settings, '/html/account/settings/', endpoint='settings')

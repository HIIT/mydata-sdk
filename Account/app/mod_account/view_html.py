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


# Register resources
api.add_resource(Home, '/html/account/home/', '/', endpoint='home')

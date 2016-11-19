# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse
import requests

# Import the database object from the main app module
from app import db, api, app, make_json_response

# Import Models
from app.helpers import get_custom_logger, ApiError
from app.mod_account.view_api import Accounts
from app.mod_api_auth.controllers import gen_account_api_key
from app.mod_api_auth.services import clear_apikey_sqlite_db
from app.mod_auth.controllers import SignUp
from app.mod_auth.helpers import get_account_by_username_and_password

# Import Resources
from app.mod_blackbox.controllers import gen_account_key
from app.mod_blackbox.services import clear_blackbox_sqlite_db
from app.mod_database.helpers import get_db_cursor, drop_table_content
from app.mod_database.models import Particulars, Account, LocalIdentityPWD, LocalIdentity, Salt, Email
from app.mod_account.view_html import Home

# Define the blueprint: 'auth', set its url prefix: app.url/auth
mod_system = Blueprint('system', __name__, template_folder='templates')

# create logger with 'spam_application'
logger = get_custom_logger('mod_system_controllers')


# Resources
class InitDb(Resource):
    def get(self, secret=None):

        # Verifying secret
        logger.debug("Provided secret: " + str(secret))
        if secret is None:
            logger.debug("No secret provided --> terminating")
            raise ApiError(code=403, title="Provide correct secret!")

        if secret != 'salainen':
            logger.debug("Wrong secret provided --> terminating")
            raise ApiError(code=403, title="Provide correct secret!")

        # Response data container
        response_data = {}

        # Clear MySQL tables
        logger.info("##########")
        logger.info("Clearing MySQL DB")
        try:
            drop_table_content()
        except Exception as exp:
            logger.error("Could not clear DB tables: " + repr(exp))
            raise ApiError(code=500, title="Could not clear DB tables", detail=repr(exp))
        else:
            logger.info("Cleared")
            response_data['Account'] = "MySQL Database cleared"

        # Clear Blackbox Sqlite
        logger.info("##########")
        logger.info("Clearing Blackbox Sqlite")
        try:
            # JWKs for accounts with id < 3 won't be deleted
            clear_blackbox_sqlite_db()
        except Exception as exp:
            logger.error("Could not clear DB tables: " + repr(exp))
            raise ApiError(code=500, title="Could not clear DB tables", detail=repr(exp))
        else:
            logger.info("Cleared")
            response_data['Blackbox'] = "SQLite Database cleared"

        # Clear ApiKey Sqlite
        logger.info("##########")
        logger.info("Clearing ApiKey Sqlite")
        try:
            # Api Keys for accounts with id < 3 won't be deleted
            clear_apikey_sqlite_db()
        except Exception as exp:
            logger.error("Could not clear DB tables: " + repr(exp))
            raise ApiError(code=500, title="Could not clear DB tables", detail=repr(exp))
        else:
            logger.info("Cleared")
            response_data['ApiKey'] = "SQLite Database cleared"

        # New accounts to MySQL Database
        logger.info("Initing MySQL")
        json_data = [
            {
                "data": {
                    "type": "Account",
                    "attributes": {
                        'firstName': 'Erkki',
                        'lastName': 'Esimerkki',
                        'dateOfBirth': '2016-04-29',
                        'email': 'erkki.esimerkki@examlpe.org',
                        'username': 'testUser',
                        'password': 'Hello',
                        'acceptTermsOfService': 'True'
                    }
                }
            },
            {
                "data": {
                    "type": "Account",
                    "attributes": {
                        'firstName': 'Iso',
                        'lastName': 'Pasi',
                        'dateOfBirth': '2016-08-12',
                        'email': 'iso.pasi@examlpe.org',
                        'username': 'pasi',
                        'password': '0nk0va',
                        'acceptTermsOfService': 'True'
                    }
                }
            },
            {
                "data": {
                    "type": "Account",
                    "attributes": {
                        'firstName': 'Dude',
                        'lastName': 'Dudeson',
                        'dateOfBirth': '2016-05-31',
                        'email': 'dude.dudeson@examlpe.org',
                        'username': 'mydata',
                        'password': 'Hello',
                        'acceptTermsOfService': 'True'
                    }
                }
            }
        ]

        form_data = [
            {
                'firstname': 'Erkki',
                'lastname': 'Esimerkki',
                'dateofbirth': '2016-05-31',
                'email': 'erkki.esimerkki@examlpe.org',
                'username': 'testUser',
                'password': 'Hello'
            },
            {
                'firstname': 'Iso',
                'lastname': 'Pasi',
                'dateofbirth': '2016-05-31',
                'email': 'iso.pasi@examlpe.org',
                'username': 'pasi',
                'password': '0nk0va'
            },
            {
                'firstname': 'Dude',
                'lastname': 'Dudeson',
                'dateofbirth': '2016-05-31',
                'email': 'dude.dudeson@examlpe.org',
                'username': 'mydata',
                'password': 'Hello'
            }
        ]


        logger.debug("##########")
        #url = api.url_for(resource=SignUp, _external=True)
        headers = {'Content-Type': 'application/json'}
        url = api.url_for(resource=Accounts, _external=True,)
        logger.debug("Posting: " + str(url))

        logger.debug("##########")
        logger.debug("Creating: " + repr(json_data[0]))
        #r = requests.post(url, data=form_data[0])
        r = requests.post(url, json=json_data[0], headers=headers)
        logger.debug("Response status: " + str(r.status_code))
        if r.status_code != 201:
            raise ApiError(code=500, title="Could not create first user", detail=str(r.text))

        logger.debug("##########")
        logger.debug("Creating: " + repr(json_data[1]))
        #r = requests.post(url, data=form_data[1])
        r = requests.post(url, json=json_data[1], headers=headers)
        logger.debug("Response status: " + str(r.status_code))
        if r.status_code != 201:
            raise ApiError(code=500, title="Could not create second user", detail=str(r.text))

        logger.debug("##########")
        logger.debug("Creating: " + repr(json_data[2]))
        #r = requests.post(url, data=form_data[2])
        r = requests.post(url, json=json_data[2], headers=headers)
        logger.debug("Response status: " + str(r.status_code))
        if r.status_code != 201:
            raise ApiError(code=500, title="Could not create third user", detail=str(r.text))


        #return make_json_response(data=response_data, status_code=418)

        # TODO: Remove following before production and uncomment above line
        # Response data
        response_text = "  \
            I'm a little teapot short and stout. <br> \
            Here is my handle. <br> \
            Here is my spout. <br> \
            When I get all steamed up, <br> \
            Hear me shout! <br> \
            Just tip me over <br> \
            And pour me out <br> \
             <br>\
            I'm a clever teapot, yes it's true. <br> \
            Here's an example of what I can do. <br> \
            I can turn my handle to a spout. <br> \
            Just tip me over and pour me out. <br> <br> \
            <a href=\"https://en.wikipedia.org/wiki/Hyper_Text_Coffee_Pot_Control_Protocol\" target=\"_blank\">https://en.wikipedia.org/wiki/Hyper_Text_Coffee_Pot_Control_Protocol</a> \
        "

        response = make_response((response_text, 418))
        return response


# Register resources
api.add_resource(InitDb, '/system/db/init/<string:secret>', endpoint='db_init')

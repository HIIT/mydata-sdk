# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session, request
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError
from app.mod_account.controllers import get_service_link_record_count, get_consent_record_count, get_telephones, \
    get_emails, get_contacts, get_passive_consents_count, get_potential_services_count, get_potential_consents_count
from app.mod_account.models import AccountSchema2
from app.mod_api_auth.controllers import gen_account_api_key, requires_api_auth_user, provideApiKey
from app.mod_blackbox.controllers import gen_account_key
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import Account, LocalIdentityPWD, LocalIdentity, Salt, Particulars, Email

mod_account_api = Blueprint('account_api', __name__, template_folder='templates')

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class Accounts(Resource):
    def post(self):
        """
        Example JSON
        {
          "username": "jukkakukkulansukka",
          "password": "kukka",
          "firstName": "string",
          "lastName": "string",
          "email": "jukka@kukkula.sukka",
          "dateOfBirth": "18-08-2016",
          "acceptTermsOfService": "True"
        }
        :return:
        """

        try:
            endpoint = str(api.url_for(self))
        except Exception as exp:
            endpoint = str(__name__)

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = AccountSchema2()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            username = json_data['username']
            password = json_data['password']
            firstName = json_data['firstName']
            lastName = json_data['lastName']
            email_address = json_data['email']
            dateOfBirth = json_data['dateOfBirth']
            acceptTermsOfService = json_data['acceptTermsOfService']

            global_identifier = str(uuid.uuid4())
            salt_str = str(bcrypt.gensalt())
            pwd_hash = bcrypt.hashpw(str(password), salt_str)
        except Exception as exp:
            error_title = "Could not prepare Account data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # DB cursor
        cursor = get_db_cursor()

        try:
            ###
            # Accounts
            logger.debug('Accounts')
            account = Account(global_identifyer=global_identifier)
            account.to_db(cursor=cursor)

            ###
            # localIdentityPWDs
            logger.debug('localIdentityPWDs')
            local_pwd = LocalIdentityPWD(password=pwd_hash)
            local_pwd.to_db(cursor=cursor)

            ###
            # localIdentities
            logger.debug('localIdentities')
            local_identity = LocalIdentity(
                username=username,
                pwd_id=local_pwd.id,
                accounts_id=account.id
            )
            local_identity.to_db(cursor=cursor)

            ###
            # salts
            logger.debug('salts')
            salt = Salt(
                salt=salt_str,
                identity_id=local_identity.id
            )
            salt.to_db(cursor=cursor)

            ###
            # Particulars
            logger.debug('particulars')
            particulars = Particulars(
                firstname=firstName,
                lastname=lastName,
                date_of_birth=dateOfBirth,
                account_id=account.id
            )
            logger.debug("to_dict: " + repr(particulars.to_dict))
            cursor = particulars.to_db(cursor=cursor)

            ###
            # emails
            logger.debug('emails')
            email = Email(
                email=email_address,
                type="Personal",
                prime=1,
                account_id=account.id
            )
            email.to_db(cursor=cursor)

            ###
            # Commit
            db.connection.commit()
        except Exception as exp:
            error_title = "Could not create Account"
            logger.debug('commit failed: ' + repr(exp))
            logger.debug('--> rollback')
            logger.error(error_title)
            db.connection.rollback()
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug('Account commited')

            try:
                logger.info("Generating Key for Account")
                kid = gen_account_key(account_id=account.id)
            except Exception as exp:
                error_title = "Could not generate Key for Account"
                logger.debug(error_title + ': ' + repr(exp))
                #raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
            else:
                logger.info("Generated Key for Account with Key ID: " + str(kid))

            try:
                logger.info("Generating API Key for Account")
                api_key = gen_account_api_key(account_id=account.id)
            except Exception as exp:
                error_title = "Could not generate API Key for Account"
                logger.debug(error_title + ': ' + repr(exp))
                #raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
            else:
                logger.info("Generated API Key: " + str(api_key))

            data = cursor.fetchall()
            logger.debug('data: ' + repr(data))

        # Response data container
        try:
            response_data = {}
            response_data['meta'] = {}
            response_data['meta']['activationInstructions'] = "Account activated already"

            response_data['data'] = {}
            response_data['data']['type'] = "Account"
            response_data['data']['id'] = str(account.id)
            response_data['data']['attributes'] = {}
            response_data['data']['attributes']['username'] = username
            response_data['data']['attributes']['firstName'] = firstName
            response_data['data']['attributes']['lastName'] = lastName
            response_data['data']['attributes']['email'] = email_address
            response_data['data']['attributes']['dateOfBirth'] = dateOfBirth
            response_data['data']['attributes']['acceptTermsOfService'] = acceptTermsOfService
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ExportAccount(Resource):
    @requires_api_auth_user
    def get(self, account_id):

        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provideApiKey(endpoint=endpoint)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)

        # Response data container
        try:
            response_data = {}
            response_data['meta'] = {}
            response_data['meta']['activationInstructions'] = "Account Export"

            response_data['data'] = {}
            response_data['data']['type'] = "Account"
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


# Register resources
api.add_resource(Accounts, '/api/accounts/', '/', endpoint='/api/accounts/')
api.add_resource(ExportAccount, '/api/account/<string:account_id>/export/', endpoint='account-export')

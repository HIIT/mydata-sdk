# -*- coding: utf-8 -*-

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash
from flask.ext.login import login_user, login_required, logout_user
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, app

# Import Models
from app.helpers import get_custom_logger
from app.mod_api_auth.controllers import gen_account_api_key
from app.mod_auth.helpers import get_account_by_username_and_password

# Import Resources
from app.mod_blackbox.controllers import gen_account_key
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import Particulars, Account, LocalIdentityPWD, LocalIdentity, Salt, Email
from app.mod_account.view_html import Home

# Define the blueprint: 'auth', set its url prefix: app.url/auth
mod_auth = Blueprint('auth', __name__, template_folder='templates')

# create logger with 'spam_application'
logger = get_custom_logger('mod_auth_controllers')

# Resources
class SignIn(Resource):
    def get(self):

        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('auth/signin.html'), 200, headers)

    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)

        parser.add_argument('username', location='form', required=True)
        parser.add_argument('password', location='form', required=True)

        args = parser.parse_args()

        username_to_check = str(repr(args['username'])[2:-1])
        password_to_check = str(repr(args['password'])[2:-1])

        # DB cursor
        cursor = get_db_cursor()

        cursor, registered_user = get_account_by_username_and_password(cursor=cursor, username=username_to_check, password=password_to_check)

        if app.config["SUPER_DEBUG"]:
            logger.debug("registered_user: " + registered_user.__repr__())

        if registered_user is None:
            flash('Wrong Credentials')
            return {}, 301, {'Location': api.url_for(resource=SignIn)}
        else:
            login_user(registered_user, remember=False)
            flash('Logged in successfully')
            return {}, 301, {'Location': api.url_for(resource=Home)}


class SignOut(Resource):
    @login_required
    def get(self):
        flash('Logged Out')
        logout_user()
        return {}, 301, {'Location': api.url_for(resource=SignIn)}


class SignUp(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('auth/signup.html'), 200, headers)

    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)

        parser.add_argument('firstname', location='form', required=True)
        parser.add_argument('lastname', location='form', required=True)
        parser.add_argument('dateofbirth', location='form', required=True)
        parser.add_argument('email', location='form', required=True)
        parser.add_argument('username', location='form', required=True)
        parser.add_argument('password', location='form', required=True)

        args = parser.parse_args()
        logger.debug('args: ' + repr(args).replace("'u'", "'"))

        global_identifier = str(uuid.uuid4())
        logger.debug('global_identifier: ' + repr(global_identifier).replace("'u'", "'"))

        username = str(repr(args['username'])[2:-1])
        logger.debug('username: ' + username)

        firstname = str(repr(args['firstname'])[2:-1])
        logger.debug('firstname: ' + firstname)

        lastname = str(repr(args['lastname'])[2:-1])
        logger.debug('lastname: ' + lastname)

        email = str(repr(args['email'])[2:-1])
        logger.debug('email: ' + email)

        date_of_birth = str(repr(args['dateofbirth'])[2:-1])
        logger.debug('date_of_birth: ' + date_of_birth)

        salt = str(bcrypt.gensalt())
        logger.debug('salt: ' + salt)

        pwd_to_hash = str(repr(args['password'])[2:-1])
        logger.debug('pwd_to_hash: ' + pwd_to_hash)

        pwd_hash = bcrypt.hashpw(pwd_to_hash, salt)
        logger.debug('pwd_hash: ' + repr(pwd_hash))

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
                salt=salt,
                identity_id=local_identity.id
            )
            salt.to_db(cursor=cursor)

            ###
            # Particulars
            logger.debug('particulars')
            particulars = Particulars(
                firstname=firstname,
                lastname=lastname,
                date_of_birth=date_of_birth,
                account_id=account.id
            )
            logger.debug("to_dict: " + repr(particulars.to_dict))
            cursor = particulars.to_db(cursor=cursor)

            ###
            # emails
            logger.debug('emails')
            email = Email(
                email=email,
                type="Personal",
                prime=1,
                account_id=account.id
            )
            email.to_db(cursor=cursor)

            ###
            # Commit
            db.connection.commit()
        except Exception as exp:
            logger.debug('commit failed: ' + repr(exp))
            db.connection.rollback()
            logger.debug('--> rollback')

            flash('Failed to create Account')
            return {}, 301, {'Location': api.url_for(resource=SignUp)}
        else:
            logger.debug('Account commited')

            try:
                logger.info("Generating Key for Account")
                kid = gen_account_key(account_id=account.id)
            except Exception as exp:
                logger.debug('Could not generate Key for Account: ' + repr(exp))
            else:
                logger.info("Generated Key for Account with Key ID: " + str(kid))

            try:
                logger.info("Generating API Key for Account")
                api_key = gen_account_api_key(account_id=account.id)
            except Exception as exp:
                logger.debug('Could not generate API Key for Account: ' + repr(exp))
            else:
                logger.info("Generated API Key: " + str(api_key))

        data = cursor.fetchall()

        logger.debug('data: ' + repr(data))

        #return {'args': args, 'data': data}
        flash('Account added')
        return {}, 301, {'Location': api.url_for(resource=SignIn)}


class Forgot(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('auth/forgot.html'), 200, headers)

    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)

        parser.add_argument('email', location='form', required=True)

        args = parser.parse_args()

        return {'response': args}


# Register resources
api.add_resource(SignIn, '/auth/signin/', endpoint='signin')
api.add_resource(SignOut, '/auth/signout/', endpoint='signout')
api.add_resource(SignUp, '/auth/signup/', endpoint='signup')
api.add_resource(Forgot, '/auth/forgot/', endpoint='forgot')

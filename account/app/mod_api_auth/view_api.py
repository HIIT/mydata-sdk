# -*- coding: utf-8 -*-

"""
Minimum viable account - API Auth module

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 26.5.2016
"""

from flask import Blueprint, render_template, make_response, flash, session, request
from flask_restful import Resource, Api, reqparse

from app import api
from app.helpers import get_custom_logger, make_json_response
from app.mod_api_auth.controllers import get_account_api_key, get_api_key_sdk
from app.mod_auth.helpers import get_account_id_by_username_and_password

logger = get_custom_logger('mod_api_auth_view_api')

# Define the blueprint: 'auth', set its url prefix: app.url/auth
mod_api_auth = Blueprint('api_auth', __name__, template_folder='templates')


class ApiKeyUser(Resource):
    account_id = None
    username = None
    api_key = None

    def check_basic_auth(self, username, password):
        """
        This function is called to check if a username password combination is valid.
        """
        user = get_account_id_by_username_and_password(username=username, password=password)
        logger.debug("User with following info: " + str(user))
        if user is not None:
            self.account_id = user['account_id']
            self.username = user['username']
            logger.debug("User info set")
            return True
        else:
            return False


    @staticmethod
    def authenticate():
        """Sends a 401 response that enables basic auth"""
        headers = {'WWW-Authenticate': 'Basic realm="Login Required"'}
        body = 'Could not verify your access level for that URL. \n You have to login with proper credentials'
        return make_response(body, 401, headers)

    def get(self):
        # account_id = session['user_id']
        # logger.debug('Account id: ' + account_id)

        auth = request.authorization
        if not auth or not self.check_basic_auth(auth.username, auth.password):
            return self.authenticate()

        api_key = get_account_api_key(account_id=self.account_id)


        response_data = {
            'api_key': api_key
        }

        return make_json_response(data=response_data, status_code=200)


class ApiKeySDK(Resource):
    username = "test_sdk"
    password = "test_sdk_pw"
    api_key = None

    def check_basic_auth(self, username, password):
        """
        This function is called to check if a username password combination is valid.
        """
        logger.debug("Provided username: " + str(username))
        logger.debug("Provided password: " + str(password))

        if (username == self.username) and (password == self.password):
            return True
        else:
            return False

    @staticmethod
    def authenticate():
        """Sends a 401 response that enables basic auth"""
        headers = {'WWW-Authenticate': 'Basic realm="Login Required"'}
        body = 'Could not verify your access level for that URL. \n You have to login with proper credentials'
        return make_response(body, 401, headers)

    def get(self):
        # account_id = session['user_id']
        # logger.debug('Account id: ' + account_id)

        auth = request.authorization
        if not auth or not self.check_basic_auth(auth.username, auth.password):
            return self.authenticate()

        api_key = get_api_key_sdk()

        response_data = {
            'api_key': api_key
        }

        return make_json_response(data=response_data, status_code=200)


# Register resources
api.add_resource(ApiKeyUser, '/api/auth/user/', endpoint='api_auth_user')
api.add_resource(ApiKeySDK, '/api/auth/sdk/', endpoint='api_auth_sdk')

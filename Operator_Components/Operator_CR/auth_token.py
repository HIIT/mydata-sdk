# -*- coding: utf-8 -*-
from flask import Blueprint, current_app
from flask_restful import Api, Resource

from DetailedHTTPException import error_handler
from helpers import AccountManagerHandler
api_CR_blueprint = Blueprint("api_AuthToken_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)

import logging
debug_log = logging.getLogger("debug")

from helpers import Helpers

from json import dumps
class AuthToken(Resource):
    def __init__(self):
        super(AuthToken, self).__init__()
        am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        timeout = current_app.config["TIMEOUT"]
        self.AM = AccountManagerHandler(am_url, am_user, am_password, timeout)
        helper_object = Helpers(current_app.config)
        self.gen_auth_token = helper_object.gen_auth_token
    @error_handler
    def get(self, cr_id):
        '''get

        :return: Returns Auth_token to service
        '''
        ##
        # Generate Auth Token and save it.
        # helper.py has the function template, look into it.
        ##

        #gen_auth_token()
        result = self.AM.get_AuthTokenInfo(cr_id)
        debug_log.debug(dumps(result, indent=2))
        token = self.gen_auth_token(result)

        return {"auth_token" : token}


api.add_resource(AuthToken, '/auth_token/<string:cr_id>')
# -*- coding: utf-8 -*-
import logging
import traceback
from json import dumps

from DetailedHTTPException import error_handler, DetailedHTTPException
from flask import Blueprint, current_app
from flask_restful import Api, Resource
from helpers import AccountManagerHandler
from helpers import Helpers

api_CR_blueprint = Blueprint("api_AuthToken_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)
debug_log = logging.getLogger("debug")
logger = logging.getLogger("sequence")
class AuthToken(Resource):
    def __init__(self):
        super(AuthToken, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}".format(repr(e)))
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
        try:
            result = self.AM.get_AuthTokenInfo(cr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.debug(dumps(result, indent=2))
        token = self.gen_auth_token(result)
        debug_log.info(dumps(result, indent=2))
        return {"auth_token" : token}


api.add_resource(AuthToken, '/auth_token/<string:cr_id>')
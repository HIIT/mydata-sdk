# -*- coding: utf-8 -*-
import logging
import traceback
from json import dumps

from DetailedHTTPException import error_handler, DetailedHTTPException
from flask import Blueprint, current_app
from flask_restful import Api, Resource
from helpers import AccountManagerHandler
from helpers import Helpers

api_CR_blueprint = Blueprint("api_Introspection_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)
debug_log = logging.getLogger("debug")
logger = logging.getLogger("sequence")
class Introspection(Resource):
    def __init__(self):
        super(Introspection, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}".format(repr(e)))
        helper_object = Helpers(current_app.config)

    @error_handler
    def get(self, cr_id):
        '''post

        :return: Returns latest csr for source
        '''
        try:
            debug_log.info("We received introspection request for cr_id ({})".format(cr_id))
            result = self.AM.get_last_csr(cr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info(dumps(result))
        return result

class Introspection_Missing(Resource):
    def __init__(self):
        super(Introspection_Missing, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}".format(repr(e)))
        helper_object = Helpers(current_app.config)

    @error_handler
    def get(self, cr_id, csr_id):
        '''get

        :return: Returns latest csr for source
        '''
        try:
            debug_log.info("We received introspection request for cr_id ({})".format(cr_id))
            result = self.AM.get_missing_csr(cr_id, csr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info(dumps(result))
        return result

api.add_resource(Introspection, '/introspection/<string:cr_id>')
api.add_resource(Introspection_Missing, '/consent/<string:cr_id>/missing_since/<string:csr_id>')

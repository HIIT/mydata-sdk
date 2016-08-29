# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
from json import loads, dumps
from flask import Blueprint, current_app
from flask_restful import Resource, Api
from requests import get, post
from DetailedHTTPException import DetailedHTTPException, error_handler
from sqlite3 import OperationalError, IntegrityError
from requests.exceptions import ConnectionError, Timeout
from Templates import Sequences, ServiceRegistryHandler
from helpers import Helpers
import logging
from flask_cors import CORS

'''

Operator_Components Mgmnt->Service_Components Mgmnt: Fetch code from service_mgmnt
Service_Components Mgmnt->Service_Components Mgmnt: Generate code
Service_Components Mgmnt->Service_Components Mgmnt: Store code in db
Service_Components Mgmnt-->Operator_Components Mgmnt: Returning code
Operator_Components Mgmnt->Operator_Components Mgmnt: Check code request is valid
Operator_Components Mgmnt->Operator_Components Mgmnt: Load code object for use
Operator_Components Mgmnt->Operator_Components Mgmnt: Add user_id to code dictionary {'code': 'code', 'user_id': 'user_id'}
Operator_Components Mgmnt->Service_Components Mgmnt: Redirect user to Service_Components Mgmnt login



'''

api_SLR_Start = Blueprint("api_SLR_Start", __name__)
from flask_cors import CORS
CORS(api_SLR_Start)

api = Api()
api.init_app(api_SLR_Start)

logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")
logger.setLevel(logging.INFO)


sq = Sequences("Operator_Components Mgmnt", {})

SUPER_DEBUG = True


class Start(Resource):
    def __init__(self):
        super(Start, self).__init__()
        self.service_registry_handler = ServiceRegistryHandler()
        self.request_timeout = current_app.config["TIMEOUT"]
        self.helper = Helpers(current_app.config)
        self.store_session = self.helper.store_session

    #@error_handler
    def get(self, account_id, service_id):
        try:
            try:
                to_store = {}  # We want to store some information for later parts of flow.

                # This address needs to be fetched somewhere to support multiple services
                service_mgmnt_address = self.service_registry_handler.getService_url(service_id)

                # Endpoint address should be fetched somewhere as well so we can re-use the service address later easily.
                endpoint = "/api/1.2/slr/code"


                sq.send_to("Service_Components Mgmnt", "Fetch code from service_mgmnt")
                result = get("{}{}".format(service_mgmnt_address, endpoint), timeout=self.request_timeout)
                code_status = result.status_code

                sq.task("Check code request is valid")
                debug_log.info(code_status)

                if code_status is 200:
                    sq.task("Load code object for use")
                    code = loads(result.text)
                    debug_log.info("Code contains: {}, account id {} and service_id {}".format(result.text, account_id, service_id))
                    to_store[code["code"]] = {"account_id": account_id, "service_id": service_id}
                    self.store_session(to_store)
                else:
                    raise DetailedHTTPException(status=code_status,
                                                detail={"msg": "Fetching code from Service_Components Mgmnt failed.",
                                                        "Errors From SrvMgmnt": loads(result.text)},
                                                title=result.reason)
            except Timeout:
                raise DetailedHTTPException(status=408,
                                            title="Request to Service_Components Mgmnt failed due to TimeoutError.",
                                            source="POST /code",
                                            detail="Service_Components Mgmnt might be under heavy load, request for code got timeout.")
            except ConnectionError:
                raise DetailedHTTPException(status=504,
                                            title="Request to Service_Components Mgmnt failed due to ConnectionError.",
                                            source="POST /code",
                                            detail="Service_Components Mgmnt might be down or unresponsive.")
            debug_log.info("We got code: {}".format(code))

            sq.task("Add user_id to code dictionary {'code': 'code', 'user_id': 'user_id'}")
            code["user_id"] = account_id

            try:
                endpoint = "/api/1.2/slr/login"
                sq.send_to("Service_Components Mgmnt", "Redirect user to Service_Components Mgmnt login")
                result = post("{}{}".format(service_mgmnt_address, endpoint), json=code, timeout=self.request_timeout)
                debug_log.info("####Response to this end point: {}\n{}".format(result.status_code, result.text))
                if not result.ok:
                    raise DetailedHTTPException(status=result.status_code,
                                                detail={
                                                    "msg": "Something went wrong while Logging in with code to Service_Components Mgmnt",
                                                    "Error from Service_Components Mgmnt": loads(result.text)},
                                                title=result.reason)

            except Timeout:
                raise DetailedHTTPException(status=408,
                                            title="Request to Service_Components Mgmnt failed due to TimeoutError.",
                                            source="POST /login",
                                            detail="Service_Components Mgmnt might be under heavy load, request for code got timeout.")
            except ConnectionError:
                raise DetailedHTTPException(status=504,
                                            title="Request to Service_Components Mgmnt failed due to ConnectionError.",
                                            source="POST /login",
                                            detail="Service_Components Mgmnt might be down or unresponsive.")



######################## This step is actually pointless since its only to fetch list of slr so we are sure it got generated right.
            # try:
            #     sq.send_to("Service_Components Mgmnt","Fetch list of slr's from service to verify success, this is debug step.")
            #     endpoint = "/api/1.2/slr/slr"
            #     result = get("{}{}".format(service_mgmnt_address, endpoint), timeout=self.request_timeout)
            #     if not result.ok:
            #         raise DetailedHTTPException(status=result.status_code,
            #                                     detail={
            #                                         "msg": "Something went wrong while Fetching list of SLR from Service_Components Mgmnt",
            #                                         "Error from Service_Components Mgmnt": loads(result.text)},
            #                                     title=result.reason)
            # except Timeout:
            #     raise DetailedHTTPException(status=408,
            #                                 title="Request to Service_Components Mgmnt failed due to TimeoutError.",
            #                                 source="POST /login",
            #                                 detail="Service_Components Mgmnt might be under heavy load, request for code got timeout.")
            # except ConnectionError:
            #     raise DetailedHTTPException(status=504,
            #                                 title="Request to Service_Components Mgmnt failed due to ConnectionError.",
            #                                 source="POST /login",
            #                                 detail="Service_Components Mgmnt might be down or unresponsive.")
            #
            # return loads(result.text)
        except DetailedHTTPException as e:
            raise DetailedHTTPException(exception=e,
                                        title="SLR registration failed.",
                                        status=500,
                                        detail="Something failed during creation of SLR.")
        except Exception as e:
            raise e
            raise DetailedHTTPException(status=500,
                                        title="Something went really wrong during SLR registration.",
                                        detail="Error: {}".format(repr(e)),
                                        exception=e)

api.add_resource(Start, '/account/<string:account_id>/service/<string:service_id>')
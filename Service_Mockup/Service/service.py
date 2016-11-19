# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import loads

from DetailedHTTPException import DetailedHTTPException, error_handler
from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from helpers import Helpers
from jwcrypto import jwk
from requests import post

debug_log = logging.getLogger("debug")

api_Root_blueprint = Blueprint("api_Root_blueprint", __name__)  # TODO Rename better

CORS(api_Root_blueprint)
api = Api()
api.init_app(api_Root_blueprint)

'''

OPERATOR: --> GET /code
<-- :SERVICE 201 CREATED {'code':'somecode'}

Here the code is stored along with the user who requested it and service it came from. Service_Components stores the generated code
 as well.


User is redirected to service login with the code.
USER: --> GET /login?code=somecode

User logins and agrees the linking. Surrogate ID is generated and sent to OPERATOR.
SERVICE: --> POST /register?surrogate=SURROGRATEID1&code=somecode
<-- :OPERATOR 200 OK
Using the code we link surrogate id to MyData Account and service confirming the link.

'''
Service_ID = "SRV-SH14W4S3"
gen = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}
token_key = jwk.JWK(**gen)
# templ = {Service_ID: loads(token_key.export_public())}
templ = {Service_ID: {"cr_keys": loads(token_key.export_public())}}


# post("http://localhost:6666/key", json=templ)
# op_key = loads(get("http://localhost:6666/key/"+"OPR-ID-RANDOM").text)
# Operator_pub = jwk.JWK(**op_key)


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log.info("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class UserLogin(Resource):
    def __init__(self):
        super(UserLogin, self).__init__()
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        debug_log.info(dumps(request.json, indent=2))
        user_id = request.json["user_id"]
        code = request.json["code"]
        self.helpers.storeCodeUser({code: user_id})

        debug_log.info("User logged in with id ({})".format(format(user_id)))
        endpoint = "/api/1.2/slr/auth"
        result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=request.json)
        if not result.ok:
            raise DetailedHTTPException(status=result.status_code,
                                        detail={
                                            "msg": "Something went wrong while posting to Service_Components Mgmnt to inform login was successful "
                                                   "and its alright to generate Surrogate_ID ",
                                            "Error from Service_Components Mgmnt": loads(result.text)},
                                        title=result.reason)

        debug_log.info(result.text)


from json import dumps


class RegisterSur(Resource):
    def __init__(self):
        super(RegisterSur, self).__init__()
        self.db_path = current_app.config["DATABASE_PATH"]
        self.helpers = Helpers(current_app.config)
    @timeme
    @error_handler
    def post(self):
        try:  # Remove this check once debugging is done. TODO
            user_id = self.helpers.get_user_id_with_code(request.json["code"])
            debug_log.info("We got surrogate_id {} for user_id {}".format(request.json["surrogate_id"], user_id))
            debug_log.info(dumps(request.json, indent=2))
            self.helpers.storeSurrogateJSON({user_id: request.json})
        except Exception as e:
            pass


class StoreSlr(Resource):
    def __init__(self):
        super(StoreSlr, self).__init__()
        self.db_path = current_app.config["DATABASE_PATH"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        debug_log.info(dumps(request.json, indent=2))
        store = request.json
        self.helpers.storeJSON({store["data"]["surrogate_id"]: store})


api.add_resource(UserLogin, '/login')
api.add_resource(RegisterSur, '/link')
api.add_resource(StoreSlr, '/store_slr')

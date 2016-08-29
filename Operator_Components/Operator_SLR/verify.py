# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
from json import loads, dumps
from uuid import uuid4 as guid
from flask import request, Blueprint, current_app
from flask_restful import Resource, Api
from jwcrypto import jws, jwk
from requests import get, post
from flask_cors import CORS
from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import Sequences
from helpers import AccountManagerHandler, Helpers
from base64 import urlsafe_b64decode as decode
api_SLR_Verify = Blueprint("api_SLR_blueprint", __name__)

CORS(api_SLR_Verify)
api = Api()
api.init_app(api_SLR_Verify)

import logging
logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")
logger.setLevel(logging.INFO)

sq = Sequences("Operator_Components Mgmnt", {})

'''

Service_Components Mgmnt->Operator_Components Mgmnt: Verify SLR(JWS)
Operator_Components Mgmnt->Operator_Components Mgmnt: Load SLR to object
Operator_Components Mgmnt->Operator_Components Mgmnt: Fix possible incorrect padding in payload
Operator_Components Mgmnt->Operator_Components Mgmnt: Load slr payload as object
Operator_Components Mgmnt->Operator_Components Mgmnt: Decode payload and store it into object
Operator_Components Mgmnt->Operator_Components Mgmnt: Fetch link_id from decoded payload
Operator_Components Mgmnt->Operator_Components Mgmnt: Load account_id from database
Operator_Components Mgmnt->Operator_Components Mgmnt: Load decoded payload as python dict
Operator_Components Mgmnt->Operator_Components Mgmnt: Load slr and code from json payload
Operator_Components Mgmnt->Account Manager: Verify SLR at Account Manager.
Operator_Components Mgmnt-->Service_Components Mgmnt: 201, SLR VERIFIED


'''

request_timeout = 20
SUPER_DEBUG = True
account_id = "ACC-ID-RANDOM"
user_account_id = account_id + "_" + str(guid())

##### Here some functions to help with verifying SLR(JWS)


def verifyJWS(json_JWS):
    def verify(jws, header):
        try:
            sign_key = jwk.JWK(**header["jwk"])
            jws.verify(sign_key)
            return True
        except Exception as e:
            debug_log.info(repr(e))

    try:

        json_web_signature = jws.JWS()
        if (isinstance(json_JWS, dict)):
            json_web_signature.deserialize(dumps(json_JWS))
        elif (isinstance(json_JWS, str)):
            json_web_signature = jws.JWS(json_JWS)
            json_JWS = loads(json_JWS)

        if json_JWS.get("header", False):  # Only one signature
            if (verify(json_web_signature, json_JWS["header"])):
                return True
            return False
        elif json_JWS.get("signatures", False):  # Multiple signatures
            signatures = json_JWS["signatures"]
            for signature in signatures:
                if (verify(json_web_signature, signature["header"])):
                    return True
        return False
    except Exception as e:
        debug_log.info("M:", repr(e))
        return False


def header_fix(malformed_dictionary):  # We do not check if its malformed, we expect it to be.
    if malformed_dictionary.get("signature", False):
        malformed_dictionary["header"] = loads(malformed_dictionary["header"])
        return malformed_dictionary
    elif malformed_dictionary.get("signatures", False):
        sigs = malformed_dictionary["signatures"]
        for signature in sigs:
            if isinstance(signature["header"], str):
                signature["header"] = loads(signature["header"])
        return malformed_dictionary
    raise ValueError("Received dictionary was not expected type.")

class VerifySLR(Resource):
    def __init__(self):
        super(VerifySLR, self).__init__()
        am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        timeout = current_app.config["TIMEOUT"]

        self.AM = AccountManagerHandler(am_url, am_user, am_password, timeout)
        self.Helpers = Helpers(current_app.config)
        self.query_db = self.Helpers.query_db

    @error_handler
    def post(self):

        debug_log.info(dumps(request.json, indent=2))

        sq.task("Load SLR to object")
        slr = request.json["slr"]
        debug_log.info("{} {}".format("SLR STORE:\n", slr))

        sq.task("Load slr payload as object")
        payload = slr["payload"]
        debug_log.info("{} {}".format("Before Fix:", payload))

        sq.task("Fix possible incorrect padding in payload")
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        debug_log.info("{} {}".format("After Fix :", payload))

        sq.task("Decode payload and store it into object")
        content = decode(payload.encode())

        sq.task("Load decoded payload as python dict")
        payload = loads(loads(content.decode("utf-8")))  # TODO: Figure out why we get str out of loads the first time?
        debug_log.info(payload)
        debug_log.info(type(payload))

        sq.task("Fetch link_id from decoded payload")
        slr_id = payload["link_id"]

        try:
            ##
            # Verify SLR with key from Service_Components Management
            ##
            sq.task("Load account_id from database")
            for code_json in self.query_db("select * from session_store where code = ?;", [request.json["data"]["code"]]):
                debug_log.debug("{}  {}".format(type(code_json), code_json))
                account_id = loads(code_json["json"])["account_id"]


            debug_log.info("################Verify########################")
            debug_log.info(dumps(request.json))
            debug_log.info("########################################")

            sq.task("Load slr and code from json payload")
            slr = request.json["slr"]
            code = request.json["data"]["code"]

            sq.send_to("Account Manager", "Verify SLR at Account Manager.")
            reply = self.AM.verify_slr(payload, code, slr, account_id)
            if reply.ok:
                sq.reply_to("Service_Components Mgmnt", "201, SLR VERIFIED")
                debug_log.info(reply.text)
                return reply.text, reply.status_code
            else:
                raise DetailedHTTPException(status=reply.status_code,
                                            detail={"msg": "Something went wrong while verifying SLR at Account Manager",
                                                    "content": reply.json()},
                                            title = reply.reason
                                            )
        except DetailedHTTPException as e:
            raise e

        except Exception as e:
            raise DetailedHTTPException(status=501, detail="Verifying SLR failed for unknown reason, access is denied.")


api.add_resource(VerifySLR, '/verify')
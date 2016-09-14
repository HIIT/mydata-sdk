# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
import traceback
from base64 import urlsafe_b64decode as decode
from json import loads, dumps, load, dump
from requests import post
from uuid import uuid4 as guid

from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import Sequences
from flask import request, abort, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from helpers import Helpers
from jwcrypto import jws, jwk

api_Service_Mgmnt = Blueprint("api_Service_Mgmnt", __name__)

CORS(api_Service_Mgmnt)
api = Api()
api.init_app(api_Service_Mgmnt)
logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

sq = Sequences("Service_Components Mgmnt", {})

'''


'''


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log.info("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class GenCode(Resource):
    def __init__(self):
        super(GenCode, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.storeCode = self.helpers.storeCode

    @error_handler
    def get(self):
        try:
            sq.task("Generate code")
            code = str(guid())
            code_storage = {code: "{}{}".format("!", code)}
            sq.task("Store code in db")
            self.storeCode(code_storage)
            sq.reply_to("Operator_Components Mgmnt", "Returning code")
            return {'code': code}
        except Exception as e:
            raise DetailedHTTPException(exception=e,
                                        detail={"msg": "Most likely storing code failed.", "code_json": code_storage},
                                        title="Failure in GenCode endpoint",
                                        trace=traceback.format_exc(limit=100).splitlines())


class UserAuthenticated(Resource):
    def __init__(self):
        super(UserAuthenticated, self).__init__()
        keysize = current_app.config["KEYSIZE"]
        cert_key_path = current_app.config["CERT_KEY_PATH"]
        Service_ID = "SRVMGNT-RSA-{}".format(keysize)
        gen = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}
        gen2 = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}

        gen3 = {"generate": "RSA", "size": keysize, "kid": Service_ID}
        self.service_key = jwk.JWK(**gen3)
        try:
            with open(cert_key_path, "r") as cert_file:
                service_key2 = jwk.JWK(**loads(load(cert_file)))
                self.service_key = service_key2
        except Exception as e:
            debug_log.error(e)
            with open(cert_key_path, "w+") as cert_file:
                dump(self.service_key.export(), cert_file, indent=2)
        service_cert = self.service_key.export_public()
        self.token_key = self.service_key

        templ = {Service_ID: {"cr_keys": loads(self.token_key.export_public())}}
        protti = {"alg": "RS256"}
        headeri = {"kid": Service_ID, "jwk": loads(self.service_key.export_public())}

        self.service_url = current_app.config["SERVICE_URL"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        try:
            debug_log.info(request.json)
            user_id = request.json["user_id"]
            code = request.json["code"]

            sq.task("Generate surrogate_id.")
            surrogate_id = "{}_{}".format(str(guid()), code)

            sq.task("Link code to generated surrogate_id")
            self.helpers.add_surrogate_id_to_code(request.json["code"], surrogate_id)
            data = {"surrogate_id": surrogate_id, "code": request.json["code"],
                    "token_key": loads(self.service_key.export_public())}

            sq.send_to("Service_Components", "Send surrogate_id to Service_Components")
            endpoint = "/api/1.2/slr/link"
            content_json = {"code": code, "surrogate_id": surrogate_id}
            result_service = post("{}{}".format(self.service_url, endpoint), json=content_json)
            if not result_service.ok:
                raise DetailedHTTPException(status=result_service.status_code,
                                            detail={
                                                "msg": "Something went wrong while posting to Service_Components for /link",
                                                "Error from Service_Components": loads(result_service.text)},
                                            title=result_service.reason)

            sq.send_to("Operator_Components Mgmnt", "Send Operator_Components request to make SLR")
            endpoint = "/api/1.2/slr/link"
            result = post("{}{}".format(self.operator_url, endpoint), json=data)
            debug_log.info("####slr/link reply from operator: {}\n{}".format(result.status_code, result.text))
            if not result.ok:
                raise DetailedHTTPException(status=result.status_code,
                                            detail={
                                                "msg": "Something went wrong while posting to Operator_SLR for /link",
                                                "Error from Operator_SLR": loads(result.text)},
                                            title=result.reason)

        except DetailedHTTPException as e:
            e.trace = traceback.format_exc(limit=100).splitlines()
            raise e
        except Exception as e:
            raise DetailedHTTPException(exception=e,
                                        detail="Something failed in generating and delivering Surrogate_ID.",
                                        trace=traceback.format_exc(limit=100).splitlines())


class SignInRedirector(Resource):
    def __init__(self):
        super(SignInRedirector, self).__init__()
        self.service_url = current_app.config["SERVICE_URL"]
        self.helpers = Helpers(current_app.config)

    @error_handler
    def post(self):

        debug_log.info(request.json)
        code = request.json

        sq.task("Verify code from Operator_Components")
        if self.helpers.verifyCode(code["code"]):
            try:
                sq.send_to("Service_Components", "Redirect login to Service_Components")
                endpoint = "/api/1.2/slr/login"
                result = post("{}{}".format(self.service_url, endpoint), json=code)
                if not result.ok:
                    raise DetailedHTTPException(status=result.status_code,
                                                detail={
                                                    "msg": "Something went wrong while redirecting verified code to Service_Components",
                                                    "Error from Service_Components": loads(result.text)},
                                                title=result.reason)
            except DetailedHTTPException as e:
                e.trace = traceback.format_exc(limit=100).splitlines()
                raise e
            except Exception as e:
                raise DetailedHTTPException(exception=e,
                                            detail="Failed to POST code/user to Service_Components's /login",
                                            trace=traceback.format_exc(limit=100).splitlines())
        else:
            abort(403)


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


class StoreSLR(Resource):
    def __init__(self):
        super(StoreSLR, self).__init__()
        keysize = current_app.config["KEYSIZE"]
        cert_key_path = current_app.config["CERT_KEY_PATH"]
        Service_ID = "SRVMGNT-RSA-{}".format(keysize)
        gen = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}
        gen2 = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}

        gen3 = {"generate": "RSA", "size": keysize, "kid": Service_ID}
        self.service_key = jwk.JWK(**gen3)
        try:
            with open(cert_key_path, "r") as cert_file:
                service_key2 = jwk.JWK(**loads(load(cert_file)))
                self.service_key = service_key2
        except Exception as e:
            debug_log.error(e)
            with open(cert_key_path, "w+") as cert_file:
                dump(self.service_key.export(), cert_file, indent=2)
        service_cert = self.service_key.export_public()
        self.token_key = self.service_key  #

        templ = {Service_ID: {"cr_keys": loads(self.token_key.export_public())}}
        self.protti = {"alg": "RS256"}
        self.headeri = {"kid": Service_ID, "jwk": loads(self.service_key.export_public())}

        self.service_url = current_app.config["SERVICE_URL"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        try:
            debug_log.info(dumps(request.json, indent=2))

            sq.task("Load SLR to object")
            slr = request.json["slr"]
            debug_log.info("SLR STORE:\n", slr)

            sq.task("Load slr payload as object")
            payload = slr["payload"]
            payload = slr["payload"]
            debug_log.info("Before Fix:{}".format(payload))

            sq.task("Fix possible incorrect padding in payload")
            payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
            debug_log.info("After Fix :{}".format(payload))

            sq.task("Decode payload and store it into object")
            debug_log.info(payload.encode())
            content = decode(payload.encode())

            sq.task("Load decoded payload as python dict")
            payload = loads(
                loads(content.decode("utf-8")))  # TODO: Figure out why we get str out of loads the first time?
            debug_log.info(payload)
            debug_log.info(type(payload))

            sq.task("Fetch surrogate_id from decoded payload")
            surrogate_id = payload["surrogate_id"].encode()
            debug_log.info(content)

            sq.task("Load code from json payload")
            code = request.json["data"]["code"].encode()

            sq.task("Verify surrogate_id and code")
            debug_log.info("Surrogate was found: {}".format(self.helpers.verifySurrogate(code, surrogate_id)))

        except Exception as e:
            raise DetailedHTTPException(title="Verifying Surrogate ID failed",
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

        try:
            sq.task("Create empty JSW object")
            jwssa = jws.JWS()
            debug_log.info("SLR R:\n", loads(dumps(slr)))
            debug_log.info(slr["header"]["jwk"])

            sq.task("Deserialize slr to JWS object created before")
            jwssa.deserialize(dumps(slr))

            sq.task("Load JWK used to sign JWS from the slr headers into an object")
            sign_key = jwk.JWK(**slr["header"]["jwk"])

            sq.task("Verify SLR was signed using the key shipped with it")
            debug_log.info(verifyJWS(slr))
            verify = jwssa.verify(sign_key)  # Verifying changes the state of this object
        except Exception as e:
            raise DetailedHTTPException(title="Verifying JWS signature failed",
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

        try:
            sq.task("Fix possible serialization errors in JWS")
            faulty_JSON = loads(jwssa.serialize(
                compact=False))  # For some reason serialization messes up "header" from "header": {} to "header": "{}"
            faulty_JSON["header"] = faulty_JSON["header"]

            sq.task("Add our signature in the JWS")
            jwssa.add_signature(self.service_key, alg="RS256", header=dumps(self.headeri), protected=dumps(self.protti))

            sq.task("Fix possible header errors")
            fixed = header_fix(loads(jwssa.serialize(compact=False)))
            debug_log.info("{}\n{}\n{}".format("Verified and Signed Signature:\n", dumps(fixed, indent=3),
                                               "\n###### END OF SIGNATURE #######"))

            sq.task("Create template for verifying JWS at Operator_Components")
            req = {"data": {"code": code}, "slr": fixed}
            debug_log.info(dumps(req, indent=2))
        except Exception as e:
            raise DetailedHTTPException(exception=e,
                                        title="JWS fix and subsequent signing of JWS with out key failed.",
                                        trace=traceback.format_exc(limit=100).splitlines())

        sq.send_to("Operator_Components Mgmnt", "Verify SLR(JWS)")
        endpoint = "/api/1.2/slr/verify"
        result = post("{}{}".format(self.operator_url, endpoint), json=req)
        debug_log.info(result.status_code)

        if result.ok:
            sq.task("Store SLR into db")
            store = loads(loads(result.text))
            debug_log.debug(dumps(store, indent=2))
            self.helpers.storeJSON({store["data"]["surrogate_id"]: store})
            endpoint = "/api/1.2/slr/store_slr"
            result = post("{}{}".format(self.service_url, endpoint), json=store)  # Send copy to Service_Components
        else:
            debug_log.debug(result.reason)
            raise DetailedHTTPException(status=result.status_code,
                                        detail={"msg": "Something went wrong while verifying SLR with Operator_SLR.",
                                                "Error from Operator_SLR": loads(result.text)},
                                        title=result.reason)

    @timeme
    @error_handler
    def get(self):  # Fancy but only used for testing. Should be disabled/removed in production.
        sq.task("Debugging endpoint, fetch SLR's from db and return")
        jsons = {"jsons": {}}
        counter = 0
        for storage_row in self.helpers.query_db("select * from storage;"):
            debug_log.info(storage_row["json"])
            jsons["jsons"][storage_row["surrogate_id"]] = loads(storage_row["json"])
            counter = +1

        sq.reply_to("Operator_Components Mgmnt", "Return SLR's from db")
        return jsons


api.add_resource(GenCode, '/code')
api.add_resource(SignInRedirector, '/login')
api.add_resource(UserAuthenticated, '/auth')
api.add_resource(StoreSLR, '/slr')

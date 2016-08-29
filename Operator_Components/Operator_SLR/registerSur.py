# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
from json import loads, dumps, load, dump
from uuid import uuid4 as guid
from flask import request, Blueprint, current_app
from flask_restful import Resource, Api
from requests import post
from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import ServiceRegistryHandler, Sequences
from helpers import AccountManagerHandler, Helpers
from jwcrypto import jwk
import logging

api_SLR_RegisterSur = Blueprint("api_SLR_RegisterSur", __name__)
from flask_cors import CORS
CORS(api_SLR_RegisterSur)
api = Api()
api.init_app(api_SLR_RegisterSur)

logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")
#logger.setLevel(logging.INFO)

sq = Sequences("Operator_Components Mgmnt", {})

'''
Service_Components Mgmnt->Operator_Components Mgmnt: Send Operator_Components request to make SLR
Operator_Components Mgmnt->Operator_Components Mgmnt: Load json payload as object
Operator_Components Mgmnt->Operator_Components Mgmnt: Load account_id and service_id from database
Operator_Components Mgmnt->Operator_Components Mgmnt: Verify surrogate_id and token_key exist
Operator_Components Mgmnt->Operator_Components Mgmnt: Fill template for Account Mgmnt
Operator_Components Mgmnt->Account Manager: Sign SLR at Account Manager
Operator_Components Mgmnt->Service_Components Mgmnt: Send created and signed SLR to Service_Components Mgnt

'''



class RegisterSur(Resource):
    def __init__(self):
        super(RegisterSur, self).__init__()
        print(current_app.config)
        keysize = current_app.config["KEYSIZE"]
        cert_key_path = current_app.config["CERT_KEY_PATH"]
        self.request_timeout = current_app.config["TIMEOUT"]

        SUPER_DEBUG = True

        account_id = "ACC-ID-RANDOM"
        user_account_id = account_id + "_" + str(guid())

        # Keys need to come from somewhere else instead of being generated each time.
        gen = {"generate": "EC", "cvr": "P-256", "kid": user_account_id}
        gen3 = {"generate": "RSA", "size": keysize, "kid": account_id}
        operator_key = jwk.JWK(**gen3)
        try:
            with open(cert_key_path, "r") as cert_file:
                operator_key2 = jwk.JWK(**loads(load(cert_file)))
                operator_key = operator_key2
        except Exception as e:
            print(e)
            with open(cert_key_path, "w+") as cert_file:
                dump(operator_key.export(), cert_file, indent=2)

        # Template to send the key to key server
        template = {account_id: {"cr_keys": loads(operator_key.export_public()),
                                 "token_keys": loads(operator_key.export_public())
                                 }
                    }
        # post("http://localhost:6666/key", json=template)

        self.payload = \
            {
                "version": "1.2",
                "link_id": "",
                "operator_id": account_id,
                "service_id": "SRV-SH14W4S3",  # How do we know this?
                "surrogate_id": "",
                "token_key": "",
                "operator_key": loads(operator_key.export_public()),
                "cr_keys": "",
                "created": ""  # time.time(),
            }
        debug_log.info(dumps(self.payload, indent=3))

        protti = {"alg": "RS256"}
        headeri = {"kid": user_account_id, "jwk": loads(operator_key.export_public())}
        self.service_registry_handler = ServiceRegistryHandler()
        am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        timeout = current_app.config["TIMEOUT"]
        self.AM = AccountManagerHandler(am_url, am_user, am_password, timeout)

        self.Helpers = Helpers(current_app.config)
        self.query_db = self.Helpers.query_db

    @error_handler
    def post(self):
        try:
            debug_log.info(dumps(request.json))
            sq.task("Load json payload as object")
            js = request.json

            sq.task("Load account_id and service_id from database")
            for code_json in self.query_db("select * from session_store where code = ?;", [js["code"]]):
                debug_log.debug("{}  {}".format(type(code_json), code_json))
                account_id = loads(code_json["json"])["account_id"]
                self.payload["service_id"] = loads(code_json["json"])["service_id"]
            # Check Surrogate_ID exists.
            # Fill token_key
            try:
                sq.task("Verify surrogate_id and token_key exist")
                self.payload["surrogate_id"] = js["surrogate_id"]
                self.payload["token_key"] = {"key": js["token_key"]}
            except Exception as e:
                raise DetailedHTTPException(exception=e,
                                            detail={"msg": "Received Invalid JSON that may not contain surrogate_id",
                                                    "json": js})

            # Create template
            self.payload["link_id"] = str(guid())
            # TODO: Currently you can generate endlessly new slr even if one exists already
            sq.task("Fill template for Account Mgmnt")
            template = {"code": js["code"],
                        "data":{
                            "slr": {
                                "type": "ServiceLinkRecord",
                                "attributes": self.payload,
                            },
                                "surrogate_id": {
                                    "type": "SurrogateId",
                                    "attributes":{
                                        "surrogate_id": self.payload["surrogate_id"],
                                        "service_id": self.payload["service_id"],
                                        "account_id": account_id
                                    }
                                }
                            },
                         }



            debug_log.info("###########Template for Account Manager#")
            debug_log.info(dumps(template, indent=3))
            debug_log.info("########################################")
            sq.send_to("Account Manager", "Sign SLR at Account Manager")
            reply = self.AM.sign_slr(template, account_id)
            debug_log.info(dumps(reply, indent=2))

            # Parse JSON form Account Manager to format Service_Mgmnt understands.
            try:
                req = {"data":
                           {"code": js["code"],
                            },
                       "slr": reply["data"]["slr"]["attributes"]["slr"]
                       }

                debug_log.info("SLR O: {}".format(dumps(req, indent=3)))
            except Exception as e:
                raise DetailedHTTPException(exception=e, detail="Parsing JSON form Account Manager to format Service_Mgmnt understands has failed.")



            try:
                sq.send_to("Service_Components Mgmnt","Send created and signed SLR to Service_Components Mgnt")
                endpoint = "/api/1.2/slr/slr"
                service_url = self.service_registry_handler.getService_url(self.payload["service_id"].encode())
                debug_log.info("Service_ulr = {}, type: {}".format(service_url, type(service_url)))
                response = post("{}{}".format(service_url, endpoint), json=req, timeout=self.request_timeout)
                debug_log.info("Request sent.")
                if not response.ok:
                    raise DetailedHTTPException(status=response.status_code,
                                                detail={"Error from Service_Components Mgmnt": loads(response.text)},
                                                title=response.reason)
            except DetailedHTTPException as e:
                raise e
            except Exception as e:
                raise DetailedHTTPException(exception=e, detail="Sending SLR to service has failed")


        except DetailedHTTPException as e:
            raise e
        except Exception as e:
            raise DetailedHTTPException(title="Creation of SLR has failed.", exception=e)

api.add_resource(RegisterSur, '/link')
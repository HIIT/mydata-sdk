# -*- coding: utf-8 -*-
from signed_requests.signed_request_auth import SignedRequest

__author__ = 'alpaloma'
from flask import Blueprint, current_app, request
from helpers import Helpers
import requests
from json import dumps, loads
from DetailedHTTPException import error_handler
from flask_restful import Resource, Api
import logging
from jwcrypto import jwk
from Templates import Sequences
debug_log = logging.getLogger("debug")
logger = logging.getLogger("sequence")
api_Sink_blueprint = Blueprint("api_Sink_blueprint", __name__)
api = Api()
api.init_app(api_Sink_blueprint)

sq = Sequences("Service_Components Mgmnt (Sink)", {})
# import xmltodict
# @api.representation('application/xml')
# def output_xml(data, code, headers=None):
#     if isinstance(data, dict):
#         xm = {"response": data}
#         resp = make_response(xmltodict.unparse(xm, pretty=True), code)
#         resp.headers.extend(headers)
#         return resp

class Status(Resource):
    @error_handler
    def get(self):
        status = {"status": "running", "service_mode": "Sink"}
        return status

class DataFlow(Resource):
    def __init__(self):
        super(DataFlow, self).__init__()
        self.service_url = current_app.config["SERVICE_URL"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.helpers = Helpers(current_app.config)

    @error_handler
    def post(self):  # TODO Make this a GET
        def renew_token(operator_url, record_id):
            sq.task("Renewing Auth Token.")
            token = requests.get(
                "{}/api/1.2/cr/auth_token/{}".format(operator_url, record_id))  # TODO Get api path from some config?
            debug_log.info("{}, {}, {}, {}".format(token.url, token.reason, token.status_code, token.text))
            store_dict = {cr_id: dumps(loads(token.text.encode()))}
            self.helpers.storeToken(store_dict)

        def step_1():
            params = request.json
            debug_log.info(params)
            debug_log.info(request.json)
            user_id = params["user_id"]
            cr_id = params["cr_id"]
            rs_id = params["rs_id"]
            sq.task("Get data_set_id from POST json")
            data_set_id = request.args.get("dataset_id", None)
            debug_log.info("data_set_id is ({}), cr_id is ({}), user_id ({}) and rs_id ({})"
                           .format(data_set_id, cr_id, user_id, rs_id))
            sq.task("Create request")
            req = {"we want": "data"}

            sq.task("Validate CR")
            cr = self.helpers.validate_cr(cr_id, surrogate_id=user_id)

            sq.task("Validate Request from UI")
            distribution_urls = self.helpers.validate_request_from_ui(cr, data_set_id, rs_id)

            # Fetch data request urls
            # Data request urls fetched.
            debug_log.info("Data request urls fetched.")
            return cr_id, cr, distribution_urls
        cr_id, cr, distribution_urls = step_1()

        sq.task("Validate Authorisation Token")
        surrogate_id = cr["cr"]["common_part"]["surrogate_id"]
        our_key = self.helpers.get_key()
        our_key_pub = our_key["pub"]
        tries = 3  # TODO: Get this from config
        while True:
            try:
                aud = self.helpers.validate_authorization_token(cr_id, surrogate_id, our_key_pub)
                break
            except ValueError as e:
                debug_log.exception(e)
                renew_token(self.operator_url, cr_id)
                if tries == 0:
                    raise EnvironmentError("Auth token validation failed and retry counter exceeded.")
                tries -= 1
            except TypeError as e:
                debug_log.exception(e)
                raise EnvironmentError("Token used too soon, halting.")

        # Most verifying and checking below is done in the validate_authorization_token function by jwcrypto
        # Fetch Authorisation Token related to CR from data storage by rs_id (cr_id?)
        # Check Integrity ( Signed by operator, Operator's public key can be found from SLR)
        # Check "Issued" timestamp
        # Check "Not Before" timestamp
        # Check "Not After" timestamp

        # Check that "sub" contains correct public key(Our key.)

        # OPT: Token expired
        # Get new Authorization token, start again from validation. # TODO: Make these steps work as functions that call the next step.

        # Check URL patterns in "aud" field
        # Check that fetched distribution urls can be found from "aud" field


        # Token validated
        debug_log.info("Auth Token Validated.")
        # With these two steps Sink has verified that it's allowed to make request.

        # Construct request
        sq.task("Construct request")
        # Select request URL from "aud" field
        # Add Authorisation Token to request
        # Request constructed.
        # Sign request
        # Fetch private key pair of public key specified in Authorisation Token's "sub" field.
        # Sign with fetched private key
        sq.task("Fetch key used to sign request")
        our_key_full = jwk.JWK()
        our_key_full.import_key(**our_key["key"])
        # Add signature to request
        # Request signed.
        # Request created.
        sq.send_to("Service_Components Mgmnt (Source)", "Data Request (PoP stuff)")
        # Make Data Request
        for url in distribution_urls:
            req = requests.get(url,
                           auth=SignedRequest(token=aud, sign_method=True, sign_path=True, key=our_key_full, protected=dumps(our_key["prot"])))
        debug_log.info("Made data request and received following data from Source: \n{}"
                       .format(dumps(loads(req.content), indent=2)))
        status = {"status": "ok", "service_mode": "Sink"}
        return status



api.add_resource(Status, '/init')
api.add_resource(DataFlow, '/dc')

#api.add_resource(DataFlow, '/user/<string:user_id>/consentRecord/<string:cr_id>/resourceSet/<string:rs_id>')
#"http://service_components:7000/api/1.2/sink_flow/user/95479a08-80cc-4359-ba28-b8ca23ff5572_53af88dc-33de-44be-bc30-e0826db9bd6c/consentRecord/cd431509-777a-4285-8211-95c5ac577537/resourceSet/http%3A%2F%2Fservice_components%3A7000%7C%7C9aebb487-0c83-4139-b12c-d7fcea93a3ad"
# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import os
import time
from json import loads, dumps

from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import sink_cr_schema, source_cr_schema, csr_schema, Sequences
from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from helpers import validate_json, SLR_tool, CR_tool, Helpers
from jwcrypto import jwk
from srv_tasks import get_AuthToken

api_Service_Mgmnt = Blueprint("api_Service_Mgmnt", __name__)  # TODO Rename this

CORS(api_Service_Mgmnt)
api = Api()
api.init_app(api_Service_Mgmnt)

file_store = os.path.abspath("file_store/") + "/"  # os.path.abspath seems to skim the / away from the end.

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

logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

sq = Sequences("Service_Components Mgmnt", {})


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class Install_CR(Resource):
    def __init__(self):
        super(Install_CR, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.db_path = current_app.config["DATABASE_PATH"]
    @error_handler
    def post(self):
        debug_log.info("arrived at Install_CR")
        cr_stuff = request.json

        debug_log.info(dumps(cr_stuff, indent=2))
        sq.task("Install CR/CSR")
        '''post

        :return: Returns 202
        '''

        sq.task("CR Received")
        crt = CR_tool()
        crt.cr = cr_stuff
        role = crt.get_role()
        errors = []
        sq.task("Verify CR format and mandatory fields")
        if role == "Source":
            debug_log.info("Source CR")
            debug_log.info(dumps(crt.get_CR_payload(), indent=2))
            debug_log.info(type(crt.get_CR_payload()))
            errors = validate_json(source_cr_schema, crt.get_CR_payload())
            for e in errors:
                raise DetailedHTTPException(detail={"msg": "Validating Source CR format and fields failed",
                                                    "validation_errors": errors},
                                            title="Failure in CR validation",
                                            status=400)


        else:
            debug_log.info("Sink CR")
            errors = validate_json(sink_cr_schema, crt.get_CR_payload())
            for e in errors:
                raise DetailedHTTPException(detail={"msg": "Validating Sink CR format and fields failed",
                                                    "validation_errors": errors},
                                            title="Failure in CR validation",
                                            status=400)

        debug_log.info(dumps(crt.get_CR_payload(), indent=2))
        debug_log.info(dumps(crt.get_CSR_payload(), indent=2))

        sq.task("Verify CR integrity")
        # SLR includes CR keys which means we need to get key from stored SLR and use it to verify this
        # 1) Fetch surrogate_id so we can query our database for slr
        surr_id = crt.get_surrogate_id()
        slr_id = crt.get_slr_id()
        debug_log.info("Fetched surr_id({}) and slr_id({})".format(surr_id, slr_id))

        slrt = SLR_tool()
        slrt.slr = self.helpers.get_slr(surr_id)
        verify_is_success = crt.verify_cr(slrt.get_cr_keys())
        if verify_is_success:
            sq.task("Verify CR is issued by authorized party")
            debug_log.info("CR was verified with key from SLR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CR failed",},
                                        title="Failure in CR verifying",
                                        status=403)

        sq.task("Verify CSR integrity")
        # SLR includes CR keys which means we need to get key from stored SLR and use it to verify this
        verify_is_success = crt.verify_csr(slrt.get_cr_keys())

        if verify_is_success:
            debug_log.info("CSR was verified with key from SLR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CSR failed",},
                                        title="Failure in CSR verifying",
                                        status=403)

        sq.task("Verify Status Record")

        sq.task("Verify CSR format and mandatory fields")
        errors = validate_json(csr_schema, crt.get_CSR_payload())
        for e in errors:
            raise DetailedHTTPException(detail={"msg": "Validating CSR format and fields failed",
                                                "validation_errors": errors},
                                        title="Failure in CSR validation",
                                        status=400)
        # 1) CSR has link to CR
        csr_has_correct_cr_id = crt.cr_id_matches_in_csr_and_cr()
        if csr_has_correct_cr_id:
            debug_log.info("Verified CSR links to CR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CSR cr_id == CR cr_id failed",},
                                        title="Failure in CSR verifying",
                                        status=403)
        # 2) CSR has link to previous CSR
        prev_csr_id_refers_to_null_as_it_should = crt.get_prev_record_id() == "null"
        if prev_csr_id_refers_to_null_as_it_should:
            debug_log.info("prev_csr_id_referred to null as it should.")
        else:
            # TODO: Check here that the csr chain is intact. and then continue.
            raise DetailedHTTPException(detail={"msg": "Verifying CSR previous_id == 'null' failed",},
                                        title="Failure in CSR verifying",
                                        status=403)

        verify_is_success = crt.verify_cr(slrt.get_cr_keys())
        if verify_is_success:
            sq.task("Verify CSR is issued by authorized party")
            debug_log.info("CSR was verified with key from SLR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CSR failed",},
                                        title="Failure in CSR verifying")
        # 5) Previous CSR has not been withdrawn
        # TODO Implement
        # If previous_id is null this step can be ignored.
        # Else fetch previous_id from db and check the status.

        sq.task("Store CR and CSR")
        store_dict = {
            "rs_id": crt.get_rs_id(),
            "csr_id": crt.get_csr_id(),
            "consent_status": crt.get_consent_status(),
            "previous_record_id": crt.get_prev_record_id(),
            "cr_id": crt.get_cr_id_from_cr(),
            "surrogate_id": surr_id,
            "slr_id": crt.get_slr_id(),
            "json": crt.cr["cr"]  # possibly store the base64 representation
        }
        self.helpers.storeCR_JSON(store_dict)

        store_dict["json"] = crt.cr["csr"]
        self.helpers.storeCSR_JSON(store_dict)
        if role == "Sink":
            debug_log.info("Requesting auth_token")
            get_AuthToken.delay(crt.get_cr_id_from_cr(), self.operator_url, current_app.config)
        return {"status": 200, "msg": "OK"}, 200


api.add_resource(Install_CR, '/add_cr')


# if __name__ == '__main__':
#    app.run(debug=True, port=7000, threaded=True)

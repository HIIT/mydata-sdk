# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
from json import dumps
from flask import request, Blueprint, current_app
from flask_restful import Resource, Api
from tasks import CR_installer
from helpers import AccountManagerHandler, Helpers
logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

from DetailedHTTPException import DetailedHTTPException, error_handler

api_CR_blueprint = Blueprint("api_CR_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)

from Templates import ServiceRegistryHandler, Consent_form_Out, Sequences

SH = ServiceRegistryHandler()
getService = SH.getService

sq = Sequences("Operator_Components Mgmnt", {})
Operator_public_key = {}
class ConsentFormHandler(Resource):
    def __init__(self):
        super(ConsentFormHandler, self).__init__()
        am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        timeout = current_app.config["TIMEOUT"]
        self.AM = AccountManagerHandler(am_url, am_user, am_password, timeout)

        self.Helpers = Helpers(current_app.config)



    @error_handler
    def get(self, account_id):
        '''get
        :return: Returns Consent form to UI for user input.
        '''
        _consent_form = Consent_form_Out
        service_ids = request.args

        sq.task("Fetch services")
        sink = getService(service_ids["sink"])
        _consent_form["sink"]["service_id"] = sink["name"]
        source = getService(service_ids["source"])
        _consent_form["source"]["service_id"] = source["name"]

        sq.task("Generate RS_ID")
        sq.task("Store RS_ID")

        rs_id = self.Helpers.gen_rs_id(source["name"])
        _consent_form["source"]["rs_id"] = rs_id

        sq.reply_to("UI", msg="Consent Form+RS_ID")
        return _consent_form

    @error_handler
    def post(self, account_id):
        '''post
        :return: Returns 201 when consent has been created
        '''
        debug_log.info(dumps(request.json, indent=2))


        _consent_form = request.json
        sink_srv_id = _consent_form["sink"]["service_id"]
        source_srv_id = _consent_form["source"]["service_id"]

        sq.task("Validate RS_ID")
        if self.Helpers.validate_rs_id(_consent_form["source"]["rs_id"]):  # Validate RS_ID (RS_ID exists and not used before)
            self.Helpers.store_consent_form(_consent_form)  # Store Consent Form
        else:
            raise DetailedHTTPException(title="RS_ID Validation error.",
                                        detail="RS_ID could not be validated.",
                                        status=403)

        sq.send_to("Account Mgmt", "GET surrogate_id & slr_id")
        sink_sur = self.AM.getSUR_ID(sink_srv_id, account_id)
        source_sur = self.AM.getSUR_ID(source_srv_id, account_id)
        debug_log.info("sink_sur = {}".format(sink_sur))
        debug_log.info("source_sur = {}".format(source_sur))
        slr_id_sink, surrogate_id_sink = sink_sur["data"]["surrogate_id"]["attributes"]["servicelinkrecord_id"], sink_sur["data"]["surrogate_id"]["attributes"]["surrogate_id"]  # Get slr and surrogate_id
        slr_id_source, surrogate_id_source = source_sur["data"]["surrogate_id"]["attributes"]["servicelinkrecord_id"], source_sur["data"]["surrogate_id"]["attributes"]["surrogate_id"] # One for Sink, one for Source

        # Generate common_cr for both sink and source.
        sq.task("Generate common CR")
        common_cr_source = self.Helpers.gen_cr_common(surrogate_id_source, _consent_form["source"]["rs_id"], slr_id_source)
        common_cr_sink = self.Helpers.gen_cr_common(surrogate_id_sink, _consent_form["source"]["rs_id"], slr_id_sink)

        sq.task("Generate ki_cr")
        mvcr = self.Helpers.Gen_ki_cr(self)  # This is silly, someone needs to define this. TODO Rename to ki_cr

        sq.task("Generate CR for sink")
        sink_cr = self.Helpers.gen_cr_sink(common_cr_sink, _consent_form)

        sq.task("Generate CR for source")
        source_cr = self.Helpers.gen_cr_source(common_cr_source, _consent_form,
                                          Operator_public_key)
        debug_log.info(sink_cr)
        debug_log.info(source_cr)
        sq.task("Generate CSR's")
        sink_csr = self.Helpers.gen_csr(surrogate_id_sink, sink_cr["cr"]["common_part"]["cr_id"], "Active",
                                        "null")
        source_csr = self.Helpers.gen_csr(surrogate_id_source, source_cr["cr"]["common_part"]["cr_id"], "Active",
                                          "null")

        sq.send_to("Account Mgmt", "Send CR/CSR to sign and store")
        result = self.AM.signAndstore(sink_cr, sink_csr, source_cr, source_csr, account_id)
        debug_log.info(dumps(result, indent=3))
        sink_cr = result["data"]["sink"]["consentRecord"]["attributes"]["cr"]
        sink_csr = result["data"]["sink"]["consentStatusRecord"]["attributes"]["csr"]

        source_cr = result["data"]["source"]["consentRecord"]["attributes"]["cr"]
        source_csr = result["data"]["source"]["consentStatusRecord"]["attributes"]["csr"]


        crs_csrs_payload = {"sink": {"cr": sink_cr, "csr": sink_csr},
                 "source": {"cr": source_cr, "csr": source_csr}}
        #logger.info("Going to Celery task")
        sq.send_to("Sink", "Post CR-Sink, CSR-Sink")
        sq.send_to("Source", "Post CR-Source, CSR-Source")

        debug_log.info(dumps(crs_csrs_payload, indent=2))
        CR_installer.delay(crs_csrs_payload, SH.getService_url(sink_srv_id), SH.getService_url(source_srv_id))
        return {"status": 201, "msg": "CREATED"}, 201




api.add_resource(ConsentFormHandler, '/consent_form/account/<string:account_id>')


# -*- coding: utf-8 -*-
from datetime import datetime
import time

__author__ = 'alpaloma'
import logging
import traceback
from json import dumps, loads

from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import ServiceRegistryHandler, Consent_form_Out, Sequences
from flask import request, Blueprint, current_app
from flask_restful import Resource, Api
from helpers import AccountManagerHandler, Helpers
from op_tasks import CR_installer
from requests import post
logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

api_CR_blueprint = Blueprint("api_CR_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)

sq = Sequences("Operator_Components Mgmnt", {})
Operator_public_key = {}
class ConsentFormHandler(Resource):
    def __init__(self):
        super(ConsentFormHandler, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        self.debug_mode = current_app.config["DEBUG_MODE"]
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}".format(repr(e)))
        self.SH = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"], current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.getService = self.SH.getService
        self.Helpers = Helpers(current_app.config)
        self.operator_url = current_app.config["OPERATOR_URL"]

    @error_handler
    def get(self, account_id):
        '''get
        :return: Returns Consent form to UI for user input.
        '''
        _consent_form = Consent_form_Out
        service_ids = request.args

        sq.task("Fetch services")
        sink = self.getService(service_ids["sink"])
        _consent_form["sink"]["service_id"] = sink["serviceId"]
        purposes = _consent_form["sink"]["dataset"][0]["purposes"] # TODO replace this once Service registry stops being stupid.
        _consent_form["sink"]["dataset"] = [] # Clear out template.
        for dataset in sink["serviceDescription"]["serviceDataDescription"][0]["dataset"]:
            item = {
                "dataset_id": dataset["datasetId"],
                "title": dataset["title"],
                "description": dataset["description"],
                "keyword": dataset["keyword"],
                "publisher": dataset["publisher"],
                "purposes": dataset["purpose"]
            }

            _consent_form["sink"]["dataset"].append(item)


        source = self.getService(service_ids["source"])
        _consent_form["source"]["service_id"] = source["serviceId"]
        _consent_form["source"]["dataset"] = [] # Clear out template.
        for dataset in source["serviceDescription"]["serviceDataDescription"][0]["dataset"]:
            item = {
                "dataset_id": dataset["datasetId"],
                "title": dataset["title"],
                "description": dataset["description"],
                "keyword": dataset["keyword"],
                "publisher": dataset["publisher"],
                "distribution": {
                    "distribution_id": dataset["distribution"][0]["distributionId"],
                    "access_url": "{}{}{}".format(source["serviceInstance"][0]["domain"],
                                                  source["serviceInstance"][0]["serviceAccessEndPoint"][
                                                      "serviceAccessURI"]
                                                  , dataset["distribution"][0]["accessURL"]),

                }
            }
            _consent_form["source"]["dataset"].append(item)


        sq.task("Generate RS_ID")

        source_domain = source["serviceInstance"][0]["domain"]
        source_access_uri = source["serviceInstance"][0]["serviceAccessEndPoint"]["serviceAccessURI"]
        rs_id = self.Helpers.gen_rs_id(source["serviceInstance"][0]["domain"])
        sq.task("Store RS_ID")
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

        sq.send_to("Account Manager", "GET surrogate_id & slr_id")
        try:
            sink_sur = self.AM.getSUR_ID(sink_srv_id, account_id)
            source_sur = self.AM.getSUR_ID(source_srv_id, account_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info("sink_sur = {}".format(sink_sur))
        debug_log.info("source_sur = {}".format(source_sur))

        slr_id_sink, surrogate_id_sink = sink_sur["data"]["surrogate_id"]["attributes"]["servicelinkrecord_id"],\
                                         sink_sur["data"]["surrogate_id"]["attributes"]["surrogate_id"]  # Get slr and surrogate_id

        slr_id_source, surrogate_id_source = source_sur["data"]["surrogate_id"]["attributes"]["servicelinkrecord_id"],\
                                             source_sur["data"]["surrogate_id"]["attributes"]["surrogate_id"] # One for Sink, one for Source

        sink_keys = self.Helpers.get_service_keys(surrogate_id_sink)
        try:
            sink_key = loads(sink_keys[0])
        except IndexError as e:
            raise DetailedHTTPException(status=500,
                                        title="Fetching service keys for sink has failed.",
                                        detail="Couldn't find keys for surrogate id ({}).".format(surrogate_id_sink),
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info("Sink keys:\n{}".format(dumps(sink_key, indent=2)))
        sink_pop_key = sink_key["pop_key"]
        # Generate common_cr for both sink and source.
        sq.task("Generate common CR")

        issued = int(time.time()) #datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = int(time.time()) #datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ") # TODO: This and not after are Optional, who says when to put them?
        not_after = int(time.time()+current_app.config["NOT_AFTER_INTERVAL"]) #datetime.fromtimestamp(time.time()+current_app.config["NOT_AFTER_INTERVAL"]).strftime("%Y-%m-%dT%H:%M:%SZ")
        operator_id = current_app.config["UID"]


        common_cr_source = self.Helpers.gen_cr_common(surrogate_id_source,
                                                      _consent_form["source"]["rs_id"],
                                                      slr_id_source,
                                                      issued,
                                                      not_before,
                                                      not_after,
                                                      source_srv_id,
                                                      operator_id,
                                                      "Source")

        common_cr_sink = self.Helpers.gen_cr_common(surrogate_id_sink,
                                                    _consent_form["source"]["rs_id"],
                                                    slr_id_sink,
                                                    issued,
                                                    not_before,
                                                    not_after,
                                                    sink_srv_id,
                                                    operator_id,
                                                    "Sink")

        sq.task("Generate ki_cr")
        ki_cr = self.Helpers.Gen_ki_cr(self)

        sq.task("Generate CR for sink")
        sink_cr = self.Helpers.gen_cr_sink(common_cr_sink, _consent_form, common_cr_source["cr_id"])

        sq.task("Generate CR for source")
        source_cr = self.Helpers.gen_cr_source(common_cr_source, _consent_form,
                                          sink_pop_key)

        sink_cr["cr"]["common_part"]["rs_description"] = source_cr["cr"]["common_part"]["rs_description"]

        debug_log.info(sink_cr)
        debug_log.info(source_cr)
        sq.task("Generate CSR's")
        sink_csr = self.Helpers.gen_csr(surrogate_id_sink, sink_cr["cr"]["common_part"]["cr_id"], "Active",
                                        "null")
        source_csr = self.Helpers.gen_csr(surrogate_id_source, source_cr["cr"]["common_part"]["cr_id"], "Active",
                                          "null")

        sq.send_to("Account Manager", "Send CR/CSR to sign and store")
        result = self.AM.signAndstore(sink_cr, sink_csr, source_cr, source_csr, account_id)

        # TODO: These are debugging and testing calls, remove them once operation is verified.
        if self.debug_mode:
            own_addr = self.operator_url #request.url_root.rstrip(request.script_root)
            debug_log.info("Our own address is: {}".format(own_addr))
            req = post(own_addr+"/api/1.2/cr/account_id/{}/service/{}/consent/{}/status/Disabled"
                          .format(surrogate_id_source, source_srv_id, common_cr_source["cr_id"]))

            debug_log.info("Changed csr status, request status ({}) reason ({}) and the following content:\n{}".format(
                req.status_code,
                req.reason,
                dumps(loads(req.content), indent=2)
            ))
            req = post(own_addr+"/api/1.2/cr/account_id/{}/service/{}/consent/{}/status/Active"
                          .format(surrogate_id_source, source_srv_id, common_cr_source["cr_id"]))
            debug_log.info("Changed csr status, request status ({}) reason ({}) and the following content:\n{}".format(
                req.status_code,
                req.reason,
                dumps(loads(req.content), indent=2)
            ))


        debug_log.info(dumps(result, indent=3))
        sink_cr = result["data"]["sink"]["consentRecord"]["attributes"]["cr"]
        sink_csr = result["data"]["sink"]["consentStatusRecord"]["attributes"]["csr"]

        source_cr = result["data"]["source"]["consentRecord"]["attributes"]["cr"]
        source_csr = result["data"]["source"]["consentStatusRecord"]["attributes"]["csr"]


        crs_csrs_payload = {"sink": {"cr": sink_cr, "csr": sink_csr},
                 "source": {"cr": source_cr, "csr": source_csr}}
        #logger.info("Going to Celery task")
        sq.send_to("Service_Components Mgmnt (Sink)", "Post CR-Sink, CSR-Sink")
        sq.send_to("Service_Components Mgmnt (Source)", "Post CR-Source, CSR-Source")

        debug_log.info(dumps(crs_csrs_payload, indent=2))
        CR_installer.delay(crs_csrs_payload, self.SH.getService_url(sink_srv_id), self.SH.getService_url(source_srv_id))
        return {"status": 201, "msg": "CREATED"}, 201




api.add_resource(ConsentFormHandler, '/consent_form/account/<string:account_id>')


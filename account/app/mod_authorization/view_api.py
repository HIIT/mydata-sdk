# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
import time
from flask import Blueprint, render_template, make_response, flash, session, request, jsonify, url_for, json
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse
from base64 import b64decode

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError
from app.mod_api_auth.controllers import requires_api_auth_user, get_account_id_by_api_key, provideApiKey, \
    requires_api_auth_sdk
from app.mod_blackbox.controllers import sign_jws_with_jwk, generate_and_sign_jws, get_account_public_key, \
    verify_jws_signature_with_jwk
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import ServiceLinkRecord, ServiceLinkStatusRecord, ConsentRecord, ConsentStatusRecord
from app.mod_authorization.controllers import sign_cr, sign_csr, store_cr_and_csr, get_auth_token_data
from app.mod_authorization.models import NewConsent

mod_authorization_api = Blueprint('authorization_api', __name__, template_folder='templates')

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class ConsentSignAndStore(Resource):
    @requires_api_auth_sdk
    def post(self, account_id, source_slr_id, sink_slr_id):

        try:
            endpoint = str(api.url_for(self, account_id=account_id, source_slr_id=source_slr_id, sink_slr_id=sink_slr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provideApiKey(endpoint=endpoint)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)

        try:
            source_slr_id = str(source_slr_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported source_slr_id", detail=repr(exp), source=endpoint)

        try:
            sink_slr_id = str(sink_slr_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported sink_slr_id", detail=repr(exp), source=endpoint)

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = NewConsent()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        ######
        # Source
        ######
        # Consent Record
        try:
            source_cr_payload = json_data['data']['source']['consentRecordPayload']['attributes']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch source_cr_payload from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got source_cr_payload: " + json.dumps(source_cr_payload))

        # Consent Status Record
        try:
            source_csr_payload = json_data['data']['source']['consentStatusRecordPayload']['attributes']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch source_csr_payload from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got source_csr_payload: " + json.dumps(source_csr_payload))

        ######
        # Sink
        ######
        # Consent Record
        try:
            sink_cr_payload = json_data['data']['sink']['consentRecordPayload']['attributes']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch sink_cr_payload from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got sink_cr_payload: " + json.dumps(sink_cr_payload))

        # Consent Status Record
        try:
            sink_csr_payload = json_data['data']['sink']['consentStatusRecordPayload']['attributes']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch sink_csr_payload from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got sink_csr_payload: " + json.dumps(sink_csr_payload))


        #####
        # IDs from CR and CSR payloads
        #####
        try:
            # Source CR
            try:
                source_cr_cr_id = source_cr_payload['common_part']['cr_id']
                source_cr_rs_id = source_cr_payload['common_part']['rs_id']
                source_cr_slr_id = source_cr_payload['common_part']['slr_id']
                source_cr_subject_id = source_cr_payload['common_part']['subject_id']
                source_cr_surrogate_id = source_cr_payload['common_part']['surrogate_id']
                source_cr_role = source_cr_payload['role_specific_part']['role']
            except Exception as exp:
                error_title = "Could not fetch IDs from Source CR payload"
                raise


            # Source CSR
            try:
                source_csr_surrogate_id = source_csr_payload['account_id']
                source_csr_cr_id = source_csr_payload['cr_id']
                source_csr_prev_record_id = source_csr_payload['prev_record_id']
                source_csr_record_id = source_csr_payload['record_id']
                source_csr_consent_status = source_csr_payload['consent_status']
            except Exception as exp:
                error_title = "Could not fetch IDs from Source CSR payload"
                raise

            # Sink CR
            try:
                sink_cr_cr_id = sink_cr_payload['common_part']['cr_id']
                sink_cr_rs_id = sink_cr_payload['common_part']['rs_id']
                sink_cr_slr_id = sink_cr_payload['common_part']['slr_id']
                sink_cr_subject_id = sink_cr_payload['common_part']['subject_id']
                sink_cr_surrogate_id = sink_cr_payload['common_part']['surrogate_id']
                sink_cr_role = sink_cr_payload['role_specific_part']['role']
            except Exception as exp:
                error_title = "Could not fetch IDs from Sink CR payload"
                raise

            # Sink CSR
            try:
                sink_csr_surrogate_id = sink_csr_payload['account_id']
                sink_csr_cr_id = sink_csr_payload['cr_id']
                sink_csr_prev_record_id = sink_csr_payload['prev_record_id']
                sink_csr_record_id = sink_csr_payload['record_id']
                sink_csr_consent_status = sink_csr_payload['consent_status']
            except Exception as exp:
                error_title = "Could not fetch IDs from Sink CSR payload"
                raise

        except Exception as exp:
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("IDs fetched from CR and CSR payloads")


        ######
        # Sign
        ####

        # Sign Source CR
        try:
            source_cr_signed, source_cr_issued = sign_cr(account_id=account_id, payload=source_cr_payload, endpoint=endpoint)
        except Exception as exp:
            logger.error("Could not sign Source's CR: " + repr(exp))
            raise
        else:
            logger.info("Source CR signed")

        # Sign Source CSR
        try:
            source_csr_signed, source_csr_issued = sign_csr(account_id=account_id, payload=source_csr_payload, endpoint=endpoint)
        except Exception as exp:
            logger.error("Could not sign Source's CSR: " + repr(exp))
            raise
        else:
            logger.info("Source CR signed")

        # Sign Sink CR
        try:
            sink_cr_signed, sink_cr_issued = sign_cr(account_id=account_id, payload=sink_cr_payload, endpoint=endpoint)
        except Exception as exp:
            logger.error("Could not sign Source's CR: " + repr(exp))
            raise
        else:
            logger.info("Sink's CR signed")

        # Sign Sink CSR
        try:
            sink_csr_signed, sink_csr_issued = sign_csr(account_id=account_id, payload=sink_csr_payload, endpoint=endpoint)
        except Exception as exp:
            logger.error("Could not sign Sink's CSR: " + repr(exp))
            raise
        else:
            logger.info("Sink's CSR signed")

        #########
        # Store #
        #########

        # Source SLR
        try:
            source_slr_entry = ServiceLinkRecord(
                surrogate_id=source_cr_surrogate_id,
                account_id=account_id,
                service_link_record_id=source_cr_slr_id
            )
        except Exception as exp:
            error_title = "Failed to create Source's Service Link Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Sink SLR
        try:
            sink_slr_entry = ServiceLinkRecord(
                surrogate_id=sink_cr_surrogate_id,
                account_id=account_id,
                service_link_record_id=sink_cr_slr_id
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Service Link Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Source CR
        try:
            source_cr_entry = ConsentRecord(
                consent_record=source_cr_signed,
                consent_id=source_cr_cr_id,
                surrogate_id=source_cr_surrogate_id,
                resource_set_id=source_cr_rs_id,
                service_link_record_id=source_cr_slr_id,
                subject_id=source_cr_subject_id,
                role=source_cr_role
            )
        except Exception as exp:
            error_title = "Failed to create Source's Consent Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Sink CR
        try:
            sink_cr_entry = ConsentRecord(
                consent_record=sink_cr_signed,
                consent_id=sink_cr_cr_id,
                surrogate_id=sink_cr_surrogate_id,
                resource_set_id=sink_cr_rs_id,
                service_link_record_id=sink_cr_slr_id,
                subject_id=sink_cr_subject_id,
                role=sink_cr_role
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Source CSR
        try:
            source_csr_entry = ConsentStatusRecord(
                status=source_csr_consent_status,
                consent_status_record=source_csr_signed,
                consent_record_id=source_csr_cr_id,
                issued_at=source_csr_issued,
                prev_record_id=source_csr_prev_record_id
            )
        except Exception as exp:
            error_title = "Failed to create Source's Consent Status Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Sink CSR
        try:
            sink_csr_entry = ConsentStatusRecord(
                status=sink_csr_consent_status,
                consent_status_record=sink_csr_signed,
                consent_record_id=sink_csr_cr_id,
                issued_at=sink_csr_issued,
                prev_record_id=sink_csr_prev_record_id
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Status Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Store CRs and CSRs
        try:
            db_meta = store_cr_and_csr(
                source_slr_entry=source_slr_entry,
                sink_slr_entry=sink_slr_entry,
                source_cr_entry=source_cr_entry,
                source_csr_entry=source_csr_entry,
                sink_cr_entry=sink_cr_entry,
                sink_csr_entry=sink_csr_entry,
                endpoint=endpoint
            )
        except Exception as exp:
            error_title = "Could not store Consent Record and Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise
        else:
            logger.info("Stored Consent Record and Consent Status Record")
            logger.debug("DB Meta: " + json.dumps(db_meta))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = {}

            response_data['data']['source'] = {}
            response_data['data']['source']['consentRecord'] = {}
            response_data['data']['source']['consentRecord']['type'] = "ConsentRecord"
            response_data['data']['source']['consentRecord']['attributes'] = {}
            response_data['data']['source']['consentRecord']['attributes']['cr'] = json.loads(source_cr_signed)

            response_data['data']['source']['consentStatusRecord'] = {}
            response_data['data']['source']['consentStatusRecord']['type'] = "ConsentStatusRecord"
            response_data['data']['source']['consentStatusRecord']['attributes'] = {}
            response_data['data']['source']['consentStatusRecord']['attributes']['csr'] = json.loads(source_csr_signed)

            response_data['data']['sink'] = {}
            response_data['data']['sink']['consentRecord'] = {}
            response_data['data']['sink']['consentRecord']['type'] = "ConsentRecord"
            response_data['data']['sink']['consentRecord']['attributes'] = {}
            response_data['data']['sink']['consentRecord']['attributes']['cr'] = json.loads(sink_cr_signed)

            response_data['data']['sink']['consentStatusRecord'] = {}
            response_data['data']['sink']['consentStatusRecord']['type'] = "ConsentStatusRecord"
            response_data['data']['sink']['consentStatusRecord']['attributes'] = {}
            response_data['data']['sink']['consentStatusRecord']['attributes']['csr'] = json.loads(sink_csr_signed)

        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class AuthorizationTokenData(Resource):
    @requires_api_auth_sdk
    def get(self, sink_cr_id):

        try:
            endpoint = str(api.url_for(self, sink_cr_id=sink_cr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provideApiKey(endpoint=endpoint)

        try:
            sink_cr_id = str(sink_cr_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported sink_cr_id", detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_cr_id: " + repr(sink_cr_id))

        # Init Sink's Consent Record Object
        try:
            sink_cr_entry = ConsentRecord(consent_id=sink_cr_id, role="Sink")
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        source_cr = {}
        sink_slr = {}
        try:
            source_cr, sink_slr = get_auth_token_data(sink_cr_object=sink_cr_entry)
        except Exception as exp:
            error_title = "Failed to get Authorization token data"
            logger.error(error_title + ": " + repr(exp))
            #raise
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("source_cr: " + json.dumps(source_cr))
            logger.debug("sink_slr: " + json.dumps(sink_slr))


        # Response data container
        try:
            response_data = {}
            response_data['data'] = {}

            response_data['data']['source'] = {}
            response_data['data']['source']['consentRecord'] = {}
            response_data['data']['source']['consentRecord']['type'] = "ConsentRecord"
            response_data['data']['source']['consentRecord']['attributes'] = {}
            response_data['data']['source']['consentRecord']['attributes']['cr'] = source_cr

            response_data['data']['sink'] = {}
            response_data['data']['sink']['serviceLinkRecord'] = {}
            response_data['data']['sink']['serviceLinkRecord']['type'] = "ServiceLinkRecord"
            response_data['data']['sink']['serviceLinkRecord']['attributes'] = {}
            response_data['data']['sink']['serviceLinkRecord']['attributes']['slr'] = sink_slr
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)




# Register resources
api.add_resource(ConsentSignAndStore, '/api/account/<string:account_id>/servicelink/<string:source_slr_id>/<string:sink_slr_id>/consent/', endpoint='mydata-authorization')
api.add_resource(AuthorizationTokenData, '/api/consent/<string:sink_cr_id>/authorizationtoken/', endpoint='mydata-authorizationtoken')

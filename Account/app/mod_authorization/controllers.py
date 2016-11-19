# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint
from time import time

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, ApiError, get_utc_time
from app.mod_blackbox.controllers import get_account_public_key, generate_and_sign_jws
from app.mod_database.helpers import get_db_cursor, get_last_csr_id, get_csr_ids, get_account_id_by_csr_id

# create logger with 'spam_application'
from app.mod_database.models import SurrogateId, ConsentRecord, ServiceLinkRecord, ConsentStatusRecord, Account

logger = get_custom_logger(__name__)


def get_account_id_by_cr(cr_id=None, endpoint="get_account_id_by_cr(cr_id, endpoint)"):
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")

    logger.info("Executing for: " + str(endpoint))

    ##
    # Account
    try:
        logger.info("Create Account object")
        account_entry = Account()
    except Exception as exp:
        error_title = "Failed to create Account object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("account_entry: " + account_entry.log_entry)

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Account table name")
        account_table_name = account_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Account table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Account table name: " + str(account_table_name))

    ##
    # ServiceLinkRecord
    try:
        logger.info("Create ServiceLinkRecord object")
        slr_entry = ServiceLinkRecord()
    except Exception as exp:
        error_title = "Failed to create ServiceLinkRecord object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("slr_entry: " + slr_entry.log_entry)

    # Get database table name for Consent Status Record
    try:
        logger.info("Get ServiceLinkRecord table name")
        slr_table_name = slr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get ServiceLinkRecord table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got ServiceLinkRecord table name: " + str(slr_table_name))

    ##
    # ConsentRecord
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord()
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("cr_entry: " + cr_entry.log_entry)

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Consent Record table name")
        cr_table_name = cr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Consent Record table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Consent Record table name: " + str(cr_table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Get Account ID
    try:
        logger.info("Get Account ID")
        cursor, account_id = get_account_id_by_csr_id(
            cursor=cursor,
            cr_id=cr_id,
            acc_table_name=account_table_name,
            slr_table_name=slr_table_name,
            cr_table_name=cr_table_name
        )
    except IndexError as exp:
        error_title = "Account ID Not Found"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to get Account ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Account ID: " + str(cr_table_name))
        return account_id


def sign_cr(account_id=None, payload=None, endpoint="sign_slr(account_id, payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if payload is None:
        raise AttributeError("Provide payload as parameter")

    logger.info("Signing Consent Record")

    # Get Account owner's public key
    try:
        account_public_key, account_kid = get_account_public_key(account_id=account_id)
        account_public_key = json.loads(account_public_key)
    except Exception as exp:
        logger.error("Could not get account owner's public key: " + repr(exp))
        raise ApiError(code=500, title="Failed to get account owner's public key", detail=repr(exp), source=endpoint)
    else:
        logger.info("Account owner's public key and kid fetched")

    # Sign cr
    try:
        cr_signed_json = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(payload))
    except Exception as exp:
        logger.error('Could not create Consent Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Consent Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('Consent Record created and signed')
        logger.debug('cr_signed_json: ' + cr_signed_json)
        try:
            logger.info("Converting signed CR from json to dict")
            cr_signed_dict = json.loads(cr_signed_json)
        except Exception as exp:
            logger.error('Could not convert signed CSR from json to dict: ' + repr(exp))
            raise ApiError(code=500, title="Failed to convert signed CSR from json to dict", detail=repr(exp), source=endpoint)
        else:
            logger.info('Converted signed CR from json to dict')
            logger.debug('cr_signed_dict: ' + json.dumps(cr_signed_dict))

        return cr_signed_dict


def sign_csr(account_id=None, payload=None, endpoint="sign_csr(account_id, payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if payload is None:
        raise AttributeError("Provide ssr_payload as parameter")

    logger.info("Signing Service Link Status Record")

    # Sign csr
    try:
        csr_signed_json = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(payload))
    except Exception as exp:
        logger.error('Could not create Consent Status Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Consent Status Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('Consent Status Record created and signed')
        logger.debug('csr_signed_json: ' + csr_signed_json)
        try:
            logger.info("Converting signed CSR from json to dict")
            csr_signed_dict = json.loads(csr_signed_json)
        except Exception as exp:
            logger.error('Could not convert signed CSR from json to dict: ' + repr(exp))
            raise ApiError(code=500, title="Failed to convert signed CSR from json to dict", detail=repr(exp), source=endpoint)
        else:
            logger.info('Converted signed CSR from json to dict')
            logger.debug('csr_signed_dict: ' + json.dumps(csr_signed_dict))

        return csr_signed_dict


def store_cr_and_csr(source_slr_entry=None, sink_slr_entry=None, source_cr_entry=None, source_csr_entry=None, sink_cr_entry=None, sink_csr_entry=None, endpoint="store_cr_and_csr()"):
    if source_slr_entry is None:
        raise AttributeError("Provide source_slr_entry as parameter")
    if sink_slr_entry is None:
        raise AttributeError("Provide sink_slr_entry as parameter")
    if source_cr_entry is None:
        raise AttributeError("Provide source_cr_entry as parameter")
    if source_csr_entry is None:
        raise AttributeError("Provide source_csr_entry as parameter")
    if sink_cr_entry is None:
        raise AttributeError("Provide sink_cr_entry as parameter")
    if sink_csr_entry is None:
        raise AttributeError("Provide sink_csr_entry as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    try:
        # Get Source's SLR from DB
        try:
            logger.info("Get Source SLR from database")
            cursor = source_slr_entry.from_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to fetch Source's SLR from DB"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("source_slr_entry: " + source_slr_entry.log_entry)

        # Get Sink's SLR from DB
        try:
            logger.info("Get Sink SLR from database")
            cursor = sink_slr_entry.from_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to fetch Sink's SLR from DB"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_slr_entry: " + sink_slr_entry.log_entry)

        # Get Source's SLR ID
        try:
            logger.info("Source SLR ID to Source CR")
            source_cr_entry.service_link_records_id = source_slr_entry.id
        except Exception as exp:
            error_title = "Failed to fetch Source's Service Link Record ID"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

        # Get Sink's SLR ID
        try:
            logger.info("Sink SLR ID to Sink CR")
            sink_cr_entry.service_link_records_id = sink_slr_entry.id
        except Exception as exp:
            error_title = "Failed to fetch Sink's Service Link Record ID"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        # Store Source CR
        try:
            logger.info("Store Source CR")
            cursor = source_cr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Source's Consent Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

        # Link Source's CSR with it's CR
        try:
            logger.info("Source CR ID to Source CSR")
            source_csr_entry.consent_records_id = source_cr_entry.id
        except Exception as exp:
            error_title = "Failed to link Source's CSR with it's CR"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug(source_csr_entry.log_entry)

        # Store Source CSR
        try:
            logger.info("Store Source CSR")
            cursor = source_csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Source's Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("source_csr_entry: " + source_csr_entry.log_entry)

        # Store Sink CR
        try:
            logger.info("Store Sink CR")
            cursor = sink_cr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Sink's Consent Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        # Link Sink's CSR with it's CR
        try:
            logger.info("Sink CR ID to Sink CSR")
            sink_csr_entry.consent_records_id = sink_cr_entry.id
        except Exception as exp:
            error_title = "Failed to link Sink's CSR with it's CR"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_csr_entry: " + sink_csr_entry.log_entry)

        # Store Sink CSR
        try:
            logger.info("Store Sink CSR")
            cursor = sink_csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Sink's Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_csr_entry: " + sink_csr_entry.log_entry)

        # Commit
        db.connection.commit()
    except Exception as exp:
        logger.debug('commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.debug('--> rollback')
        #raise ApiError(code=500, title="Failed to store CR's and CSR's", detail=repr(exp), source=endpoint)
        raise
    else:
        logger.info("CR's and CSR's commited")
        return source_cr_entry, source_csr_entry, sink_cr_entry, sink_csr_entry


def get_auth_token_data(sink_cr_object=None, endpoint="get_auth_token_data()"):
    if sink_cr_object is None:
        raise AttributeError("Provide sink_cr_object as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Get Sink's CR from DB
    try:
        logger.info("Get Sink's CR from DB")
        cursor = sink_cr_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Sink's CR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_object: " + sink_cr_object.log_entry)

    # Get required id's from Sink's CR
    try:
        logger.info("Get required id's from Sink's CR")
        sink_rs_id = str(sink_cr_object.resource_set_id)
        sink_slr_primary_key = str(sink_cr_object.service_link_records_id)
    except Exception as exp:
        error_title = "Failed to get id's from Sink's CR"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_rs_id: " + sink_rs_id)

    # Init Source's Consent Record Object
    try:
        logger.info("Init Source's Consent Record Object")
        source_cr_entry = ConsentRecord(resource_set_id=sink_rs_id, role="Source")
    except Exception as exp:
        error_title = "Failed to create Source's Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

    # Get Source's Consent Record from DB
    try:
        logger.info("Get Source's Consent Record from DB")
        cursor = source_cr_entry.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Source's CR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

    # Init Sink's Service Link Record Object
    try:
        logger.info("Init Sink's Service Link Record Object")
        sink_slr_entry = ServiceLinkRecord(id=sink_slr_primary_key)
    except Exception as exp:
        error_title = "Failed to create Source's Service Link Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_slr_entry: " + sink_slr_entry.log_entry)

    # Get Source's Consent Record from DB
    try:
        logger.info("Get Source's Consent Record from DB")
        cursor = sink_slr_entry.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Sink's SLR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_slr_entry: " + sink_slr_entry.log_entry)

    return source_cr_entry, sink_slr_entry


def get_last_cr_status(cr_id=None, endpoint="get_last_cr_status()"):
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Init Consent Record Object
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord(consent_id=cr_id)
        logger.info(cr_entry.log_entry)
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_entry: " + cr_entry.log_entry)

    # Get Consent Record from DB
    try:
        cursor = cr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry: " + cr_entry.log_entry)

    # Get Consent Record ID of cr_entry
    try:
        cr_entry_id = cr_entry.consent_id
    except Exception as exp:
        error_title = "Failed to get Consent Record ID from object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry_id: " + str(cr_entry_id))

    # Create Consent Status Record object
    try:
        csr_entry = ConsentStatusRecord()
    except Exception as exp:
        error_title = "Failed to create Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_entry: " + csr_entry.log_entry)

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Consent Status Record table name")
        csr_table_name = csr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Consent Status Record table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Consent Status Record table name: " + str(csr_table_name))

    # Get Consent Status Record ID
    try:
        cursor, csr_id = get_last_csr_id(cursor=cursor, cr_id=cr_id, table_name=csr_table_name)
    except IndexError as exp:
        error_title = "Consent Status Record not found from DB with given Consent Record ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to get last Consent Status Record ID from database"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_id: " + str(csr_id))

    # Append ID to Consent Status Record Object
    try:
        logger.info("Append ID to Consent Status Record object: " + csr_entry.log_entry)
        csr_entry.consent_status_record_id = csr_id
    except Exception as exp:
        error_title = "Failed to append ID to Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Appended ID to Consent Status Record object: " + csr_entry.log_entry)

    # Get Consent Status Record from DB
    try:
        cursor = csr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_entry: " + csr_entry.log_entry)

    return csr_entry


def add_csr(cr_id=None, csr_payload=None, endpoint="add_csr()"):
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if csr_payload is None:
        raise AttributeError("Provide csr_payload as parameter")

    ######
    # Base information
    ####
    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # IDs from CSR payload
    try:
        logger.info("Fetching IDs from CSR payload")
        csr_surrogate_id = csr_payload['surrogate_id']
        csr_cr_id = csr_payload['cr_id']
        csr_prev_record_id = csr_payload['prev_record_id']
        csr_record_id = csr_payload['record_id']
        csr_consent_status = csr_payload['consent_status']
        csr_issued = csr_payload['iat']
    except Exception as exp:
        error_title = "Could not fetch IDs from CSR payload"
        logger.error(error_title)
        raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Fetched IDs from CSR payload")

    # Verify that cr_id and csr_cr_id are the same
    if cr_id != csr_cr_id:
        error_title = "cr_id from URI and cr_id from payload are not identical"
        logger.error(error_title + " | cr_id from URI: " + str(cr_id) + ", cr_id from payload: " + str(csr_cr_id))
        raise ApiError(code=400, title=error_title, source=endpoint)
    else:
        logger.info("Identical IDs: cr_id from URI: " + str(cr_id) + ", cr_id from payload: " + str(csr_cr_id))


    ######
    # Account ID
    ####
    try:
        logger.info("Get Account ID by CSR_ID")
        account_id = get_account_id_by_cr(cr_id=cr_id, endpoint=endpoint)
    except Exception as exp:
        logger.error("Could not Account ID by CSR_ID: " + repr(exp))
        raise
    else:
        logger.info("account_id: " + str(account_id))

    ######
    # Sign
    ####
    # Sign CSR
    try:
        logger.info("Sign CSR")
        csr_signed = sign_csr(account_id=account_id, payload=csr_payload, endpoint=endpoint)
    except Exception as exp:
        logger.error("Could not sign Source's CSR: " + repr(exp))
        raise
    else:
        logger.info("Source CR signed")

    ###########
    # Entries #
    ###########
    # Existing Consent Record
    ###
    # Init Consent Record Object
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord(consent_id=cr_id)
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_entry: " + cr_entry.log_entry)

    # Get Consent Record from DB
    try:
        logger.info("Get Consent Record from DB")
        cursor = cr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry: " + cr_entry.log_entry)

    # Get primary key of Consent Record database entry
    try:
        logger.info("Get primary key of Consent Record database entry")
        cr_entry_primary_key = cr_entry.id
    except Exception as exp:
        error_title = "Failed to get primary key of Consent Record database entry"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry_primary_key: " + str(cr_entry_primary_key))

    # CSR
    try:
        logger.info("Create ConsentStatusRecord object")
        csr_entry = ConsentStatusRecord(
            consent_status_record_id=csr_record_id,
            status=csr_consent_status,
            consent_status_record=csr_signed,
            consent_record_id=cr_id,
            issued_at=int(csr_issued),
            prev_record_id=csr_prev_record_id,
            consent_records_id=int(cr_entry_primary_key)
        )
    except Exception as exp:
        error_title = "Failed to create Source's Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("csr_entry: " + csr_entry.log_entry)

    ###########
    # Store #
    ###########
    # CSR

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Consent Status Record table name")
        csr_table_name = csr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Consent Status Record table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Consent Status Record table name: " + str(csr_table_name))

    # Store CSR
    try:
        logger.info("Store ConsentStatusRecord")
        try:
            cursor = csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("csr_entry: " + csr_entry.log_entry)

        # Commit
        db.connection.commit()
    except Exception as exp:
        logger.error('Consent Status Record Commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.error('--> rollback')
        raise
    else:
        logger.info("Consent Status Record commited")

    return csr_entry


def get_csr(cr_id=None, csr_id=None, cursor=None):
    """
    Get one csr entry from database by Account ID and ID
    :param slr_id:
    :param cr_id:
    :param csr_id:
    :return: dict
    """
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if csr_id is None:
        raise AttributeError("Provide csr_id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = ConsentStatusRecord(consent_record_id=cr_id, consent_status_record_id=csr_id)
    except Exception as exp:
        error_title = "Failed to create csr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("csr object created: " + db_entry_object.log_entry)

    # Get csr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch csr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("csr fetched")
        logger.info("csr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_record_dict


def get_csrs(cr_id=None, last_csr_id=None):
    """
    Get all csr -entries related to service link record
    :param cr_id:
    :return: List of dicts
    """
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get CSR limit if necessary
    if last_csr_id is None:
        logger.info("No limiting CSR ID provided")
        csr_primary_key = None
    else:
        csr_limit_id = last_csr_id
        logger.info("csr_limit_id: " + str(csr_limit_id))

        # Get primary key of limiting CSR
        try:
            logger.info("Create CSR object")
            csr_entry = ConsentStatusRecord(consent_record_id=cr_id, consent_status_record_id=last_csr_id)
        except Exception as exp:
            error_title = "Failed to create csr object"
            logger.error(error_title + ": " + repr(exp))
            raise
        else:
            logger.debug("csr object created: " + csr_entry.log_entry)

        # Get csr from DB
        try:
            cursor = csr_entry.from_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to fetch csr from DB"
            logger.error(error_title + ": " + repr(exp))
            raise
        else:
            logger.info("csr fetched")
            logger.info("csr fetched from db: " + csr_entry.log_entry)

        # Get primary key of Consent Record database entry
        try:
            logger.info("Get primary key of Consent Record database entry")
            csr_primary_key = csr_entry.id
        except Exception as exp:
            error_title = "Failed to get primary key of Consent Record database entry"
            logger.error(error_title + ": " + repr(exp))
            raise

        logger.debug("csr_primary_key: " + str(csr_primary_key))

    # Get primary keys for csrs
    try:
        # Get table name
        logger.info("Create csr")
        db_entry_object = ConsentStatusRecord()
        logger.info(db_entry_object.log_entry)
        logger.info("Get table name")
        table_name = db_entry_object.table_name
        logger.info("Got table name: " + str(table_name))

        cursor, id_list = get_csr_ids(cursor=cursor, cr_id=cr_id, csr_primary_key=csr_primary_key, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get csrs from database
    logger.info("Get csrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting csr with cr_id: " + str(cr_id) + " csr_id: " + str(id))
        db_entry_dict = get_csr(cr_id=cr_id, csr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("csr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list



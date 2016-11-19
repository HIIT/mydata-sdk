# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, ApiError
from app.mod_api_auth.controllers import get_account_id_by_api_key
from app.mod_database.helpers import get_db_cursor, get_primary_keys_by_account_id, get_slr_ids, \
    get_slsr_ids, get_cr_ids, get_csr_ids

# create logger with 'spam_application'
from app.mod_database.models import Particulars, Contacts, Email, Telephone, Settings, EventLog, ServiceLinkRecord, \
    ServiceLinkStatusRecord, ConsentRecord, ConsentStatusRecord

logger = get_custom_logger(__name__)


def verify_account_id_match(account_id=None, api_key=None, account_id_to_compare=None, endpoint=None):
    """
    Verifies that provided account id matches with account id fetched with api key.

    :param account_id:
    :param api_key:
    :param endpoint:
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")

    # Get Account ID by Api-Key or compare to provided
    if api_key is not None:
        try:
            logger.info("Fetching Account ID by Api-Key")
            account_id_by_api_key = get_account_id_by_api_key(api_key=api_key)
        except Exception as exp:
            error_title = "Account ID not found with provided ApiKey"
            logger.error(error_title)
            raise ApiError(
                code=403,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )
        else:
            logger.info("account_id_by_api_key: " + str(account_id_by_api_key))
            account_id_to_compare = account_id_by_api_key
            error_title = "Authenticated Account ID not matching with Account ID that was provided with request"
    elif account_id_to_compare is not None:
        logger.info("account_id_to_compare provided as parameter")
        error_title = "Account ID in payload not matching with Account ID that was provided with request"

    # Check if Account IDs are matching
    logger.info("Check if Account IDs are matching")
    logger.info("account_id: " + str(account_id))
    logger.info("account_id_to_compare: " + str(account_id_to_compare))
    if str(account_id) != str(account_id_to_compare):
        logger.error(error_title)
        raise ApiError(
            code=403,
            title=error_title,
            source=endpoint
        )
    else:
        logger.info("Account IDs are matching")
        logger.info("account_id: " + str(account_id))
        logger.info("account_id_to_compare: " + str(account_id_to_compare))

    return True


##################################
##################################
# Particulars
##################################
##################################
def get_particular(account_id=None, id=None, cursor=None):
    """
    Get one particular entry from database by Account ID and Particulars ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        logger.info("Creating Particulars object")
        db_entry_object = Particulars(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create Particulars object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Particulars object created: " + db_entry_object.log_entry)

    # Get particulars from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Particulars from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Particulars fetched")
        logger.info("Particulars fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_particulars(account_id=None):
    """
    Get all Particulars -entries related to account
    :param account_id:
    :return: List of Particular dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create db_entry_object")
    db_entry_object = Particulars()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for particulars
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get Particulars from database
    logger.info("Get Particulars from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting particulars with particular_id: " + str(id))
        db_entry_dict = get_particular(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("Particulars object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def update_particular(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one particular entry at database identified by Account ID and Particulars ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Particulars(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create Particulars object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Particulars object created: " + db_entry_object.log_entry)

    # Get particulars from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Particulars from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Particulars fetched")
        logger.info("Particulars fetched from db: " + db_entry_object.log_entry)

    # Update Particulars object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("Particulars object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "lastname" in attributes:
        logger.info("Updating lastname")
        old_value = str(db_entry_object.lastname)
        new_value = str(attributes.get("lastname", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.lastname = new_value
        logger.info(db_entry_object.log_entry)

    if "firstname" in attributes:
        logger.info("Updating firstname")
        old_value = str(db_entry_object.firstname)
        new_value = str(attributes.get("firstname", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.firstname = new_value
        logger.info(db_entry_object.log_entry)

    if "img_url" in attributes:
        logger.info("Updating img_url")
        old_value = str(db_entry_object.img_url)
        new_value = str(attributes.get("img_url", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.img_url = new_value
        logger.info(db_entry_object.log_entry)

    if "date_of_birth" in attributes:
        logger.info("Updating date_of_birth")
        old_value = str(db_entry_object.date_of_birth)
        new_value = str(attributes.get("date_of_birth", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.date_of_birth = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update Particulars to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("Particulars updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


##################################
###################################
# Contacts
##################################
##################################
def get_contact(account_id=None, id=None, cursor=None):
    """
    Get one contact entry from database by Account ID and contact ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Contacts(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create contact object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contact object created: " + db_entry_object.log_entry)

    # Get contact from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch contact from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("contact fetched")
        logger.info("contact fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_contacts(account_id=None):
    """
    Get all contact -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create contact")
    db_entry_object = Contacts()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for contacts
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get contacts from database
    logger.info("Get contacts from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting contacts with contacts_id: " + str(id))
        db_entry_dict = get_contact(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("contact object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def add_contact(account_id=None, attributes=None, cursor=None):
    """
    Add one contacts entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Update contacts object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to add.")
        raise StandardError("Not adding empty entry to database")
    else:
        # log provided attributes
        for key, value in attributes.items():
            logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Create object
    try:
        db_entry_object = Contacts(
            account_id=account_id,
            address1=str(attributes.get("address1", "")),
            address2=str(attributes.get("address2", "")),
            postal_code=str(attributes.get("postalCode", "")),
            city=str(attributes.get("city", "")),
            state=str(attributes.get("state", "")),
            country=str(attributes.get("country", "")),
            type=str(attributes.get("type", "")),
            prime=str(attributes.get("primary", ""))
        )
    except Exception as exp:
        error_title = "Failed to create contacts object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contacts object created: " + db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.to_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to add contacts to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("contacts added")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def update_contact(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one contacts entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Contacts(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create contacts object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contacts object created: " + db_entry_object.log_entry)

    # Get contacts from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch contacts from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("contacts fetched")
        logger.info("contacts fetched from db: " + db_entry_object.log_entry)

    # Update contacts object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("contacts object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "address1" in attributes:
        logger.info("Updating address1")
        old_value = str(db_entry_object.address1)
        new_value = str(attributes.get("address1", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.address1 = new_value
        logger.info(db_entry_object.log_entry)

    if "address2" in attributes:
        logger.info("Updating address2")
        old_value = str(db_entry_object.address2)
        new_value = str(attributes.get("address2", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.address2 = new_value
        logger.info(db_entry_object.log_entry)

    if "postalCode" in attributes:
        logger.info("Updating postalCode")
        old_value = str(db_entry_object.postal_code)
        new_value = str(attributes.get("postalCode", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.postal_code = new_value
        logger.info(db_entry_object.log_entry)

    if "city" in attributes:
        logger.info("Updating city")
        old_value = str(db_entry_object.city)
        new_value = str(attributes.get("city", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.city = new_value
        logger.info(db_entry_object.log_entry)

    if "state" in attributes:
        logger.info("Updating state")
        old_value = str(db_entry_object.state)
        new_value = str(attributes.get("state", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.state = new_value
        logger.info(db_entry_object.log_entry)

    if "country" in attributes:
        logger.info("Updating country")
        old_value = str(db_entry_object.country)
        new_value = str(attributes.get("country", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.country = new_value
        logger.info(db_entry_object.log_entry)

    if "type" in attributes:
        logger.info("Updating type")
        old_value = str(db_entry_object.type)
        new_value = str(attributes.get("type", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.type = new_value
        logger.info(db_entry_object.log_entry)

    if "primary" in attributes:
        logger.info("Updating primary")
        old_value = str(db_entry_object.prime)
        new_value = str(attributes.get("primary", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.prime = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update contacts to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("contacts updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


##################################
###################################
# Emails
##################################
##################################
def get_email(account_id=None, id=None, cursor=None):
    """
    Get one email entry from database by Account ID and email ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Email(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create email object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("email object created: " + db_entry_object.log_entry)

    # Get email from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch email from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("email fetched")
        logger.info("email fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_emails(account_id=None):
    """
    Get all email -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create email")
    db_entry_object = Email()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for emails
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get emails from database
    logger.info("Get emails from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting emails with emails_id: " + str(id))
        db_entry_dict = get_email(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("email object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def add_email(account_id=None, attributes=None, cursor=None):
    """
    Add one email entry to database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Update emails object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to add.")
        raise StandardError("Not adding empty entry to database")
    else:
        # log provided attributes
        for key, value in attributes.items():
            logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Create object
    try:
        db_entry_object = Email(
            account_id=account_id,
            email=str(attributes.get("email", "")),
            type=str(attributes.get("type", "")),
            prime=str(attributes.get("primary", ""))
        )
    except Exception as exp:
        error_title = "Failed to create emails object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("emails object created: " + db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.to_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to add emails to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("emails added")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def update_email(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one email entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Email(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create email object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("email object created: " + db_entry_object.log_entry)

    # Get email from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch email from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("email fetched")
        logger.info("email fetched from db: " + db_entry_object.log_entry)

    # Update email object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("email object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "email" in attributes:
        logger.info("Updating email")
        old_value = str(db_entry_object.email)
        new_value = str(attributes.get("email", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.email = new_value
        logger.info(db_entry_object.log_entry)

    if "type" in attributes:
        logger.info("Updating type")
        old_value = str(db_entry_object.type)
        new_value = str(attributes.get("type", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.type = new_value
        logger.info(db_entry_object.log_entry)

    if "primary" in attributes:
        logger.info("Updating primary")
        old_value = str(db_entry_object.prime)
        new_value = str(attributes.get("primary", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.prime = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update email to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("email updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict




##################################
###################################
# Telephones (numbers)
##################################
##################################
def get_telephone(account_id=None, id=None, cursor=None):
    """
    Get one telephone entry from database by Account ID and telephone ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Telephone(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create telephone object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("telephone object created: " + db_entry_object.log_entry)

    # Get telephone from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch telephone from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("telephone fetched")
        logger.info("telephone fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_telephones(account_id=None):
    """
    Get all telephone -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create telephone")
    db_entry_object = Telephone()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for telephones
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get telephones from database
    logger.info("Get telephones from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting telephones with telephones_id: " + str(id))
        db_entry_dict = get_telephone(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("telephone object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def add_telephone(account_id=None, attributes=None, cursor=None):
    """
    Add one telephone entry to database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Update telephone object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to add.")
        raise StandardError("Not adding empty entry to database")
    else:
        # log provided attributes
        for key, value in attributes.items():
            logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Create object
    try:
        db_entry_object = Telephone(
            account_id=account_id,
            tel=str(attributes.get("tel", "")),
            type=str(attributes.get("type", "")),
            prime=str(attributes.get("primary", ""))
        )
    except Exception as exp:
        error_title = "Failed to create telephone object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("telephone object created: " + db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.to_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to add telephone to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("telephone added")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def update_telephone(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one telephone entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Telephone(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create telephone object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("telephone object created: " + db_entry_object.log_entry)

    # Get telephone from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch telephone from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("telephone fetched")
        logger.info("telephone fetched from db: " + db_entry_object.log_entry)

    # Update telephone object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("telephone object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "tel" in attributes:
        logger.info("Updating telephone")
        old_value = str(db_entry_object.tel)
        new_value = str(attributes.get("tel", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.tel = new_value
        logger.info(db_entry_object.log_entry)

    if "type" in attributes:
        logger.info("Updating type")
        old_value = str(db_entry_object.type)
        new_value = str(attributes.get("type", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.type = new_value
        logger.info(db_entry_object.log_entry)

    if "primary" in attributes:
        logger.info("Updating primary")
        old_value = str(db_entry_object.prime)
        new_value = str(attributes.get("primary", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.prime = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update telephone to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("telephone updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict



##################################
###################################
# Settings
##################################
##################################
def get_setting(account_id=None, id=None, cursor=None):
    """
    Get one setting entry from database by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Settings(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create setting object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("setting object created: " + db_entry_object.log_entry)

    # Get setting from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch setting from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("setting fetched")
        logger.info("setting fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_settings(account_id=None):
    """
    Get all setting -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create setting")
    db_entry_object = Settings()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for setting
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get setting from database
    logger.info("Get setting from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting setting with setting_id: " + str(id))
        db_entry_dict = get_setting(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("setting object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def add_setting(account_id=None, attributes=None, cursor=None):
    """
    Add one setting entry to database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Update setting object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to add.")
        raise StandardError("Not adding empty entry to database")
    else:
        # log provided attributes
        for key, value in attributes.items():
            logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Create object
    try:
        db_entry_object = Settings(
            account_id=account_id,
            key=str(attributes.get("key", "")),
            value=str(attributes.get("value", ""))
        )
    except Exception as exp:
        error_title = "Failed to create setting object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("setting object created: " + db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.to_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to add setting to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("setting added")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def update_setting(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one setting entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Settings(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create setting object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("setting object created: " + db_entry_object.log_entry)

    # Get setting from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch setting from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("setting fetched")
        logger.info("setting fetched from db: " + db_entry_object.log_entry)

    # Update setting object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("setting object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "key" in attributes:
        logger.info("Updating key")
        old_value = str(db_entry_object.key)
        new_value = str(attributes.get("key", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.key = new_value
        logger.info(db_entry_object.log_entry)

    if "value" in attributes:
        logger.info("Updating value")
        old_value = str(db_entry_object.value)
        new_value = str(attributes.get("value", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.value = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update setting to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("setting updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


##################################
###################################
# Event logs
##################################
##################################
def get_event_log(account_id=None, id=None, cursor=None):
    """
    Get one event_log entry from database by Account ID and ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = EventLog(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create event_log object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("event_log object created: " + db_entry_object.log_entry)

    # Get event_log from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch event_log from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("event_log fetched")
        logger.info("event_log fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_event_logs(account_id=None):
    """
    Get all event_log -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create event_log")
    db_entry_object = EventLog()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for event_log
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get event_log from database
    logger.info("Get event_log from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting event_log with event_log_id: " + str(id))
        db_entry_dict = get_event_log(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("event_log object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
###################################
# Service Link Records
##################################
##################################
def get_slr(account_id=None, slr_id=None, cursor=None):
    """
    Get one slr entry from database by Account ID and ID
    :param account_id:
    :param slr_id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = ServiceLinkRecord(account_id=account_id, service_link_record_id=slr_id)
    except Exception as exp:
        error_title = "Failed to create slr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("slr object created: " + db_entry_object.log_entry)

    # Get slr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch slr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("slr fetched")
        logger.info("slr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_record_dict


def get_slrs(account_id=None):
    """
    Get all slr -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create slr")
    db_entry_object = ServiceLinkRecord()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for slr
    try:
        cursor, id_list = get_slr_ids(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get slrs from database
    logger.info("Get slrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting slr with slr_id: " + str(id))
        db_entry_dict = get_slr(account_id=account_id, slr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("slr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def get_record_ids(cursor=None, account_id=None):
    """
    Fetches IDs for all record structures
    :param cursor:
    :param account_id:
    :return:
    """
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Containers
    record_id_container = {}
    table_names = {
        "slr": "",
        "slsr": "",
        "cr": "",
        "csr": ""
    }

    # Get table names
    try:
        logger.info("Table names")
        # SLR
        db_entry_object = ServiceLinkRecord()
        table_names["slr"] = db_entry_object.table_name
        # SLSR
        db_entry_object = ServiceLinkStatusRecord()
        table_names["slsr"] = db_entry_object.table_name
        # CR
        db_entry_object = ConsentRecord()
        table_names["cr"] = db_entry_object.table_name
        # CSR
        db_entry_object = ConsentStatusRecord()
        table_names["csr"] = db_entry_object.table_name
        #
        logger.info("Table names: " + json.dumps(table_names))
    except Exception as exp:
        logger.error('Could not get database table names: ' + repr(exp))
        raise

    # Get primary keys for Service Link Records
    try:
        logger.info("Getting SLR IDs")
        cursor, slr_id_list = get_slr_ids(cursor=cursor, account_id=account_id, table_name=table_names["slr"])
    except Exception as exp:
        logger.error('Could not get slr primary key list: ' + repr(exp))
        raise
    else:
        logger.debug("Got following SLR IDs: " + json.dumps(slr_id_list))

    # Get primary keys for Service Link Status Records and Consent Records
    for slr_id in slr_id_list:
        logger.debug("Looping through slr_id_list: " + json.dumps(slr_id_list))
        # Add Service Link Record IDs to record_container
        try:
            logger.info("Adding SLR IDs")
            record_id_container[slr_id] = {"serviceLinkStatusRecords": {}, "consentRecords": {}}
        except Exception as exp:
            logger.error('Could not add slr_id: ' + str(slr_id) + ' to record_id_container: ' + repr(exp))
            raise
        else:
            logger.debug("Added SLR ID: " + str(slr_id))

        # Get Service Link Status Record IDs
        try:
            logger.info("Getting SLSR IDs")
            cursor, slsr_id_list = get_slsr_ids(cursor=cursor, slr_id=slr_id, table_name=table_names["slsr"])
        except Exception as exp:
            logger.error('Could not get slsr primary key list: ' + repr(exp))
            raise
        else:
            logger.debug("Got following SLSR IDs: " + json.dumps(slsr_id_list))

        # Add Service Link Status Record IDs to record_container
        for slsr_id in slsr_id_list:
            logger.debug("Looping through slsr_id_list: " + json.dumps(slsr_id_list))
            try:
                logger.info("Adding SLSR IDs")
                record_id_container[slr_id]["serviceLinkStatusRecords"][slsr_id] = {}
            except Exception as exp:
                logger.error('Could not add slsr_id: ' + str(slsr_id) + ' to record_id_container: ' + repr(exp))
                raise
            else:
                logger.debug("Added SLSR ID: " + str(slsr_id))

        # Get Consent Record IDs
        try:
            logger.info("Getting CR IDs")
            cursor, cr_id_list = get_cr_ids(cursor=cursor, slr_id=slr_id, table_name=table_names["cr"])
        except Exception as exp:
            logger.error('Could not get cr primary key list: ' + repr(exp))
            raise
        else:
            logger.debug("Got following CR IDs: " + json.dumps(cr_id_list))

        # Add Consent Record IDs to record_container
        for cr_id in cr_id_list:
            logger.debug("Looping through cr_id_list: " + json.dumps(cr_id_list))
            try:
                logger.info("Adding CR IDs")
                record_id_container[slr_id]["consentRecords"][cr_id] = {"consentStatusRecords": {}}
            except Exception as exp:
                logger.error('Could not add cr_id: ' + str(cr_id) + ' to record_id_container: ' + repr(exp))
                raise
            else:
                logger.debug("Added CR ID: " + str(cr_id))

            # Get Consent Status Record IDs
            try:
                logger.info("Getting CSR IDs")
                cursor, csr_id_list = get_csr_ids(cursor=cursor, cr_id=cr_id, table_name=table_names["csr"])
            except Exception as exp:
                logger.error('Could not get csr primary key list: ' + repr(exp))
                raise
            else:
                logger.debug("Got following CSR IDs: " + json.dumps(csr_id_list))

            # Add Consent Status Record IDs to record_container
            for csr_id in csr_id_list:
                logger.debug("Looping through csr_id_list: " + json.dumps(csr_id_list))
                try:
                    logger.info("Adding CSR IDs")
                    record_id_container[slr_id]["consentRecords"][cr_id]["consentStatusRecords"][csr_id] = {}
                except Exception as exp:
                    logger.error('Could not add csr_id: ' + str(csr_id) + ' to record_id_container: ' + repr(exp))
                    raise
                else:
                    logger.debug("Added CSR ID: " + str(csr_id))

    return record_id_container


def get_records(cursor=None, record_ids=None):
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if record_ids is None:
        raise AttributeError("Provide record_ids as parameter")
    if not isinstance(record_ids, dict):
        raise AttributeError("record_ids MUST be dict")

    logger.debug("Type of record_ids: " + repr(type(record_ids)))

    record_container = {}

    logger.info("Getting Records")
    logger.info("record_ids: " + repr(record_ids))
    record_ids = dict(record_ids)

    # logger.info("Get Service Link Records")
    # for slr in record_ids.iteritems():
    #     logger.debug("slr: " + repr(slr))
    #     logger.info("Looping through Service Link Record with ID: " + json.dumps(slr))

    return record_container


def get_slrs_and_subcomponents(account_id=None):
    """
    Get all slr -entries with sub elements (slsr, cr, csr) related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Containers
    return_container = {}
    record_id_container = {}
    record_container = {}

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    try:
        record_id_container = get_record_ids(cursor=cursor, account_id=account_id)
    except Exception as exp:
        logger.error('Could not get record id collection: ' + repr(exp))
        raise

    # TODO: Get Actual records from db
    logger.info("################")
    logger.info("################")
    logger.info("################")
    try:
        record_container = get_records(cursor=cursor, record_ids=record_id_container)
    except Exception as exp:
        logger.error('Could not get record collection: ' + repr(exp))
        raise

    logger.info("################")
    logger.info("################")
    logger.info("################")

    return_container["record_id_container"] = record_id_container
    return_container["record_container"] = record_container


    # Get slrs from database
    # logger.info("Get slrs from database")
    # db_entry_list = []
    # for id in id_list:
    #     # TODO: try-except needed?
    #     logger.info("Getting slr with slr_id: " + str(id))
    #     db_entry_dict = get_slr(account_id=account_id, slr_id=id)
    #     db_entry_list.append(db_entry_dict)
    #     logger.info("slr object added to list: " + json.dumps(db_entry_dict))

    return return_container


##################################
###################################
# Service Link Status Records
##################################
##################################
def get_slsr(account_id=None, slr_id=None, slsr_id=None, cursor=None):
    """
    Get one slsr entry from database by Account ID and ID
    :param slr_id:
    :param slsr_id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if slsr_id is None:
        raise AttributeError("Provide slsr_id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Check if slr can be found with account_id and slr_id
    try:
        slr = get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found SLR: " + repr(slr))

    try:
        db_entry_object = ServiceLinkStatusRecord(service_link_status_record_id=slsr_id, service_link_record_id=slr_id)
    except Exception as exp:
        error_title = "Failed to create slsr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("slsr object created: " + db_entry_object.log_entry)

    # Get slsr from DB
    try:
        logger.info("Get slsr from DB")
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch slsr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("slsr fetched")
        logger.info("slsr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_record_dict


def get_slsrs(account_id=None, slr_id=None):
    """
    Get all slsr -entries related to service link record
    :param account_id:
    :param slr_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")

    # Check if slr can be found with account_id and slr_id
    try:
        slr = get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("HEP")
        logger.info("Found SLR: " + repr(slr))

    # Get table name
    logger.info("Create slsr")
    db_entry_object = ServiceLinkStatusRecord()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for slsr
    try:
        cursor, id_list = get_slsr_ids(cursor=cursor, slr_id=slr_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get slsrs from database
    logger.info("Get slsrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting slsr with account_id: " + str(account_id) + " slr_id: " + str(slr_id) + " slsr_id: " + str(id))
        db_entry_dict = get_slsr(account_id=account_id, slr_id=slr_id, slsr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("slsr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
###################################
# Consent Records
##################################
##################################
def get_cr(account_id=None, slr_id=None, cr_id=None, cursor=None):
    """
    Get one cr entry from database by Account ID and ID
    :param slr_id:
    :param cr_id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Check if slr can be found with account_id and slr_id
    try:
        logger.info("Check if slr can be found with account_id and slr_id")
        slr = get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found: " + repr(slr))

    try:
        db_entry_object = ConsentRecord(consent_id=cr_id, service_link_record_id=slr_id)
    except Exception as exp:
        error_title = "Failed to create cr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("cr object created: " + db_entry_object.log_entry)

    # Get cr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch cr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("cr fetched")
        logger.info("cr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_record_dict


def get_crs(account_id=None, slr_id=None):
    """
    Get all cr -entries related to service link record
    :param account_id:
    :param slr_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")

    # Check if slr can be found with account_id and slr_id
    try:
        slr = get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found SLR: " + repr(slr))

    # Get table name
    logger.info("Create cr")
    db_entry_object = ConsentRecord()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for crs
    try:
        logger.info("Get primary keys for crs")
        cursor, id_list = get_cr_ids(cursor=cursor, slr_id=slr_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise
    else:
        logger.info("primary keys for crs: " + repr(id_list))

    # Get crs from database
    logger.info("Get crs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting cr with account_id: " + str(account_id) + " slr_id: " + str(slr_id) + " cr_id: " + str(id))
        db_entry_dict = get_cr(account_id=account_id, slr_id=slr_id, cr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("cr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
###################################
# Consent Status Records
##################################
##################################
def get_csr(account_id=None, slr_id=None, cr_id=None, csr_id=None, cursor=None):
    """
    Get one csr entry from database by Account ID and ID
    :param slr_id:
    :param cr_id:
    :param csr_id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
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

    # Check if cr can be found with account_id, slr_id and cr_id
    try:
        cr = get_cr(account_id=account_id, slr_id=slr_id, cr_id=cr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id, 'cr_id': cr_id}
        title = "No CR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found: " + repr(cr))

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


def get_csrs(account_id=None, slr_id=None, cr_id=None):
    """
    Get all csr -entries related to service link record
    :param account_id:
    :param slr_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")

    # Check if cr can be found with account_id, slr_id and cr_id
    try:
        cr = get_cr(account_id=account_id, slr_id=slr_id, cr_id=cr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id, 'cr_id': cr_id}
        title = "No CR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found: " + repr(cr))

    # Get table name
    logger.info("Create csr")
    db_entry_object = ConsentStatusRecord()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for csrs
    try:
        cursor, id_list = get_csr_ids(cursor=cursor, cr_id=cr_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get csrs from database
    logger.info("Get csrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting csr with account_id: " + str(account_id) + " slr_id: " + str(slr_id) + " cr_id: " + str(cr_id) + " csr_id: " + str(id))
        db_entry_dict = get_csr(account_id=account_id, slr_id=slr_id, cr_id=cr_id, csr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("csr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
##################################
# Account Export
##################################
##################################
def export_account(account_id=None):
    """
    Export Account as JSON presentation
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    export = {
        "type": "Account",
        "id": account_id,
        "attributes": {}
    }

    export_attributes = {}

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    ##################################
    # Service Link Records
    ##################################
    title = "Service Link Records"
    try:
        logger.info(title)
        entries = get_slrs_and_subcomponents(account_id=account_id)
        export_attributes["serviceLinkRecords"] = entries
    except IndexError as exp:
        error_title = "Export of " + title + " failed. No entries in database."
        logger.error(error_title + ': ' + repr(exp))
        export_attributes["serviceLinkRecords"] = {}
    except Exception as exp:
        error_title = "Export of " + title + " failed"
        logger.error(error_title + ': ' + repr(exp))
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info(title + ": " + json.dumps(entries))

    ##################################
    # Particulars
    ##################################
    # title = "Particulars"
    # try:
    #     logger.info(title)
    #     entries = get_particulars(account_id=account_id)
    #     export_attributes["particulars"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["particulars"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))
    #
    # ##################################
    # # Contacts
    # ##################################
    # title = "Contacts"
    # try:
    #     logger.info(title)
    #     entries = get_contacts(account_id=account_id)
    #     export_attributes["contacts"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["contacts"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))
    #
    # ##################################
    # # Emails
    # ##################################
    # title = "Emails"
    # try:
    #     logger.info(title)
    #     entries = get_emails(account_id=account_id)
    #     export_attributes["emails"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["emails"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))
    #
    # ##################################
    # # Telephones
    # ##################################
    # title = "Telephones"
    # try:
    #     logger.info(title)
    #     entries = get_telephones(account_id=account_id)
    #     export_attributes["telephones"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["telephones"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))
    #
    # ##################################
    # # Settings
    # ##################################
    # title = "Settings"
    # try:
    #     logger.info(title)
    #     entries = get_settings(account_id=account_id)
    #     export_attributes["settings"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["settings"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))
    #
    # ##################################
    # # Event logs
    # ##################################
    # title = "Event logs"
    # try:
    #     logger.info(title)
    #     entries = get_event_logs(account_id=account_id)
    #     export_attributes["logs"] = {}
    #     export_attributes["logs"]["events"] = entries
    # except IndexError as exp:
    #     error_title = "Export of " + title + " failed. No entries in database."
    #     logger.error(error_title + ': ' + repr(exp))
    #     export_attributes["logs"] = {}
    #     export_attributes["logs"]["events"] = {}
    # except Exception as exp:
    #     error_title = "Export of " + title + " failed"
    #     logger.error(error_title + ': ' + repr(exp))
    #     raise StandardError(title + ": " + repr(exp))
    # else:
    #     logger.info(title + ": " + json.dumps(entries))

    ##################################
    ##################################
    ##################################
    # Preparing return content
    ##################################
    title = "export['attributes'] = export_attributes"
    try:
        logger.info(title)
        export["attributes"] = export_attributes
    except Exception as exp:
        error_title = title + " failed"
        logger.error(error_title + ': ' + repr(exp))
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Content of export: " + json.dumps(export))

    return export








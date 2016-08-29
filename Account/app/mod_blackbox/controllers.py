# -*- coding: utf-8 -*-

"""
Minimum viable Key management

__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""
import json
from uuid import uuid4

from app.mod_blackbox.helpers import append_description_to_exception, get_custom_logger

from app.mod_blackbox.services import get_sqlite_connection, get_sqlite_cursor, store_jwk_to_db, gen_key_as_jwk, \
    get_public_key_by_account_id, get_key_by_account_id, jws_json_to_object, get_key, jws_sign, log_dict_as_json, \
    jws_object_to_json, jws_verify, jws_generate

SLR_PAYLOAD = {
  "slr": {
    "ACC-ID-RANDOM_ff8209ae-5d55-4cab-b853-577c30806ba6": {
      "signatures": [
        {
          "header": {
            "kid": "SRVMGNT-IDK3Y",
            "jwk": {
              "y": "B3l_eAy6jYyMbaT3ZvCFDo-H7VIa2672pWbwkkr6SJs",
              "x": "yYuswabb1V5oP0wxTSFSrm6IQQwM8sGK59yp9bqf13Y",
              "kid": "SRVMGNT-IDK3Y",
              "kty": "EC",
              "crv": "P-256"
            }
          },
          "signature": "gd3_od6E7UMGpZHffK4BfUIQwuWyRFMER-gDmymq5NNgHe03JPD2re-PGG64M7c0c3nh9ru4asTqtiVjtfbsLw",
          "protected": "eyJhbGciOiAiRVMyNTYifQ"
        }
      ],
      "payload": "eyJ0b2tlbl9rZXlzIjogeyJrZXlzIjogW3sieCI6ICJiV1VJY0hlSmpzcG9lWEFxR2tCa0RTV09aMXE4anRQbjdVdG51akhqa2RNIiwgInkiOiAib0RsVmZaN25fUVdwZHNmVjBjNW5lb1FXdVRJU2tOU056amJEV0ZIWHBWUSIsICJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgImtpZCI6ICJBQ0MtSUQtUkFORE9NX2ZmODIwOWFlLTVkNTUtNGNhYi1iODUzLTU3N2MzMDgwNmJhNiJ9XX0sICJzdXJyb2dhdGVfaWQiOiAiNzFjNDllZGUtYTEzMS00ODBmLThjZWYtMzViOTc5MTMzYmUxRHVtbXkgVXVzZXJpIiwgImNyZWF0ZWQiOiAxNDYyNzc4NzgyLjY1NTMyMzUsICJvcGVyYXRvcl9pZCI6ICJBQ0MtSUQtUkFORE9NIiwgImNyX2tleXMiOiB7ImtleXMiOiBbeyJ4IjogImJXVUljSGVKanNwb2VYQXFHa0JrRFNXT1oxcThqdFBuN1V0bnVqSGprZE0iLCAieSI6ICJvRGxWZlo3bl9RV3Bkc2ZWMGM1bmVvUVd1VElTa05TTnpqYkRXRkhYcFZRIiwgImt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAia2lkIjogIkFDQy1JRC1SQU5ET01fZmY4MjA5YWUtNWQ1NS00Y2FiLWI4NTMtNTc3YzMwODA2YmE2In1dfSwgInZlcnNpb24iOiAiMS4xIiwgInNlcnZpY2VfaWQiOiAiU1JWLVNIMTRXNFMzIn0"
    }
  }
}

CR_CSR_PAYLOAD = {
   "sink": {
      "csr": {
         "record_id": "418bf90d-7b49-4d8f-aded-cce8c260bd25",
         "account_id": "account_id_sink",
         "consent_status": "consent_status",
         "consent_record_id": "ed926523-d31a-4671-b5f3-beedd2805a86",
         "timestamp": "unix_time",
         "previous_record_id": "null"
      },
      "cr": {
         "common_part": {
            "issued_at": "String",
            "issued": "String",
            "version_number": "String",
            "not_before": "String",
            "slr_id": "123",
            "rs_id": "Amazing Source_ed19ee3f-7d16-4537-8272-85b6912b6ae7",
            "surrogate_id": "Surrhurrdurrrrrr",
            "not_after": "String",
            "subject_id": "String",
            "cr_id": "ed926523-d31a-4671-b5f3-beedd2805a86"
         },
         "ki_cr": {},
         "role_specific_part": {
            "role": "String: sink",
            "usage_rules": [
               "All your cats are belong to us",
               "Something random"
            ]
         },
         "extensions": {}
      }
   },
   "source": {
      "csr": {
         "record_id": "e423e7d7-9d08-45f7-920a-aebd41ba99be",
         "account_id": "account_id_source",
         "consent_status": "consent_status",
         "consent_record_id": "325843db-5dc5-4005-a206-5f1fe8c76555",
         "timestamp": "unix_time",
         "previous_record_id": "null"
      },
      "cr": {
         "common_part": {
            "issued_at": "String",
            "issued": "String",
            "version_number": "String",
            "not_before": "String",
            "slr_id": "123",
            "rs_id": "Amazing Source_ed19ee3f-7d16-4537-8272-85b6912b6ae7",
            "surrogate_id": "Surrhurrdurrrrrr",
            "not_after": "String",
            "subject_id": "String",
            "cr_id": "325843db-5dc5-4005-a206-5f1fe8c76555"
         },
         "ki_cr": {},
         "role_specific_part": {
            "auth_token_issuer_key": "Get this from somewhere!",
            "role": "String: source",
            "resource_set_description": "String (RDF)"
         },
         "extensions": {}
      }
   }
}


logger = get_custom_logger('mod_blackbox_controllers')


def store_jwk(account_id=None, account_kid=None, account_key=None):
    """
    Stores JWK to key storage

    :param account_id: User account ID
    :param account_kid: Key ID
    :param account_key: JWK
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if account_kid is None:
        raise AttributeError("Provide account_kid as parameter")
    if account_key is None:
        raise AttributeError("Provide account_key as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor = store_jwk_to_db(account_id=account_id, account_kid=account_kid, account_key=account_key, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not store jwk to database')
        logger.error('Could not store jwk to database: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.commit()
        connection.close()
        logger.debug('JWK, kid and account_id stored')


def gen_account_key(account_id=None):
    """
    Generate key for account ID

    :param account_id:
    :return: Key ID for created key
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    account_kid = "acc-kid-" + str(uuid4())
    logger.debug('Generated account_kid: ' + str(account_kid))

    try:
        account_key = gen_key_as_jwk(account_kid=account_kid)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Failed to generate key for account')
        logger.error('Failed to generate key for account: ' + repr(exp))
        raise

    try:
        store_jwk(account_id=account_id, account_kid=account_kid, account_key=account_key)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Failed to store generated key. Key must be regenerated.')
        logger.error('Failed to store generated key: ' + repr(exp))
        raise
    else:
        logger.info('For account with id: ' + str(account_id) + ' has been generated JWK with kid: ' + str(account_kid))
        return account_kid


def get_account_public_key(account_id=None):
    """
    Get public Key by account ID

    :param account_id:
    :return: public Key & Key ID
    """

    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor, key_public, kid = get_public_key_by_account_id(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get public key from database')
        logger.error('Could not get public key from database: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.close()
        logger.debug('Public key fetched')
        return key_public, kid


def get_account_key(account_id=None):
    """
    Get Key by account ID

    :param account_id:
    :return: Key
    """
    if(True):
        # For to disable usage of this function
        raise NotImplementedError()
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise

    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise

    try:
        cursor, key, kid = get_key_by_account_id(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not lget jwk from database')
        logger.error('Could not get jwk from database: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        connection.close()
        logger.debug('JWK fetched')
        return key


def sign_jws_with_jwk(account_id=None, jws_json_to_sign=None):
    """
    For signing JWSs that have been generated by others.
    Gathers necessary data for JWS signing. Signs JWS.

    :param account_id: User account ID
    :param jws_json_to_sign: JSON presentation of JWS that should be signed
    :return: Signed JWS json
    """
    if account_id is None:
        raise AttributeError("Provide account_id or as parameter")
    if jws_json_to_sign is None:
        # raise AttributeError("Provide jws_to_sign or as parameter")
        # Fake request payload to json
        # TODO: Following two lines, NOT FOR PRODUCTION
        jws_json_to_sign = json.dumps(SLR_PAYLOAD['slr'])
        logger.info("No jws_json_to_sign provided as parameter. Using SLR_PAYLOAD -template instead.")

    # jws_json_to_sign to dict
    try:
        jws_structure = json.loads(jws_json_to_sign)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert jws_json_to_sign to dict')
        logger.error('Could not convert jws_json_to_sign to dict: ' + repr(exp))
        raise
    else:
        log_dict_as_json(jws_structure)
        logger.info("######## jws_json_to_sign to dict  -> OK ########")

    # Fix incorrect padding of base64 string
    try:
        # dict_keys = jws_structure.keys()  # Top-level dict key to enable access to JWS payload
        # first_key_in_dict = dict_keys[0]
        # logger.debug('JWS payload before Base64 fix: ' + str(jws_structure[first_key_in_dict]['payload']))
        # jws_structure[first_key_in_dict]['payload'] += '=' * (-len(jws_structure[first_key_in_dict]['payload']) % 4)  # Fix incorrect padding of base64 string.
        logger.debug('JWS payload before Base64 fix: ' + str(jws_structure['payload']))
        jws_structure['payload'] += '=' * (-len(jws_structure['payload']) % 4)  # Fix incorrect padding of base64 string.
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Failed to fix incorrect padding of base64 string')
        logger.error('Failed to fix incorrect padding of base64 string: ' + repr(exp))
        raise
    else:
        #logger.debug('JWS payload after  Base64 fix: ' + str(jws_structure[first_key_in_dict]['payload']))
        logger.debug('JWS payload after  Base64 fix: ' + str(jws_structure['payload']))
        logger.info("######## Base64 fix -> OK ########")

    # Convert jws_structure to JSON for future steps
    try:
        #jws_structure_json = json.dumps(jws_structure[first_key_in_dict])
        jws_structure_json = json.dumps(jws_structure)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='JSON conversion failed')
        logger.error('JSON conversion failed: ' + repr(exp))
        raise
    else:
        logger.info("######## JSON conversion -> OK ########")

    # Prepare JWS for signing
    try:
        jws_object_to_sign = jws_json_to_object(jws_json=jws_structure_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS json to JWS object')
        logger.error('Could not convert JWS json to JWS object: ' + repr(exp))
        raise
    else:
        logger.debug("jws_object_to_sign: " + str(jws_object_to_sign.__dict__))
        logger.info("######## JWS object  -> OK ########")

    # Prepare database connection
    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Connection -> OK ########")

    # Prepare database cursor
    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Cursor -> OK ########")

    # Get public Key as JSON and Key ID
    kid = {}
    try:
        cursor, key_public_json, kid[0] = get_public_key_by_account_id(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get public key as JSON')
        logger.error('Could not get public key as JSON: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        logger.info("######## Public Key -> OK ########")

    # Get Key as JWK object and Key ID
    try:
        cursor, key_object, kid[1] = get_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get key object')
        logger.error('Could not get key object: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        logger.info("######## Key Object -> OK ########")
        connection.close()

    # Sign JWS
    try:
        jws_object_signed = jws_sign(account_id=account_id, account_kid=kid[0], jws_object=jws_object_to_sign, jwk_object=key_object, jwk_public_json=key_public_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not sign JWS object')
        logger.error('Could not sign JWS object: ' + repr(exp))
        raise
    else:
        logger.info("######## JWS signature -> OK ########")

    # JWS object to JWS JSON
    try:
        jws_json = jws_object_to_json(jws_object=jws_object_signed)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS object to JWS json')
        logger.error('Could not convert JWS object to JWS json: ' + repr(exp))
        raise
    else:
        logger.info("######## JWS conversion -> OK ########")
        return jws_json


def verify_jws_signature_with_jwk(account_id=None, jws_json_to_verify=None):
    """
    Verifies signature of JWS with key related to user account.
    Key used in verification is fetched from database by account_id.

    :param account_id: User account ID
    :param jws_json_to_verify: JSON presentation of JWS object that should be verified
    :return: Boolean, presenting if verification passed
    """
    if account_id is None:
        raise AttributeError("Provide account_id or as parameter")
    if jws_json_to_verify is None:
        # raise AttributeError("Provide jws_to_sign or as parameter")
        # TODO: Following two lines, NOT FOR PRODUCTION
        jws_json_to_verify = sign_jws_with_jwk(account_id=account_id)
        logger.info("No jws_json_to_sign provided as parameter. Using SLR_PAYLOAD -template instead.")

    # Prepare JWS for signing
    try:
        jws_object_to_verify = jws_json_to_object(jws_json=jws_json_to_verify)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS json to JWS object')
        logger.error('Could not convert JWS json to JWS object: ' + repr(exp))
        raise
    else:
        logger.debug("jws_object_to_verify: " + str(jws_object_to_verify.__dict__))
        logger.info("######## JWS object  -> OK ########")

    # Prepare database connection
    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Connection -> OK ########")

    # Prepare database cursor
    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Cursor -> OK ########")

    # Get Key as JWK object and Key ID
    try:
        cursor, key_object, kid = get_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get key object')
        logger.error('Could not get key object: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        logger.info("######## Key Object -> OK ########")
        connection.close()

    # Verifying JWS
    logger.info("Verifying JWS")
    jws_signature_valid = jws_verify(jws_object=jws_object_to_verify, jwk_object=key_object)
    logger.info("JWS verified: " + str(jws_signature_valid))

    return jws_signature_valid


def generate_and_sign_jws(account_id=None, jws_payload=None):
    if account_id is None:
        raise AttributeError("Provide account_id or as parameter")
    if jws_payload is None:
        # raise AttributeError("Provide jws_to_sign or as parameter")
        # TODO: Following two lines, NOT FOR PRODUCTION
        jws_payload = CR_CSR_PAYLOAD['sink']['cr']
        logger.info("No jws_payload provided as parameter. Using CR_CSR_PAYLOAD -template instead.")

    # Prepare database connection
    try:
        connection = get_sqlite_connection()
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get connection SQL database.')
        logger.error('Could not get connection SQL database: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Connection -> OK ########")

    # Prepare database cursor
    try:
        cursor, connection = get_sqlite_cursor(connection=connection)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get cursor for database connection')
        logger.error('Could not get cursor for database connection: ' + repr(exp))
        raise
    else:
        logger.info("######## DB Cursor -> OK ########")

    # Get public Key as JSON and Key ID
    kid = {}
    try:
        cursor, key_public_json, kid[0] = get_public_key_by_account_id(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get public key as JSON')
        logger.error('Could not get public key as JSON: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        logger.info("######## Public Key -> OK ########")

    # Get Key as JWK object and Key ID
    try:
        cursor, key_object, kid[1] = get_key(account_id=account_id, cursor=cursor)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not get key object')
        logger.error('Could not get key object: ' + repr(exp))
        connection.rollback()
        connection.close()
        raise
    else:
        logger.info("######## Key Object -> OK ########")
        connection.close()

    # Generate JWS
    try:
        jws_object = jws_generate(payload=jws_payload)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not generate JWS object')
        logger.error('Could not generate JWS object: ' + repr(exp))
        raise
    else:
        logger.info("######## JWS Object -> OK ########")

    # Sign JWS
    try:
        jws_object_signed = jws_sign(account_id=account_id, account_kid=kid[0], jws_object=jws_object, jwk_object=key_object, jwk_public_json=key_public_json)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not sign JWS object')
        logger.error('Could not sign JWS object: ' + repr(exp))
        raise
    else:
        logger.info("######## JWS signature -> OK ########")

    # JWS object to JWS JSON
    try:
        jws_json = jws_object_to_json(jws_object=jws_object_signed)
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not convert JWS object to JWS json')
        logger.error('Could not convert JWS object to JWS json: ' + repr(exp))
        raise
    else:
        logger.info("######## JWS conversion -> OK ########")
        return jws_json


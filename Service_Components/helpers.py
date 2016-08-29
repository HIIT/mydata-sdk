# -*- coding: utf-8 -*-
import pkgutil
import importlib

from flask import Blueprint
from flask_restful import Api
import logging

from json import dumps, loads
debug_log = logging.getLogger("debug")
import jsonschema
import db_handler
from sqlite3 import OperationalError, IntegrityError
from DetailedHTTPException import  DetailedHTTPException

def validate_json(schema, json): # "json" here needs to be python dict.
    errors = []
    validator = jsonschema.Draft4Validator(schema)
    validator.check_schema(schema)
    for error in sorted(validator.iter_errors(json), key=str):
        debug_log.warning("Validation error found: {}".format(repr(error)))
        errors.append(repr(error))
    return errors



class Helpers:
    def __init__(self, app_config):
        self.db_path = app_config["DATABASE_PATH"]

    def query_db(self, query, args=(), one=False):
        db = db_handler.get_db(self.db_path)
        cur = db.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv

    def storeJSON(self, DictionaryToStore):
        db = db_handler.get_db(self.db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        debug_log.info(DictionaryToStore)
        for key in DictionaryToStore:
            debug_log.info(key)
            try:
                db.execute("INSERT INTO storage (surrogate_id,json) \
                    VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
                db.commit()
            except IntegrityError as e:
                db.execute("UPDATE storage SET json=? WHERE surrogate_id=? ;", [dumps(DictionaryToStore[key]), key])
                db.commit()

    def storeCode(self, code):
        db = db_handler.get_db(self.db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        code_key = list(code.keys())[0]
        code_value = code[code_key]
        db.execute("INSERT INTO codes (ID,code) \
            VALUES (?, ?)", [code_key, code_value])
        db.commit()

        debug_log.info("{}  {}".format(code_key, code_value))
        for code in self.query_db("select * from codes where ID = ?;", [code_key]):
            debug_log.info(code["code"])
        db.close()

    def add_surrogate_id_to_code(self, code, surrogate_id):
        db = db_handler.get_db(self.db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        for code in self.query_db("select * from codes where code = ?;", [code]):
            code_from_db = code["code"]
            code_is_valid_and_unused = "!" in code_from_db
            if (code_is_valid_and_unused):
                db.execute("UPDATE codes SET code=? WHERE ID=? ;", [surrogate_id, code])
                db.commit()
            else:
                raise Exception("Invalid code")

    def verifyCode(self, code):
        db = db_handler.get_db(self.db_path)
        for code_row in self.query_db("select * from codes where ID = ?;", [code]):
            code_from_db = code_row["code"]
            return True
        return False

    def verifySurrogate(self, code, surrogate):
        db = db_handler.get_db(self.db_path)
        for code_row in self.query_db("select * from codes where ID = ? AND code = ?;", [code, surrogate]):
            code_from_db = code_row["code"]
            # TODO: Could we remove code and surrogate_id after this check to ensure they wont be abused later.
            return True
        return False

    def get_slr(self, surrogate_id):
        db = db_handler.get_db(self.db_path)
        for storage_row in self.query_db("select * from storage where surrogate_id = ?;", [surrogate_id]):
            slr_from_db = storage_row["json"]
            return loads(slr_from_db)

    def storeCR_JSON(self, DictionaryToStore):
        cr_id = DictionaryToStore["cr_id"]
        rs_id = DictionaryToStore["rs_id"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        slr_id = DictionaryToStore["slr_id"]
        json = DictionaryToStore["json"]
        db = db_handler.get_db(self.db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        debug_log.info(DictionaryToStore)
        # debug_log.info(key)
        try:
            db.execute("INSERT INTO cr_storage (cr_id, surrogate_id, slr_id, rs_id, json) \
                VALUES (?, ?, ?, ?, ?)", [cr_id, surrogate_id, slr_id, rs_id, dumps(json)])
            db.commit()
        except IntegrityError as e:
            # db.execute("UPDATE cr_storage SET json=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
            # db.commit()
            db.rollback()
            raise DetailedHTTPException(detail={"msg": "Adding CR to the database has failed.",},
                                        title="Failure in CR storage", exception=e)

    def storeCSR_JSON(self, DictionaryToStore):
        cr_id = DictionaryToStore["cr_id"]
        rs_id = DictionaryToStore["rs_id"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        slr_id = DictionaryToStore["slr_id"]
        json = DictionaryToStore["json"]
        db = db_handler.get_db(self.db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        debug_log.info(DictionaryToStore)
        # debug_log.info(key)
        try:
            db.execute("INSERT INTO csr_storage (cr_id, surrogate_id, slr_id, rs_id, json) \
                VALUES (?, ?, ?, ?, ?)", [cr_id, surrogate_id, slr_id, rs_id, dumps(json)])
            db.commit()
        except IntegrityError as e:
            # db.execute("UPDATE csr_storage SET json=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
            # db.commit()
            db.rollback()
            raise DetailedHTTPException(detail={"msg": "Adding CSR to the database has failed.",},
                                        title="Failure in CSR storage", exception=e)


def register_blueprints(app, package_name, package_path):
    """Register all Blueprint instances on the specified Flask application found
    in all modules for the specified package.
    :param app: the Flask application
    :param package_name: the package name
    :param package_path: the package path
    """
    rv = []
    apis = []
    for _, name, _ in pkgutil.iter_modules(package_path):
        m = importlib.import_module('%s.%s' % (package_name, name))
        for item in dir(m):
            item = getattr(m, item)
            if isinstance(item, Blueprint):
                app.register_blueprint(item)
            rv.append(item)
            if isinstance(item, Api):
                apis.append(item)
    return rv, apis

from base64 import urlsafe_b64decode as decode
from json import loads
class SLR_tool:
    def __init__(self):
        self.slr = {
                  "code": "7e4f7cf6-f169-4430-9b23-a4820446fe71",
                  "data": {
                    "slr": {
                      "type": "ServiceLinkRecord",
                      "attributes": {
                        "slr": {
                          "payload": "IntcIm9wZXJhdG9yX2lkXCI6IFwiQUNDLUlELVJBTkRPTVwiLCBcImNyZWF0ZWRcIjogMTQ3MTM0NDYyNiwgXCJzdXJyb2dhdGVfaWRcIjogXCI5YjQxNmE5Zi1jYjRmLTRkNWMtYjJiZS01OWQxYjc3ZjJlZmFfMVwiLCBcInRva2VuX2tleVwiOiB7XCJrZXlcIjoge1wieVwiOiBcIkN0NGNHMnpPQzdrano5VWF1WHFqcTRtZ0d0bEdXcDJjcWZneVVlaUU4U2dcIiwgXCJ4XCI6IFwiUnJueHZoZjVsZXppQTZyZms4ZDlRbV96bXd2SDc5X2U5eUhBS2ZJR2dFRVwiLCBcImNydlwiOiBcIlAtMjU2XCIsIFwia3R5XCI6IFwiRUNcIiwgXCJraWRcIjogXCJTUlZNR05ULUlESzNZXCJ9fSwgXCJsaW5rX2lkXCI6IFwiNDJhMzVhN2QtMjkxZS00N2UzLWIyMmYtOTk2NjJmNjgzNDEzXCIsIFwib3BlcmF0b3Jfa2V5XCI6IHtcInVzZVwiOiBcInNpZ1wiLCBcImVcIjogXCJBUUFCXCIsIFwia3R5XCI6IFwiUlNBXCIsIFwiblwiOiBcIndITUFwQ2FVSkZpcHlGU2NUNzgxd2VuTm5mbU5jVkQxZTBmSFhfcmVfcWFTNWZvQkJzN1c0aWE1bnVxNjVFQWJKdWFxaGVPR2FEamVIaVU4V1Q5cWdnYks5cTY4SXZUTDN1bjN6R2o5WmQ3N3MySXdzNE1BSW1EeWN3Rml0aDE2M3lxdW9ETXFMX1YySXl5Mm45Uzloa1M5ZkV6cXJsZ01sYklnczJtVkJpNmdWVTJwYnJTN0gxUGFSV194YlFSX1puN19laV9uOFdlWFA1d2NEX3NJYldNa1NCc3VVZ21jam9XM1ktNW1ERDJWYmRFejJFbWtZaTlHZmstcDlBenlVbk56ZkIyTE1jSk1aekpWUWNYaUdCTzdrcG9uRkEwY3VIMV9CR0NsZXJ6Mnh2TWxXdjlPVnZzN3ZDTmRlQV9mano2eloyMUtadVo0RG1nZzBrOTRsd1wifSwgXCJ2ZXJzaW9uXCI6IFwiMS4yXCIsIFwiY3Jfa2V5c1wiOiBbe1wieVwiOiBcIlhaeWlveV9BME5qQ3Q1ZGt6OW5MOGI3YXdQRl9Cck5iYzVObjFOTTdXS0FcIiwgXCJ4XCI6IFwiR3ZaVEdpMllSb0VCblc2QzB4clpRQ0tNeWwza2lNcjgtRVoySU1ocnpXb1wiLCBcImNydlwiOiBcIlAtMjU2XCIsIFwia3R5XCI6IFwiRUNcIiwgXCJraWRcIjogXCJhY2Mta2lkLTg1MTVhYjQ2LTlkODItNDUzNC1hZDFmLTYzZDFlNDdiZDY2YlwifV0sIFwic2VydmljZV9pZFwiOiBcIjFcIn0i",
                          "signatures": [
                            {
                              "header": {
                                "jwk": {
                                  "x": "GvZTGi2YRoEBnW6C0xrZQCKMyl3kiMr8-EZ2IMhrzWo",
                                  "kty": "EC",
                                  "crv": "P-256",
                                  "y": "XZyioy_A0NjCt5dkz9nL8b7awPF_BrNbc5Nn1NM7WKA",
                                  "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                                },
                                "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                              },
                              "protected": "eyJhbGciOiAiRVMyNTYifQ",
                              "signature": "fsSuhqLp6suUuT8waseMlpYcFx4vqIviIteBLUNWPUOubHPDY64sbpfx_flpPFymxG_t8r3Ptb96kv-ZDyjb7g"
                            },
                            {
                              "header": {
                                "jwk": {
                                  "x": "Rrnxvhf5leziA6rfk8d9Qm_zmwvH79_e9yHAKfIGgEE",
                                  "kty": "EC",
                                  "crv": "P-256",
                                  "y": "Ct4cG2zOC7kjz9UauXqjq4mgGtlGWp2cqfgyUeiE8Sg",
                                  "kid": "SRVMGNT-IDK3Y"
                                },
                                "kid": "SRVMGNT-IDK3Y"
                              },
                              "protected": "eyJhbGciOiAiRVMyNTYifQ",
                              "signature": "3rZCfJxvpD7covQjH_lhkJwId8ynVIMLZ6t1obiCrlwJOJe_Yc7dmImi10w8tc9_7c7u35_ysiD72wIlbJ4oFQ"
                            }
                          ]
                        }
                      }
                    },
                    "meta": {
                      "slsr_id": "374707b7-a60b-4596-9f3a-6a5affa414c3",
                      "slr_id": "42a35a7d-291e-47e3-b22f-99662f683413"
                    },
                    "slsr": {
                      "type": "ServiceLinkStatusRecord",
                      "attributes": {
                        "slsr": {
                          "header": {
                            "jwk": {
                              "x": "GvZTGi2YRoEBnW6C0xrZQCKMyl3kiMr8-EZ2IMhrzWo",
                              "kty": "EC",
                              "crv": "P-256",
                              "y": "XZyioy_A0NjCt5dkz9nL8b7awPF_BrNbc5Nn1NM7WKA",
                              "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                            },
                            "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                          },
                          "protected": "eyJhbGciOiAiRVMyNTYifQ",
                          "payload": "IntcInNscl9pZFwiOiBcIjQyYTM1YTdkLTI5MWUtNDdlMy1iMjJmLTk5NjYyZjY4MzQxM1wiLCBcImFjY291bnRfaWRcIjogXCIxXCIsIFwic2xfc3RhdHVzXCI6IFwiQWN0aXZlXCIsIFwicmVjb3JkX2lkXCI6IFwiMzc0NzA3YjctYTYwYi00NTk2LTlmM2EtNmE1YWZmYTQxNGMzXCIsIFwiaWF0XCI6IDE0NzEzNDQ2MjYsIFwicHJldl9yZWNvcmRfaWRcIjogXCJOVUxMXCJ9Ig",
                          "signature": "cfj3Zm5ICVtTdUJigKGTxJX4V8vzs1e9qVj83hPmiD-XJonrBRW60zQN-3lRTuJithFbrGgBJShGj1InuNGMsw"
                        }
                      }
                    },
                    "surrogate_id": "9b416a9f-cb4f-4d5c-b2be-59d1b77f2efa_1"
                  }}
    def decrypt_payload(self, payload):
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        content = decode(payload.encode())
        payload = loads(loads(content.decode("utf-8")))
        return payload

    def get_SLR_payload(self):
        base64_payload = self.slr["data"]["slr"]["attributes"]["slr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_SLSR_payload(self):
        base64_payload =  self.slr["data"]["slsr"]["attributes"]["slsr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_token_key(self):
        return self.get_SLR_payload()["token_key"]

    def get_operator_key(self):
        return self.get_SLR_payload()["operator_key"]

    def get_cr_keys(self):
        return self.get_SLR_payload()["cr_keys"]


#
# sl = SLR_tool()
# print(dumps(sl.get_CR_payload(), indent=2))
# print(sl.get_SLR_payload())
# print(sl.get_cr_keys())
# print(sl.get_rs_id())
# print(sl.get_rs_set())
# print(sl.get_slr_id())
# print(sl.get_sink_surrogate_id())
# print(sl.get_source_surrogate_id())

from jwcrypto import jwk, jws
class CR_tool:
    def __init__(self):
        self.cr = {
  "csr": {
    "signature": "e4tiFSvnqUb8k1U6BXC5WhbkQWVJZqMsDqc3efPRkBcL1cM21mSJXYOS4dSiCx4ak8S8S1IKN4wcyuAxXfrGeQ",
    "payload": "IntcImNvbW1vbl9wYXJ0XCI6IHtcInNscl9pZFwiOiBcImJhYmY5Mjc3LWEyZmItNGI4MS1iMTYyLTE4ZTI5MzUyNzYxN1wiLCBcInZlcnNpb25fbnVtYmVyXCI6IFwiU3RyaW5nXCIsIFwicnNfaWRcIjogXCIyXzYyNmE3YmZiLTk0MmEtNDI2ZC1hNDc2LWE0Mzk5NmYyMDAwNVwiLCBcImNyX2lkXCI6IFwiMjlmZmRkZmMtNjBhMS00YmYwLTkzMWMtNGQ1ZWYwMmQ2N2YyXCIsIFwiaXNzdWVkXCI6IDE0NzE1OTMwMjYsIFwic3ViamVjdF9pZFwiOiBcIjFcIiwgXCJub3RfYmVmb3JlXCI6IFwiU3RyaW5nXCIsIFwibm90X2FmdGVyXCI6IFwiU3RyaW5nXCIsIFwiaXNzdWVkX2F0XCI6IFwiU3RyaW5nXCIsIFwic3Vycm9nYXRlX2lkXCI6IFwiZTZlMjdlNzUtNjUxZi00Y2I0LTg5ZTItYTUxZWI5NDllYjYwXzJcIn0sIFwicm9sZV9zcGVjaWZpY19wYXJ0XCI6IHtcInJvbGVcIjogXCJTaW5rXCIsIFwidXNhZ2VfcnVsZXNcIjogW1wiQWxsIHlvdXIgY2F0cyBhcmUgYmVsb25nIHRvIHVzXCIsIFwiU29tZXRoaW5nIHJhbmRvbVwiXX0sIFwiZXh0ZW5zaW9uc1wiOiB7fSwgXCJtdmNyXCI6IHt9fSI",
    "protected": "eyJhbGciOiAiRVMyNTYifQ",
    "header": {
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao",
        "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
        "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
      },
      "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
    }
  },
  "cr": {
    "signature": "fiiVhAPxzYGgkV3D43FvgKSdIvDrsyMm_Vz4WWhBoLaXbTcZKNEvKL5Tx1O6YRwShOc9plK7YRxgWyY9OYd7zA",
    "payload": "IntcImFjY291bnRfaWRcIjogXCJlNmUyN2U3NS02NTFmLTRjYjQtODllMi1hNTFlYjk0OWViNjBfMlwiLCBcImNyX2lkXCI6IFwiMjlmZmRkZmMtNjBhMS00YmYwLTkzMWMtNGQ1ZWYwMmQ2N2YyXCIsIFwicHJldl9yZWNvcmRfaWRcIjogXCJudWxsXCIsIFwicmVjb3JkX2lkXCI6IFwiZTBiZDk1MTUtNjA5Zi00YzMxLThiMmQtZDliMTY5NjdiZmQzXCIsIFwiaWF0XCI6IDE0NzE1OTMwMjYsIFwiY29uc2VudF9zdGF0dXNcIjogXCJBY3RpdmVcIn0i",
    "protected": "eyJhbGciOiAiRVMyNTYifQ",
    "header": {
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao",
        "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
        "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
      },
      "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
    }
  }
}
    def decrypt_payload(self, payload):
        #print("payload :\n", slr)
        #print("Before Fix:", payload)
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        #print("After Fix :", payload)
        content = decode(payload.encode())
        payload = loads(loads(content.decode("utf-8")))
        return payload

    def get_CR_payload(self):
        base64_payload = self.cr["cr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_CSR_payload(self):
        base64_payload = self.cr["csr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_cr_id_from_csr(self):
        return self.get_CSR_payload()["cr_id"]

    def get_prev_record_id(self):
        return self.get_CSR_payload()["prev_record_id"]

    def get_cr_id_from_cr(self):
        return self.get_CR_payload()["common_part"]["cr_id"]

    def cr_id_matches_in_csr_and_cr(self):
        return self.get_cr_id_from_cr() == self.get_cr_id_from_csr()

    def get_usage_rules(self):
        return self.get_CR_payload()["role_specific_part"]["usage_rules"]

    def get_slr_id(self):
        return self.get_CR_payload()["common_part"]["slr_id"]

    def get_rs_id(self):
        return self.get_CR_payload()["common_part"]["rs_id"]

    def get_subject_id(self):
        return self.get_CR_payload()["common_part"]["subject_id"]

    def get_surrogate_id(self):
        return self.get_CR_payload()["common_part"]["surrogate_id"]

    def get_role(self):
        return self.get_CR_payload()["role_specific_part"]["role"]

    def verify_cr(self, keys):
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            cr_jws = jws.JWS()
            cr_jws.deserialize(dumps(self.cr["cr"]))

            try:
                cr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                pass
                #print(repr(e))
                #return False
        return False


    def verify_csr(self, keys):
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            csr_jws = jws.JWS()
            csr_jws.deserialize(dumps(self.cr["csr"]))
            try:
                csr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                pass
                #print(repr(e))
                #return False
        return False

#crt = CR_tool()
#print (dumps(crt.get_CR_payload(), indent=2))
#print (dumps(crt.get_CSR_payload(), indent=2))
#print(crt.get_role())
# print(crt.get_cr_id())
# print(crt.get_usage_rules())
# print(crt.get_surrogate_id())
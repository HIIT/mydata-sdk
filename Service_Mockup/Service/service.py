# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import loads
from requests import post
from sqlite3 import OperationalError, IntegrityError

import db_handler as db_handler
from DetailedHTTPException import DetailedHTTPException, error_handler
from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from jwcrypto import jwk

debug_log = logging.getLogger("debug")

api_Root_blueprint = Blueprint("api_Root_blueprint", __name__)  # TODO Rename better

CORS(api_Root_blueprint)
api = Api()
api.init_app(api_Root_blueprint)

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
Service_ID = "SRV-SH14W4S3"
gen = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}
token_key = jwk.JWK(**gen)
# templ = {Service_ID: loads(token_key.export_public())}
templ = {Service_ID: {"cr_keys": loads(token_key.export_public())}}


# post("http://localhost:6666/key", json=templ)
# op_key = loads(get("http://localhost:6666/key/"+"OPR-ID-RANDOM").text)
# Operator_pub = jwk.JWK(**op_key)


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log.info("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


def storeJSON(DictionaryToStore):
    db = db_handler.get_db()
    try:
        db_handler.init_db(db)
    except OperationalError:
        pass

    debug_log.info(DictionaryToStore)

    for key in DictionaryToStore:
        debug_log.info(key)
        # codes = {"jsons": {}}
        # codes = {"jsons": {}}
        try:
            db.execute("INSERT INTO storage (ID,json) \
                VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
            db.commit()
        except IntegrityError as e:
            db.execute("UPDATE storage SET json=? WHERE ID=? ;", [dumps(DictionaryToStore[key]), key])
            db.commit()


def storeCodeUser(DictionaryToStore):
    # {"code": "user_id"}
    db = db_handler.get_db()
    try:
        db_handler.init_db(db)
    except OperationalError:
        pass

    debug_log.info(DictionaryToStore)

    for key in DictionaryToStore:
        debug_log.info(key)
        db.execute("INSERT INTO code_and_user_mapping (code, user_id) \
            VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
        db.commit()


def get_user_id_with_code(code):
    db = db_handler.get_db()
    for code_row in db_handler.query_db("select * from code_and_user_mapping where code = ?;", [code]):
        user_from_db = code_row["user_id"]
        return user_from_db
    raise DetailedHTTPException(status=500,
                                detail={"msg": "Unable to link code to user_id in database", "detail": {"code": code}},
                                title="Failed to link code to user_id")
    # Letting world burn if user was not in db. Fail fast, fail hard.


def storeSurrogateJSON(DictionaryToStore):
    db = db_handler.get_db()
    try:
        db_handler.init_db(db)
    except OperationalError:
        pass

    debug_log.info(DictionaryToStore)

    for key in DictionaryToStore:
        debug_log.info(key)
        db.execute("INSERT INTO surrogate_and_user_mapping (user_id, surrogate_id) \
            VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
        db.commit()


class UserLogin(Resource):
    @timeme
    @error_handler
    def post(self):
        debug_log.info(dumps(request.json, indent=2))
        user_id = request.json["user_id"]
        code = request.json["code"]
        storeCodeUser({code: user_id})

        debug_log.info("User logged in with id ({})".format(format(user_id)))
        endpoint = "/api/1.2/slr/auth"
        result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=request.json)
        if not result.ok:
            raise DetailedHTTPException(status=result.status_code,
                                        detail={
                                            "msg": "Something went wrong while posting to Service_Components Mgmnt to inform login was successful "
                                                   "and its alright to generate Surrogate_ID ",
                                            "Error from Service_Components Mgmnt": loads(result.text)},
                                        title=result.reason)

        debug_log.info(result.text)


from json import dumps


class RegisterSur(Resource):
    @timeme
    @error_handler
    def post(self):
        try:  # Remove this check once debugging is done. TODO
            user_id = get_user_id_with_code(request.json["code"])
            debug_log.info("We got surrogate_id {} for user_id {}".format(request.json["surrogate_id"], user_id))
            debug_log.info(dumps(request.json, indent=2))
            storeSurrogateJSON({user_id: request.json})
        except Exception as e:
            pass


class StoreSlr(Resource):
    @timeme
    @error_handler
    def post(self):
        debug_log.info(dumps(request.json, indent=2))
        store = request.json
        storeJSON({store["data"]["surrogate_id"]: store})


api.add_resource(UserLogin, '/login')
api.add_resource(RegisterSur, '/link')
api.add_resource(StoreSlr, '/store_slr')

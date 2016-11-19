# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
from json import dumps, loads
from sqlite3 import IntegrityError

from Crypto.PublicKey.RSA import importKey as import_rsa_key
from flask import Blueprint
from flask_restful import Api

import db_handler
from DetailedHTTPException import DetailedHTTPException

debug_log = logging.getLogger("debug")

class Helpers:
    def __init__(self, app_config):
        self.host = app_config["MYSQL_HOST"]
        self.cert_key_path = app_config["CERT_KEY_PATH"]
        self.keysize = app_config["KEYSIZE"]
        self.user = app_config["MYSQL_USER"]
        self.passwd = app_config["MYSQL_PASSWORD"]
        self.db = app_config["MYSQL_DB"]
        self.port = app_config["MYSQL_PORT"]

    def query_db(self, query, args=()):
        '''
        Simple queries to DB
        :param query: SQL query
        :param args: Arguments to inject into the query
        :return: Single hit for the given query
        '''
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cur = cursor.execute(query, args)
        try:
            rv = cursor.fetchone()  # Returns tuple
            debug_log.info(rv)
            if rv is not None:
                db.close()
                return rv[1]  # The second value in the tuple.
            else:
                return None
        except Exception as e:
            debug_log.exception(e)
            debug_log.info(cur)
            db.close()
            return None

    def storeJSON(self, DictionaryToStore):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            # codes = {"jsons": {}}
            # codes = {"jsons": {}}
            try:
                cursor.execute("INSERT INTO storage (ID,json) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
                db.close()
            except IntegrityError as e:
                cursor.execute("UPDATE storage SET json=%s WHERE ID=%s ;", (dumps(DictionaryToStore[key]), key))
                db.commit()
                db.close()

    def storeCodeUser(self, DictionaryToStore):
        # {"code": "user_id"}
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            cursor.execute("INSERT INTO code_and_user_mapping (code, user_id) \
                VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
            db.commit()
        db.close()

    def get_user_id_with_code(self, code):
        try:
            db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
            query = self.query_db("select * from code_and_user_mapping where code=%s;", (code,))
            debug_log.info(query)
            user_from_db = loads(query)
            return user_from_db
        except Exception as e:
            debug_log.exception(e)
            raise DetailedHTTPException(status=500,
                                        detail={"msg": "Unable to link code to user_id in database",
                                                "detail": {"code": code}},
                                        title="Failed to link code to user_id")

        # Letting world burn if user was not in db. Fail fast, fail hard.

    def storeSurrogateJSON(self, DictionaryToStore):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            cursor.execute("INSERT INTO surrogate_and_user_mapping (user_id, surrogate_id) \
                VALUES (%s, %s)", [key, dumps(DictionaryToStore[key])])
            db.commit()
        db.close()
            
def read_key(path, password=None):
    ##
    # Read RSA key from PEM file and return JWK object of it.
    ##
    try:
        from Service_Mockup.instance.settings import cert_password_path
        with open(cert_password_path, "r") as pw_file:
            password = pw_file.readline()
    except Exception as e:
        password = None
        pass
    if password is not None:  # Remove trailing line end if it exists
        password = password.strip("\n")

    from jwcrypto import jwk
    from jwkest.jwk import RSAKey
    with open(path, "r") as f:
        pem_data = f.read()
    try:
        rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=password), use='sig')
    except ValueError as e:
        while True:
            pw = input("Please enter password for PEM file: ")
            try:
                rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=pw), use='sig')
                save_pw = bool(str(input("Should the password be saved?(True/False): ")).capitalize())
                if save_pw:
                    with open("./cert_pw", "w+") as pw_file:
                        pw_file.write(pw)
                break

            except Exception as e:
                print(repr(e))
                print("Password may have been incorrect. Try again or terminate.")

    jwssa = jwk.JWK(**rsajwk.to_dict())
    return jwssa


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

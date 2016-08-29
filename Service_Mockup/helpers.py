# -*- coding: utf-8 -*-
import importlib
import pkgutil

from Crypto.PublicKey.RSA import importKey as import_rsa_key
from flask import Blueprint
from flask_restful import Api


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

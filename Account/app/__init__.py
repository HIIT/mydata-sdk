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

import sys

from app.helpers import ApiError, make_json_response, get_custom_logger

reload(sys)
sys.setdefaultencoding('utf-8')

# print("Current value of the recursion limit: " + str(sys.getrecursionlimit()))


# Import flask and template operators
from flask import Flask, render_template, Blueprint, json, make_response
from flask_restful import Resource, Api
from flask.ext.mysqldb import MySQL
from flask.ext.login import LoginManager

# Define the WSGI application object
app = Flask(__name__)

# Configurations
app.config.from_object('config')

# LoginManager
# https://flask-login.readthedocs.org/en/latest/
# TODO: Validate next()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = app.config["LOGIN_VIEW"]
login_manager.login_message = app.config["LOGIN_MESSAGE"]
login_manager.session_protection = app.config["SESSION_PROTECTION"]

# Database
db = MySQL(app)

# =========================================
# Flask-restful
# add prefix here or it won't work when you register blueprint
# =========================================
api = Api(app, prefix=app.config["URL_PREFIX"])


@app.before_request
def new_request():
    print("New Request")
    print("############")


@app.errorhandler(404)
def not_found(error):
    not_found_error = ApiError(code=404, title="Not Found", detail="Endpoint not found", status="NotFound")
    error_dict = not_found_error.to_dict()
    return make_json_response(errors=error_dict, status_code=str(error_dict['code']))


@app.errorhandler(ApiError)
def handle_apierror(error):
    error_dict = error.to_dict()
    logger = get_custom_logger(logger_name="ApiError")
    logger.error(json.dumps(error_dict))
    return make_json_response(errors=error_dict, status_code=str(error_dict['code']))


# Import a module / component using its blueprint handler variable
from app.mod_auth.controllers import mod_auth
from app.mod_api_auth.view_api import mod_api_auth
from app.mod_account.view_html import mod_account_html
from app.mod_account.view_api import mod_account_api
from app.mod_service.view_api import mod_service_api
from app.mod_authorization.view_api import mod_authorization_api
from app.mod_system.controllers import mod_system


# Register blueprint(s)
app.register_blueprint(mod_auth)
app.register_blueprint(mod_api_auth)
app.register_blueprint(mod_account_html)
app.register_blueprint(mod_account_api)
app.register_blueprint(mod_service_api)
app.register_blueprint(mod_system)
app.register_blueprint(mod_authorization_api)


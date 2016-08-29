# -*- coding: utf-8 -*-
from functools import wraps
from flask_restful import Api
import logging
import factory

def create_app(settings_override=None, register_security_blueprint=False):
    """Returns the Overholt API application instance"""

    app, apis = factory.create_app(__name__, __path__, settings_override,
                             register_security_blueprint=register_security_blueprint)

    debug_log = logging.getLogger("debug")
    debug_log.info("Started up Service Components, Service_Mgmnt module successfully.")

    # @app.after_request
    # def magic(response):
    #     print("It happens")
    #     return response

    return app
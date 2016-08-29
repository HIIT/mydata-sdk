# -*- coding: utf-8 -*-
import logging
from functools import wraps
from flask import make_response
#import xmltodict


import factory
from json import dumps

def create_app(settings_override=None, register_security_blueprint=False):
    """Returns the Overholt API application instance"""

    app, apis = factory.create_app(__name__, __path__, settings_override,
                             register_security_blueprint=register_security_blueprint)
    debug_log = logging.getLogger("debug")
    debug_log.info("Started up Operator Components, Operator_SLR module successfully.")
    # for api in apis:
    #     @api.representation('application/xml')
    #     def output_xml(data, code, headers=None):
    #         if isinstance(data, dict):
    #             xm = {"response": data}
    #             resp = make_response(xmltodict.unparse(xm, pretty=True), code)
    #             resp.headers.extend(headers)
    #             return resp

    return app
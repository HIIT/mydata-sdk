# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

from flask import Blueprint, make_response
from flask_restful import Resource, Api

from DetailedHTTPException import DetailedHTTPException, error_handler

api_Root_blueprint = Blueprint("api_Root_blueprint", __name__)
api = Api()
api.init_app(api_Root_blueprint)
import json

@api.representation('application/json')
def output_json(data, code, headers=None):
    if isinstance(data, dict):
        xm = json.dumps(data, indent=2)
        resp = make_response(xm, code)
        resp.headers.extend(headers)
        return resp

# import xmltodict
# @api.representation('application/xml')
# def output_xml(data, code, headers=None):
#     if isinstance(data, dict):
#         xm = {"response": data}
#         resp = make_response(xmltodict.unparse(xm, pretty=True), code)
#         resp.headers.extend(headers)
#         return resp

class Root(Resource):
    #@error_handler
    def get(self):

        status = '{"status": "running"}'
        return json.loads(status)


api.add_resource(Root, '/')


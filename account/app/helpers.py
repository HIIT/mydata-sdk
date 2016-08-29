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

import logging
from logging.handlers import TimedRotatingFileHandler
from os.path import isdir
from datetime import datetime
from functools import wraps

from flask import json

# https://docs.python.org/3/howto/urllib2.html#httperror
http_responses = {
    100: ('Continue', 'Request received, please continue'),
    101: ('Switching Protocols', 'Switching to new protocol; obey Upgrade header'),

    200: ('OK', 'Request fulfilled, document follows'),
    201: ('Created', 'Document created, URL follows'),
    202: ('Accepted', 'Request accepted, processing continues off-line'),
    203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
    204: ('No Content', 'Request fulfilled, nothing follows'),
    205: ('Reset Content', 'Clear input form for further input.'),
    206: ('Partial Content', 'Partial content follows.'),

    300: ('Multiple Choices', 'Object has several resources -- see URI list'),
    301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
    302: ('Found', 'Object moved temporarily -- see URI list'),
    303: ('See Other', 'Object moved -- see Method and URL list'),
    304: ('Not Modified', 'Document has not changed since given time'),
    305: ('Use Proxy', 'You must use proxy specified in Location to access this resource.'),
    307: ('Temporary Redirect', 'Object moved temporarily -- see URI list'),

    400: ('Bad Request', 'Bad request syntax or unsupported method'),
    401: ('Unauthorized', 'No permission -- see authorization schemes'),
    402: ('Payment Required', 'No payment -- see charging schemes'),
    403: ('Forbidden', 'Request forbidden -- authorization will not help'),
    404: ('Not Found', 'Nothing matches the given URI'),
    405: ('Method Not Allowed', 'Specified method is invalid for this server.'),
    406: ('Not Acceptable', 'URI not available in preferred format.'),
    407: ('Proxy Authentication Required', 'You must authenticate with ' 'this proxy before proceeding.'),
    408: ('Request Timeout', 'Request timed out; try again later.'),
    409: ('Conflict', 'Request conflict.'),
    410: ('Gone', 'URI no longer exists and has been permanently removed.'),
    411: ('Length Required', 'Client must specify Content-Length.'),
    412: ('Precondition Failed', 'Precondition in headers is false.'),
    413: ('Request Entity Too Large', 'Entity is too large.'),
    414: ('Request-URI Too Long', 'URI is too long.'),
    415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
    416: ('Requested Range Not Satisfiable', 'Cannot satisfy request range.'),
    417: ('Expectation Failed', 'Expect condition could not be satisfied.'),
    500: ('Internal Server Error', 'Server got itself in trouble'),
    501: ('Not Implemented', 'Server does not support this operation'),
    502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
    503: ('Service Unavailable', 'The server cannot process the request due to a high load'),
    504: ('Gateway Timeout', 'The gateway server did not receive a timely response'),
    505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
}


def get_custom_logger(logger_name='default_logger'):
    # TODO: Is it ok to import here?
    from os import mkdir
    from app import app

    # Logging levels
    # CRITICAL
    # ERROR
    # WARNING
    # INFO
    # DEBUG
    # NOTSET

    # If there is no directory './logs', it will be created
    if app.config["LOG_PATH"] != "./":
        if not isdir(app.config["LOG_PATH"]):
            try:
                mkdir(app.config["LOG_PATH"])
                print("Creating LOG_PATH: '{}'.".format(app.config["LOG_PATH"]))
            except IOError:
                print("LOG_PATH: '{}' already exists.".format(app.config["LOG_PATH"]))
            except Exception as e:
                print("LOG_PATH: '{}' could not be created. Exception: {}.".format(app.config["LOG_PATH"], repr(e)))

    logger = logging.getLogger(logger_name)

    if len(logger.handlers) == 0:
        # TODO: This can not be correct solution
        logger.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter(app.config["LOG_FORMATTER"])

        # console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # file handler
        if app.config["LOG_TO_FILE"]:
            file_handler = TimedRotatingFileHandler(app.config["LOG_FILE"], when="midnight", interval=1, backupCount=10, utc=True)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


def make_json_response(data=None, errors=None, status_code=200):

    logger = get_custom_logger(logger_name="make_json_response")

    headers = {}
    response_data = {}

    if data is not None:
        try:
            response_data = dict(data)
            logger.debug("data was dict()")
        except TypeError:
            try:
                response_data = str(data)
                logger.debug("data was str()")
            except TypeError:
                try:
                    response_data = repr(data)
                    logger.debug("data was repr()")
                except TypeError as e:
                    data_error = {'0': repr(e)}
                    # TODO: Change status code
                    raise ApiError(code=418, title="Unknown data format", detail=data_error, source="make_json_response()")
        try:
            response_data = dict(response_data)
        except Exception as e:
            data_error = {'0': repr(e)}
            # TODO: Change status code
            raise ApiError(code=418, title="response_data[data] could not be parsed to dict", detail=data_error, source="make_json_response()")

    if errors is not None:
        response_data['errors'] = dict(errors)

    response_data = dict(response_data)

    # To fix strange json encoding behaviour
    # TODO: Get rid of this
    if errors is not None:
        logger.debug("response_data: " + json.dumps(response_data))
        response_data = json.dumps(response_data, sort_keys=True, indent=4)
    else:
        logger.debug("response_data: " + json.dumps(response_data))

    # http://flask.pocoo.org/snippets/83/
    # response = jsonify(message=str(ex))
    # response.status_code = status_code
    # return response
    logger.info("Resposne status code: " + str(status_code))
    return response_data, status_code, headers  # Return formatting: http://flask-restful-cn.readthedocs.org/en/0.3.5/quickstart.html#resourceful-routing


class ApiError(Exception):
    status = ""
    code = ""
    title = ""
    detail = ""
    source = ""

    def __init__(self, code=None, title=None, detail=None, source=None, status=None):
        if code is not None:
            self.code = code
            try:
                self.status = http_responses[int(code)][0] + ", " + http_responses[int(code)][1]
            except Exception:
                self.status = ""
        if status is not None:
            self.status = status
        if title is not None:
            self.title = title
        if detail is not None:
            self.detail = detail
        if source is not None:
            self.source = source

    def to_dict(self):
        rv = {}
        if self.status is not None:
            rv['status'] = str(self.status)
        if self.code is not None:
            rv['code'] = str(self.code)
        if self.title is not None:
            rv['title'] = str(self.title)
        if self.source is not None:
            rv['source'] = str(self.source)
        if self.detail is not None:
            try:
                rv['detail'] = dict(self.detail)
            except Exception:
                try:
                    rv['detail'] = str(self.detail)
                except Exception:
                    try:
                        rv['detail'] = repr(self.detail)
                    except Exception:
                        rv['detail'] = "Unknown error detail format"
            return rv


def get_utc_time():
    """
    Returns ISO 8601 Date

    :return:
    """

    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# -*- coding: utf-8 -*-
from uuid import uuid4 as guid
from werkzeug.exceptions import HTTPException
from json import dumps
import traceback
from importlib import import_module
from instance.settings import DEBUG_MODE
from requests import status_codes


def error_handler(method):
    def wrapper(self, *args, **kw):
        app = import_module(method.__module__)
        api = app.api
        try:  # If we get DetailedHTTPException we want to show some additional debug to it
            try:  # Incase we fail with something else then DetailedHTTPException, wrap it in one, else raise it.
                result = method(self, *args, **kw)
                return result
            except DetailedHTTPException as e:
                print(e.trace, type(e.trace))
                if e.trace is None:
                    e.trace = traceback.format_exc(limit=100).splitlines()
                    print(e.trace)
                raise e
            except Exception as e:
                trace = traceback.format_exc(limit=100).splitlines()
                raise DetailedHTTPException(exception=e, trace=trace)
        except DetailedHTTPException as e:
            # Need for this can be questioned. It reduces portability of the decorator.
            if (DEBUG_MODE):
                print(e.trace)
                try:
                    location_url = api.url_for(method)  # This is a handy feature but as before, reduces portability.
                except:
                    location_url = "Not resolved"
                # location = repr(method).split(" ")[1]
                if (e.error["errors"][e.count]["source"] is None):
                    e.error["errors"][e.count]["source"] = location_url
                    e.error["errors"][e.count]["trace"] = e.trace
                print(dumps(e.error, indent=2))
                return e.error, e.code
            else:
                return {"errors": {"detail": e.detail,
                                   "title": e.title,
                                   "source": e.source,
                                   "status": status_codes._codes[e.code][0].replace("_", " ").capitalize(),
                                   "code": str(e.code)}}, e.code

    return wrapper


class DetailedHTTPException(HTTPException):
    def __init__(self, status=None, source=None, title="An Error occurred", detail=None, exception=None, trace=None):
        HTTPException.__init__(self)
        self.count = 0
        self.code = status
        self.detail = detail
        self.title = title
        self.trace = trace
        self.source = source
        self.error = {
            "errors": []
        }

        if exception is not None:
            try:
                raise exception
            except DetailedHTTPException as e:
                self.count = exception.count + 1
                if (self.code is None):
                    self.code = e.code
                for errors in e.error["errors"]:
                    print(errors)
                    self.error["errors"].append(errors)
            # Incase of general exception.
            except Exception as e:
                if self.detail is None:
                    self.detail = {"Error": repr(e)}
                if self.code is None:
                    self.code = 500
                if self.title is None:
                    self.title = repr(e)
        if self.detail is None:
            self.detail = "An unspecified Error has occurred"
        if self.code is None:
            self.code = 500

        uuid = str(guid())
        er = {
            "id": uuid,
            "status": self.code,
            "source": self.source,
            "trace": self.trace,
            "title": self.title,
            "detail": self.detail,
            "count": self.count
        }
        self.error["errors"].append(er)
        self.description = dumps(self.error, indent=3)


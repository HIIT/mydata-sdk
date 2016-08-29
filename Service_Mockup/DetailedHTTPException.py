# -*- coding: utf-8 -*-
from uuid import uuid4 as guid
from werkzeug.exceptions import HTTPException
from json import dumps
import traceback
from importlib import import_module



def error_handler(method):
    SUPER_DEBUG = True
    app = import_module(method.__module__)
    api = app.api
    def wrapper(self, *args, **kw):
        try: # If we get DetailedHTTPException we want to show some additional debug to it
            try:  # Incase we fail with something else then DetailedHTTPException, wrap it in one, else raise it.
                result = method(self, *args, **kw)
                return result
            except DetailedHTTPException as e:
                raise e
            except Exception as e:
                raise DetailedHTTPException(exception=e)
        except DetailedHTTPException as e:
            #Need for this can be questioned. It reduces portability of the decorator.
            if (SUPER_DEBUG):

                try:
                    location_url = api.url_for(self) # This is a handy feature but as before, reduces portability.
                except:
                    location_url = "Not resolved"
                # location = repr(method).split(" ")[1]
                if (e.error["errors"][e.count]["source"] is None):
                    e.error["errors"][e.count]["source"] = location_url
                    e.error["errors"][e.count]["trace"] = traceback.format_exc(limit=100).splitlines()
                print("Returning following JSON and {}".format(e.code))
                print(dumps(e.error, indent=2))

                return e.error, e.code
            else:
                return dumps({e.code: {"detail": e.detail, "title": e.title, "source":e.source}}, indent=2)

    return wrapper


class DetailedHTTPException(HTTPException):
    def __init__(self, status=None, source=None, title="An Error occurred", detail=None, exception=None, ):
        HTTPException.__init__(self)
        self.count = 0
        self.code = status
        self.detail = detail
        self.title = title
        self.source = source
        self.error = {
            "errors": [ ]
        }

        if exception is not None:
            try:
                raise exception
            except DetailedHTTPException as e:
                self.count = exception.count + 1
                if(self.code is None):
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
        er =     {
                    "id": uuid,
                    "status": self.code,
                    "source": self.source,
                    "title": self.title,
                    "detail": self.detail,
                    "count": self.count
                }
        self.error["errors"].append(er)
        self.description = dumps(self.error, indent=3)
        # Loggaus koodia tähän uuid tunnisteen kanssa?

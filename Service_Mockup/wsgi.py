# -*- coding: utf-8 -*-
"""
    wsgi
    ~~~~
    overholt wsgi module
"""

from werkzeug.serving import run_simple
from werkzeug.wsgi import DispatcherMiddleware

import Service
import Service_Root


import logging

logger = logging.getLogger("sequence")
try:
    from restapi_logging_handler import RestApiHandler

    restapihandler = RestApiHandler("http://localhost:9004/")
    logger.addHandler(restapihandler)

except Exception as e:
    pass
logger.setLevel(logging.INFO)

debug_log = logging.getLogger("debug")
logging.basicConfig()
debug_log.setLevel(logging.INFO)
service_app = Service.create_app()
application = DispatcherMiddleware(Service_Root.create_app(),
                                   {"/api/1.2/cr": service_app, # TODO We are spawning two service_app with different base path but same end points!
                                   "/api/1.2/slr": service_app})

if __name__ == "__main__":
    run_simple('0.0.0.0', 2000, application, use_reloader=False, use_debugger=False, threaded=True)
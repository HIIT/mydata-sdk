# -*- coding: utf-8 -*-
"""
    wsgi
    ~~~~
    overholt wsgi module
"""

from werkzeug.serving import run_simple
from werkzeug.wsgi import DispatcherMiddleware

import Service_Mgmnt
import Service_Root
import Authorization_Management



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

from instance.settings import SERVICE_ROOT_PATH, SERVICE_CR_PATH, SERVICE_SLR_PATH

application = DispatcherMiddleware(Service_Root.create_app(),
                                   {
                                    SERVICE_ROOT_PATH+SERVICE_SLR_PATH: Service_Mgmnt.create_app(),
                                    SERVICE_ROOT_PATH+SERVICE_CR_PATH: Authorization_Management.create_app()
                                    }
                                   )

if __name__ == "__main__":
    run_simple('0.0.0.0', 7000, application, use_reloader=False, use_debugger=False, threaded=True)
# -*- coding: utf-8 -*-
import logging

import factory


def create_app(settings_override=None, register_security_blueprint=False):
    """Returns the Overholt API application instance"""

    app, apis = factory.create_app(__name__, __path__, settings_override,
                             register_security_blueprint=register_security_blueprint)
    #app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
    #app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'
    #celery = Celery(__name__, broker=app.config['CELERY_BROKER_URL'])
    #celery.conf.update(api_CR_blueprint.config)
    #app.config["CELERY_INSTANCE"] =
    debug_log = logging.getLogger("debug")
    debug_log.info("Started up Operator Components, Operator_CR module successfully.")

    return app
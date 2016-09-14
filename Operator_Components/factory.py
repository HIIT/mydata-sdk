# -*- coding: utf-8 -*-
"""
    overholt.factory
    ~~~~~~~~~~~~~~~~
    overholt factory module
"""

import os

from celery import Celery
from flask import Flask
from flask_restful import Api
from helpers import register_blueprints



def create_app(package_name, package_path, settings_override=None,
               register_security_blueprint=False):
    """Returns a :class:`Flask` application instance configured with common
    functionality for the Overholt platform.
    :param package_name: application package name
    :param package_path: application package path
    :param settings_override: a dictionary of settings to override
    :param register_security_blueprint: flag to specify if the Flask-Security
                                        Blueprint should be registered. Defaults
                                        to `True`.
    """
    app = Flask(package_name, instance_relative_config=True)
    app.config.from_pyfile('settings.py', silent=False)
    app.config.from_object(settings_override)

    rv, apis  =register_blueprints(app, package_name, package_path)

    return app, apis


def create_celery_app(app=None):
    if app is not None:
        app = app
    else:
        app, apis = create_app('operator_component', os.path.dirname(__file__))
    celery = Celery(__name__, broker=app.config['SELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery
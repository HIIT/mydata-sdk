# -*- coding: utf-8 -*-

"""
Minimum viable Key management. NOT FOR PRODUCTION USE.


__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""
import inspect
import json
import logging
from logging.handlers import TimedRotatingFileHandler
from os.path import isdir, dirname, abspath
from os import mkdir


def append_description_to_exception(exp=None, description=None):
    """
    Adds additional description to Exception. As result original Exception can be reraised with additional information
    http://stackoverflow.com/questions/9157210/how-do-i-raise-the-same-exception-with-a-custom-message-in-python

    :param exp: Exception
    :param description: Description to add as String
    :return: Exception
    """
    if exp is None:
        raise AttributeError("Provide exp as parameter")
    if description is None:
        raise AttributeError("Provide description as parameter")

    if not exp.args:
        exp.args = ('',)

    try:
        description = str(description)
    except Exception:
        try:
            description = repr(description)
        except Exception:
            description = 'Description could not be converted to string'

    exp.args = exp.args + (description,)
    return exp


class KeyNotFoundError(StandardError):
    """
    Exception to indicate that there were no key for user account in database.

     https://docs.python.org/2/tutorial/errors.html#user-defined-exceptions
    """
    pass


def get_custom_logger(logger_name='default_logger'):
    """
    Creates logger instance.

    :param logger_name: Name for logger
    :return: Logger object
    """

    LOG_TO_FILE = False
    DELIMITTER = '/'
    LOG_PATH = dirname(abspath(__file__)) + DELIMITTER + 'logs'
    LOG_FILE = LOG_PATH + DELIMITTER + 'blackbox.log'
    LOG_FORMATTER = '%(asctime)s - %(name)s in function %(funcName)s at line: %(lineno)s - %(levelname)s - %(message)s'

    # If there is no directory './logs', it will be created
    if not isdir(LOG_PATH):
        try:
            mkdir(LOG_PATH)
            print("Creating LOG_PATH: '{}'.".format(LOG_PATH))
        except IOError:
            print("LOG_PATH: '{}' already exists.".format(LOG_PATH))
        except Exception as e:
            print("LOG_PATH: '{}' could not be created. Exception: {}.".format(LOG_PATH, repr(e)))

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter(LOG_FORMATTER)

    # console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # file handler
    if LOG_TO_FILE:
        file_handler = TimedRotatingFileHandler(LOG_FILE, when="midnight", interval=1, backupCount=10, utc=True)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def jws_header_fix(malformed_jws_json=None):
    """
    Fixes malformed header object after jws.serialize().
    For some reason serialization messes up "header" from "header": {} to "header": "{}"

    Function does not check if header field in given dictionary is malformed, it's expecting it to be.

    :param malformed_jws_json: JSON presentation of JWS with malformed header field
    :return: JSON presentation of JWS fixed header field.
    """
    try:
        fixed_jws_json = malformed_jws_json.replace('"{', '{').replace('}"', '}').replace('\\"', '"')
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fix header in JWS json')
        raise
    else:
        return fixed_jws_json


def get_current_line_no():
    """
    Returns the current line number program.
    :return: Line number
    """
    return inspect.currentframe().f_back.f_lineno

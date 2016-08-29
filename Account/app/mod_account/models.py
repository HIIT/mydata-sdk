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

# Import dependencies
from marshmallow import Schema, fields, validates, ValidationError
from marshmallow.validate import Range, Regexp, ContainsOnly, Equal

GENERAL_STRING_MIN_LENGTH = 3
GENERAL_STRING_MAX_LENGTH = 100
GENERAL_REGEX = "[a-zA-Z]+"

USERNAME_MIN = GENERAL_STRING_MIN_LENGTH
USERNAME_MAX = GENERAL_STRING_MAX_LENGTH
USERNAME_REGEX = "[a-zA-Z0-9!#¤%&/()=?+_-]+"

PASSWORD_MIN = GENERAL_STRING_MIN_LENGTH
PASSWORD_MAX = GENERAL_STRING_MAX_LENGTH
PASSWORD_REGEX = "[a-zA-Z0-9!#¤%&/()=?+_-]+"

FIRSTNAME_MIN = GENERAL_STRING_MIN_LENGTH
FIRSTNAME_MAX = GENERAL_STRING_MAX_LENGTH
FIRSTNAME_REGEX = GENERAL_REGEX

LASTNAME_MIN = GENERAL_STRING_MIN_LENGTH
LASTNAME_MAX = GENERAL_STRING_MAX_LENGTH
LASTNAME_REGEX = GENERAL_REGEX

class BaseSchema(Schema):
    type = fields.Str()


class AccountSchema(BaseSchema):
    username = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=USERNAME_MIN, max=USERNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                              ),
                              Regexp(regex=USERNAME_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    password = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=USERNAME_MIN, max=USERNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                              ),
                              Regexp(regex=PASSWORD_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    firstName = fields.Str(required=True,
                           validate=[
                               Range(
                                   min=FIRSTNAME_MIN, max=FIRSTNAME_MAX,
                                   error='Got: {input} as input, should be between {min} - {max}.'
                               ),
                               Regexp(regex=FIRSTNAME_REGEX, error="'{input}' not matching to '{regex}'")
                           ])

    lastName = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=LASTNAME_MIN, max=LASTNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                               ),
                              Regexp(regex=LASTNAME_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    email = fields.Email(required=True, error='Email not valid')
    dateOfBirth = fields.Date(required=True, error='Not valid date. Provide ISO8601-formatted date string.')
    acceptTermsOfService = fields.Bool(required=True, validate=[ContainsOnly(choices='True')])


class AccountSchema2(BaseSchema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    firstName = fields.Str(required=True)
    lastName = fields.Str(required=True)
    email = fields.Email(required=True)
    dateOfBirth = fields.Date(required=True, error='Not valid date. Provide ISO8601-formatted date string.')
    acceptTermsOfService = fields.Str(required=True, validate=Equal("True"))

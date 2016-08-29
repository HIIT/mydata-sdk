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
from marshmallow import Schema, fields
from marshmallow.validate import Equal, OneOf


class SlrAttributes(Schema):
    version = fields.Str(required=True)
    link_id = fields.Str(required=True)
    operator_id = fields.Str(required=True)
    service_id = fields.Str(required=True)
    surrogate_id = fields.Str(required=True)
    token_key = fields.Dict(required=True)
    operator_key = fields.Dict(required=True)
    cr_keys = fields.Str(required=True)
    created = fields.Str(required=True)


class SurrogateAttributes(Schema):
    surrogate_id = fields.Str(required=True)
    service_id = fields.Str(required=True)
    account_id = fields.Str(required=True)

class SlrContent(Schema):
    type = fields.Str(required=True, validate=Equal("ServiceLinkRecord"))
    attributes = fields.Nested(nested=SlrAttributes, required=True)


class SurrogateContent(Schema):
    type = fields.Str(required=True, validate=Equal("SurrogateId"))
    attributes = fields.Nested(nested=SurrogateAttributes, required=True)


class NewServiceLinkData(Schema):
    slr = fields.Nested(nested=SlrContent, required=True)
    surrogate_id = fields.Nested(nested=SurrogateContent, required=True)


class NewServiceLink(Schema):
    data = fields.Nested(nested=NewServiceLinkData, required=True)
    code = fields.Str(required=True)


############
class SsrAttributes(Schema):
    record_id = fields.Str(required=True)
    account_id = fields.Str(required=True)
    slr_id = fields.Str(required=True)
    sl_status = fields.Str(required=True, validate=OneOf(["Active", "Removed"]))
    iat = fields.Str(required=True)
    prev_record_id = fields.Str(required=True)


class SsrContent(Schema):
    type = fields.Str(required=True, validate=Equal("ServiceLinkStatusRecord"))
    attributes = fields.Nested(nested=SsrAttributes, required=True)


class SlrData(Schema):
    slr = fields.Dict(required=True)


class Slr(Schema):
    type = fields.Str(required=True, validate=Equal("ServiceLinkRecord"))
    attributes = fields.Nested(nested=SlrData, required=True)


class VerifyServiceLinkData(Schema):
    slr = fields.Nested(nested=Slr, required=True)
    ssr = fields.Nested(nested=SsrContent, required=True)
    surrogate_id = fields.Nested(nested=SurrogateContent, required=True)


class VerifyServiceLink(Schema):
    data = fields.Nested(nested=VerifyServiceLinkData, required=True)
    code = fields.Str(required=True)

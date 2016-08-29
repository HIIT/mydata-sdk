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



class ConsentStatusAttributes(Schema):
    record_id = fields.Str(required=True)
    account_id = fields.Str(required=True)
    cr_id = fields.Str(required=True)
    consent_status = fields.Str(required=True)
    iat = fields.Str(required=True)
    prev_record_id = fields.Str(required=True)


class ConsentStatusPayload(Schema):
    type = fields.Str(required=True, validate=Equal("ConsentStatusRecord"))
    attributes = fields.Nested(nested=ConsentStatusAttributes, required=True)


class CommonConsentAttributes(Schema):
    version_number = fields.Str(required=True)
    cr_id = fields.Str(required=True)
    surrogate_id = fields.Str(required=True)
    rs_id = fields.Str(required=True)
    slr_id = fields.Str(required=True)
    issued = fields.Str(required=True)
    not_before = fields.Str(required=True)
    not_after = fields.Str(required=True)
    issued_at = fields.Str(required=True)
    subject_id = fields.Str(required=True)


class DataSet(Schema):
    dataset_id = fields.Str(required=True)
    distribution_id = fields.Str(required=True)


class ResourceSet(Schema):
    rs_id = fields.Str(required=True)
    dataset = fields.Nested(nested=DataSet, required=True, many=True)


class ResourceSetDescription(Schema):
    resource_set = fields.Nested(nested=ResourceSet, required=True)


class SourceRoleSpecificAttributes(Schema):
    role = fields.Str(required=True, validate=OneOf(["Source", "InternalProcessing"]))
    auth_token_issuer_key = fields.Dict(required=True)
    resource_set_description = fields.Nested(nested=ResourceSetDescription, required=True)


class UsageRules(Schema):
    rule = fields.Str(required=True)


class SinkRoleSpecificAttributes(Schema):
    role = fields.Str(required=True, validate=OneOf(["Sink", "InternalProcessing"]))
    #usage_rules = fields.Nested(nested=UsageRules, only=UsageRules.rule, many=True, required=True)
    usage_rules = fields.Field(required=True)


class SinkConsentAttributes(Schema):
    common_part = fields.Nested(nested=CommonConsentAttributes, required=True)
    role_specific_part = fields.Nested(nested=SinkRoleSpecificAttributes, required=True)
    ki_cr = fields.Dict(required=True)
    extensions = fields.Dict(required=True)


class SourceConsentAttributes(Schema):
    common_part = fields.Nested(nested=CommonConsentAttributes, required=True)
    role_specific_part = fields.Nested(nested=SourceRoleSpecificAttributes, required=True)
    ki_cr = fields.Dict(required=True)
    extensions = fields.Dict(required=True)


class SourceConsentPayload(Schema):
    type = fields.Str(required=True, validate=Equal("ConsentRecord"))
    attributes = fields.Nested(nested=SourceConsentAttributes, required=True)


class SinkConsentPayload(Schema):
    type = fields.Str(required=True, validate=Equal("ConsentRecord"))
    attributes = fields.Nested(nested=SinkConsentAttributes, required=True)


class SourceConsentPayloads(Schema):
    consentRecordPayload = fields.Nested(nested=SourceConsentPayload, required=True)
    consentStatusRecordPayload = fields.Nested(nested=ConsentStatusPayload, required=True)


class SinkConsentPayloads(Schema):
    consentRecordPayload = fields.Nested(nested=SinkConsentPayload, required=True)
    consentStatusRecordPayload = fields.Nested(nested=ConsentStatusPayload, required=True)


class NewConsentData(Schema):
    source = fields.Nested(nested=SourceConsentPayloads, required=True)
    sink = fields.Nested(nested=SinkConsentPayloads, required=True)


class NewConsent(Schema):
    data = fields.Nested(nested=NewConsentData, required=True)


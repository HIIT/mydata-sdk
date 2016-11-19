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

STATUS_LIST = ["Active", "Disabled", "Withdrawn"]  # List that contains status entries


# Consent Status Records
class ConsentStatusAttributes(Schema):
    record_id = fields.Str(required=True)
    surrogate_id = fields.Str(required=True)
    cr_id = fields.Str(required=True)
    consent_status = fields.Str(required=True, validate=OneOf(STATUS_LIST))
    iat = fields.Int(required=True)
    prev_record_id = fields.Str(required=True)


class ConsentStatusPayload(Schema):
    type = fields.Str(required=True, validate=Equal("ConsentStatusRecord"))
    attributes = fields.Nested(nested=ConsentStatusAttributes, required=True)


# Consent Records
class DataSet(Schema):
    dataset_id = fields.Str(required=True)
    distribution_id = fields.Str(required=True)


class ResourceSet(Schema):
    rs_id = fields.Str(required=True)
    dataset = fields.Nested(nested=DataSet, required=True, many=True)


class ResourceSetDescription(Schema):
    resource_set = fields.Nested(nested=ResourceSet, required=True)


class SourceCommonConsentAttributes(Schema):
    version = fields.Str(required=True)
    cr_id = fields.Str(required=True)
    surrogate_id = fields.Str(required=True)
    rs_description = fields.Nested(nested=ResourceSetDescription, required=True)
    slr_id = fields.Str(required=True)
    iat = fields.Int(required=True)
    nbf = fields.Int(required=True)
    exp = fields.Int(required=True)
    operator = fields.Str(required=True)
    subject_id = fields.Str(required=True)
    role = fields.Str(required=True, validate=Equal("Source"))


class SinkCommonConsentAttributes(Schema):
    version = fields.Str(required=True)
    cr_id = fields.Str(required=True)
    surrogate_id = fields.Str(required=True)
    rs_description = fields.Nested(nested=ResourceSetDescription, required=True)
    slr_id = fields.Str(required=True)
    iat = fields.Int(required=True)
    nbf = fields.Int(required=True)
    exp = fields.Int(required=True)
    operator = fields.Str(required=True)
    subject_id = fields.Str(required=True)
    role = fields.Str(required=True, validate=Equal("Sink"))


class SourceRoleSpecificAttributes(Schema):
    pop_key = fields.Dict(required=True)
    token_issuer_key = fields.Dict(required=True)


# class UsageRules(Schema):
#     rule = fields.Str(required=True)


class SinkRoleSpecificAttributes(Schema):
    #usage_rules = fields.Nested(nested=UsageRules, only=UsageRules.rule, many=True, required=True)
    usage_rules = fields.Field(required=True)
    source_cr_id = fields.Str(required=True)


class ConsentReceiptPart(Schema):
    ki_cr = fields.Dict(required=True)


class ExtensionPart(Schema):
    extensions = fields.Dict(required=True)


class SinkConsentAttributes(Schema):
    common_part = fields.Nested(nested=SinkCommonConsentAttributes, required=True)
    role_specific_part = fields.Nested(nested=SinkRoleSpecificAttributes, required=True)
    consent_receipt_part = fields.Nested(nested=ConsentReceiptPart, required=True)
    extension_part = fields.Nested(nested=ExtensionPart, required=True)


class SourceConsentAttributes(Schema):
    common_part = fields.Nested(nested=SourceCommonConsentAttributes, required=True)
    role_specific_part = fields.Nested(nested=SourceRoleSpecificAttributes, required=True)
    consent_receipt_part = fields.Nested(nested=ConsentReceiptPart, required=True)
    extension_part = fields.Nested(nested=ExtensionPart, required=True)


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


class NewConsentStatus(Schema):
    data = fields.Nested(nested=ConsentStatusPayload, required=True)


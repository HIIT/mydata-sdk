# -*- coding: utf-8 -*-
from time import time
import logging
from json import dumps, loads

from base64 import urlsafe_b64decode as decode


from base64 import urlsafe_b64decode as decode
from json import loads
from jwcrypto import jws, jwk

#### Schemas
source_cr_schema = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "extensions": {
      "type": "object",
      "properties": {}
    },
    "ki_cr": {
      "type": "object",
      "properties": {}
    },
    "common_part": {
      "type": "object",
      "properties": {
        "issued_at": {
          "type": "string"
        },
        "surrogate_id": {
          "type": "string"
        },
        "subject_id": {
          "type": "string"
        },
        "cr_id": {
          "type": "string"
        },
        "version_number": {
          "type": "string"
        },
        "not_before": {
          "type": "string"
        },
        "slr_id": {
          "type": "string"
        },
        "issued": {
          "type": "string"
        },
        "not_after": {
          "type": "string"
        },
        "rs_id": {
          "type": "string"
        }
      },
      "required": [
        "issued_at",
        "surrogate_id",
        "subject_id",
        "cr_id",
        "version_number",
        "not_before",
        "slr_id",
        "issued",
        "not_after",
        "rs_id"
      ]
    },
    "role_specific_part": {
      "type": "object",
      "properties": {
        "auth_token_issuer_key": {
          "type": "object",
          "properties": {}
        },
        "role": {
          "type": "string"
        },
        "resource_set_description": {
          "type": "object",
          "properties": {
            "resource_set": {
              "type": "object",
              "properties": {
                "rs_id": {
                  "type": "string"
                },
                "dataset": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "distribution_id": {
                        "type": "string"
                      },
                      "dataset_id": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "distribution_id",
                      "dataset_id"
                    ]
                  }
                }
              },
              "required": [
                "rs_id",
                "dataset"
              ]
            }
          },
          "required": [
            "resource_set"
          ]
        }
      },
      "required": [
        "auth_token_issuer_key",
        "role",
        "resource_set_description"
      ]
    }
  },
  "required": [
    "extensions",
    "ki_cr",
    "common_part",
    "role_specific_part"
  ]
}

sink_cr_schema = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "extensions": {
      "type": "object",
      "properties": {}
    },
    "ki_cr": {
      "type": "object",
      "properties": {}
    },
    "common_part": {
      "type": "object",
      "properties": {
        "issued_at": {
          "type": "string"
        },
        "surrogate_id": {
          "type": "string"
        },
        "subject_id": {
          "type": "string"
        },
        "cr_id": {
          "type": "string"
        },
        "version_number": {
          "type": "string"
        },
        "not_before": {
          "type": "string"
        },
        "slr_id": {
          "type": "string"
        },
        "issued": {
          "type": "string"
        },
        "not_after": {
          "type": "string"
        },
        "rs_id": {
          "type": "string"
        }
      },
      "required": [
        "issued_at",
        "surrogate_id",
        "subject_id",
        "cr_id",
        "version_number",
        "not_before",
        "slr_id",
        "issued",
        "not_after",
        "rs_id"
      ]
    },
    "role_specific_part": {
      "type": "object",
      "properties": {
        "role": {
          "type": "string"
        },
        "usage_rules": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "role",
        "usage_rules"
      ]
    }
  },
  "required": [
    "extensions",
    "ki_cr",
    "common_part",
    "role_specific_part"
  ]
}

csr_schema = {
  "iat": 1471857663,
  "prev_record_id": "null",
  "cr_id": "833dbc2b-bb11-425c-9c66-42b4c104f8da",
  "account_id": "48e2a067-c268-4bcb-b069-68c16bf45c5b_2",
  "record_id": "f8f01397-d5e7-4e5d-ac48-c42707a4f0b8",
  "consent_status": "Active"
}


####


class Sequences:
    def __init__(self, name, seq=False):
        '''

        :param name:
        '''
        self.logger = logging.getLogger("sequence")
        self.name = name
        self.sequence = {}

    def update(self, seq):
        self.sequence.update(seq)

    def send_to(self, to, msg=""):
        return self.seq_tool(msg, to, )

    def reply_to(self, to, msg=""):
        return self.seq_tool(msg, to, dotted=True)

    def task(self, content):

        return self.seq_tool(msg=content, box=False, to=self.name)

    def seq_tool(self, msg=None, to="Change_Me", box=False, dotted=False):

        if box:
            form = 'Note over {}: {}'.format(self.name, msg)
            return self.seq_form(form, self.sequence)
        elif dotted:
            form = "{}-->{}: {}".format(self.name, to, msg)
            return self.seq_form(form, self.sequence)
        else:
            form = "{}->{}: {}".format(self.name, to, msg)
            return self.seq_form(form, self.sequence)

    def dump_sequence(self):
        return ""

    def seq_form(self, line, seq):
        self.logger.info(dumps({"seq": line, "time": time()}))
        return {"seq": {}}

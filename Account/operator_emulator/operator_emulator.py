# -*- coding: utf-8 -*-

"""
Minimum viable account - MyData Operator SDK Emulator

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 12.8.2016
"""
from uuid import uuid4

import requests
import time
from requests.auth import HTTPBasicAuth
import json

request_statuses = []

account_ip = "http://127.0.0.1"
account_port = "8080"
account_host = account_ip+":"+account_port
headers = {'Api-Key': '682adc10-10e3-478f-8c53-5176d109d7ec', 'Content-Type': 'application/json'}

code = "CODE-" + str(uuid4())
account_id = "1"
operator_id = "OP-ID-" + str(uuid4())

source_service_id = "SRV-SOURCE-ID-" + str(uuid4())
source_surrogate_id = "SOURCE-SUR-" + str(uuid4())
source_slr_id = "SOURCE-SLR-" + str(uuid4())
source_ssr_id = "SOURCE-SSR-" + str(uuid4())

sink_service_id = "SRV-SINK-ID-" + str(uuid4())
sink_surrogate_id = "SINK-SUR-" + str(uuid4())
sink_slr_id = "SINK-SLR-" + str(uuid4())
sink_ssr_id = "SINK-SSR-" + str(uuid4())

source_cr_id = "SOURCE-CR-" + str(uuid4())
sink_cr_id = "SINK-CR-" + str(uuid4())

source_csr_id = "SOURCE-CSR-" + str(uuid4())
sink_csr_id = "SINK-CSR-" + str(uuid4())
rs_id = "RS-ID-" + str(uuid4())
not_before = str(time.time())
not_after = str(time.time() + (60*60*24*7))
distribution_id = "DISTRIBUTION-ID-" + str(uuid4())
dataset_id = "DATASET-ID-" + str(uuid4())

source_slr_payload = {
      "code": code,
      "data": {
        "slr": {
          "type": "ServiceLinkRecord",
          "attributes": {
            "version": "1.2",
            "link_id": source_slr_id,
            "operator_id": operator_id,
            "service_id": source_service_id,
            "surrogate_id": source_surrogate_id,
            "token_key": {
              "key": {
                "y": "FFuMENxef5suGtcBz4PWXt_KvRUHdURU5kH7EI5GZj8",
                "x": "5IxIntzP7SPShzbGVW6dVYQlMsJ9kg9rjrE5Z3B6fmg",
                "kid": "SRVMGNT-IDK3Y",
                "crv": "P-256",
                "kty": "EC"
              }
            },
            "operator_key": {
              "key": {
                "y": "FFuMENxef5suGtcBz4PWXt_KvRUHdURU5kH7EI5GZj8",
                "x": "5IxIntzP7SPShzbGVW6dVYQlMsJ9kg9rjrE5Z3B6fmg",
                "kid": "SRVMGNT-IDK3Y",
                "crv": "P-256",
                "kty": "EC"
              }
            },
            "cr_keys": "",
            "created": ""
          }
        },
        "surrogate_id": {
          "type": "SurrogateId",
          "attributes": {
            "surrogate_id": source_surrogate_id,
            "service_id": source_service_id,
            "account_id": account_id
          }
        }
      }
    }

sink_slr_payload = {
      "code": code,
      "data": {
        "slr": {
          "type": "ServiceLinkRecord",
          "attributes": {
            "version": "1.2",
            "link_id": sink_slr_id,
            "operator_id": operator_id,
            "service_id": sink_service_id,
            "surrogate_id": sink_surrogate_id,
            "token_key": {
              "key": {
                "y": "FFuMENxef5suGtcBz4PWXt_KvRUHdURU5kH7EI5GZj8",
                "x": "5IxIntzP7SPShzbGVW6dVYQlMsJ9kg9rjrE5Z3B6fmg",
                "kid": "SRVMGNT-IDK3Y",
                "crv": "P-256",
                "kty": "EC"
              }
            },
            "operator_key": {
              "key": {
                "y": "FFuMENxef5suGtcBz4PWXt_KvRUHdURU5kH7EI5GZj8",
                "x": "5IxIntzP7SPShzbGVW6dVYQlMsJ9kg9rjrE5Z3B6fmg",
                "kid": "SRVMGNT-IDK3Y",
                "crv": "P-256",
                "kty": "EC"
              }
            },
            "cr_keys": "",
            "created": ""
          }
        },
        "surrogate_id": {
          "type": "SurrogateId",
          "attributes": {
            "surrogate_id": sink_surrogate_id,
            "service_id": sink_service_id,
            "account_id": account_id
          }
        }
      }
    }

source_ssr_payload = {
      "code": code,
      "data": {
        "slr": {
          "attributes": {
            "slr": {}
          },
          "type": "ServiceLinkRecord"
        },
        "ssr": {
          "attributes": {
            "record_id": source_ssr_id,
            "account_id": source_surrogate_id,
            "slr_id": source_slr_id,
            "sl_status": "Active",
            "iat": "",
            "prev_record_id": "NULL"
          },
          "type": "ServiceLinkStatusRecord"
        },
        "surrogate_id": {
          "attributes": {
            "account_id": account_id,
            "service_id": source_service_id,
            "surrogate_id": source_surrogate_id
          },
          "type": "SurrogateId"
        }
      }
    }

sink_ssr_payload = {
      "code": code,
      "data": {
        "slr": {
          "attributes": {
            "slr": {}
          },
          "type": "ServiceLinkRecord"
        },
        "ssr": {
          "attributes": {
            "record_id": sink_ssr_id,
            "account_id": sink_surrogate_id,
            "slr_id": sink_slr_id,
            "sl_status": "Active",
            "iat": "",
            "prev_record_id": "NULL"
          },
          "type": "ServiceLinkStatusRecord"
        },
        "surrogate_id": {
          "attributes": {
            "account_id": account_id,
            "service_id": sink_service_id,
            "surrogate_id": sink_surrogate_id
          },
          "type": "SurrogateId"
        }
      }
    }

consent_record_payload = {
      "data": {
        "source": {
          "consentRecordPayload": {
            "type": "ConsentRecord",
            "attributes": {
              "common_part": {
                "version_number": "1.2",
                "cr_id": source_cr_id,
                "surrogate_id": source_surrogate_id,
                "rs_id": rs_id,
                "slr_id": source_slr_id,
                "issued": "timestamp",
                "not_before": not_before,
                "not_after": not_after,
                "issued_at": operator_id,
                "subject_id": source_service_id
              },
              "role_specific_part": {
                "role": "Source",
                "auth_token_issuer_key": {},
                "resource_set_description": {
                  "resource_set": {
                    "rs_id": rs_id,
                    "dataset": [
                      {
                        "dataset_id": dataset_id + "_1",
                        "distribution_id": distribution_id + "_1"
                      },
                      {
                        "dataset_id": dataset_id + "_2",
                        "distribution_id": distribution_id + "_2"
                      }
                    ]
                  }
                }
              },
              "ki_cr": {},
              "extensions": {}
            }
          },
          "consentStatusRecordPayload": {
            "type": "ConsentStatusRecord",
            "attributes": {
              "record_id": source_csr_id,
              "account_id": source_surrogate_id,
              "cr_id": source_cr_id,
              "consent_status": "Active",
              "iat": "timestamp",
              "prev_record_id": "Null"
            }
          }
        },
        "sink": {
          "consentRecordPayload": {
            "type": "ConsentRecord",
            "attributes": {
              "common_part": {
                "version_number": "1.2",
                "cr_id": sink_cr_id,
                "surrogate_id": sink_surrogate_id,
                "rs_id": rs_id,
                "slr_id": sink_slr_id,
                "issued": "timestamp",
                "not_before": not_before,
                "not_after": not_after,
                "issued_at": operator_id,
                "subject_id": sink_service_id
              },
              "role_specific_part": {
                "role": "Sink",
                "usage_rules": [
                  "Rule 1",
                  "Rule 2",
                  "Rule 3"
                ]
              },
              "ki_cr": {},
              "extensions": {}
            }
          },
          "consentStatusRecordPayload": {
            "type": "ConsentStatusRecord",
            "attributes": {
              "record_id": sink_csr_id,
              "account_id": sink_surrogate_id,
              "cr_id": sink_cr_id,
              "consent_status": "Active",
              "iat": "timestamp",
              "prev_record_id": "Null"
            }
          }
        }
      }
    }


def slr_sign(host=None, account_id=None, headers=None, data=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if data is None:
        raise AttributeError("Provide data as parameter")

    endpoint = "/api/account/" + str(account_id) + "/servicelink/"
    url = host + endpoint

    print("Request")
    print("Endpoint: " + endpoint)
    print("Payload: " + json.dumps(data, indent=3))

    req = requests.post(url, headers=headers, json=data)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data


def slr_verify(host=None, account_id=None, headers=None, slr_to_verify=None, data_template=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if slr_to_verify is None:
        raise AttributeError("Provide slr_to_verify as parameter")
    if data_template is None:
        raise AttributeError("Provide data_template as parameter")

    endpoint = "/api/account/" + str(account_id) + "/servicelink/verify/"
    url = host + endpoint

    try:
        data = data_template
        data['data']['slr']['attributes']['slr'] = slr_to_verify
    except Exception as exp:
        error_title = "Filed to insert slr to data template"
        print(error_title + ": " + repr(exp))
        raise

    print("Request")
    print("Endpoint: " + endpoint)
    print("Payload: " + json.dumps(data, indent=3))

    req = requests.post(url, headers=headers, json=data)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data


def surrogate(host=None, account_id=None, headers=None, service_id=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if service_id is None:
        raise AttributeError("Provide service_id as parameter")

    endpoint = "/api/account/" + str(account_id) + "/service/" + str(service_id) + "/surrogate/"
    url = host + endpoint

    print("Request")
    print("Endpoint: " + endpoint)

    req = requests.get(url, headers=headers)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data


def give_consent(host=None, account_id=None, source_slr_id=None, sink_slr_id=None, headers=None, data=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if source_slr_id is None:
        raise AttributeError("Provide source_slr_id as parameter")
    if sink_slr_id is None:
        raise AttributeError("Provide sink_slr_id as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if data is None:
        raise AttributeError("Provide consent_data as parameter")

    endpoint = "/api/account/" + str(account_id) + "/servicelink/" + str(source_slr_id) + "/" + str(sink_slr_id) + "/consent/"
    url = host + endpoint

    print("Request")
    print("Endpoint: " + endpoint)
    print("Payload: " + json.dumps(data, indent=3))

    req = requests.post(url, headers=headers, json=data)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data

# Source SLR sign
print ("------------------------------------")
print("Source SLR")
try:
    source_slr = slr_sign(host=account_host, account_id=account_id, headers=headers, data=source_slr_payload)
except Exception as exp:
    error_title = "Source SLR filed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Source SLR: " + source_slr[0])
    print ("Response: " + source_slr[0])
    print (json.dumps(source_slr[1], indent=3))

# Sink SLR sign
print ("------------------------------------")
print("Sink SLR")
try:
    sink_slr = slr_sign(host=account_host, account_id=account_id, headers=headers, data=sink_slr_payload)
except Exception as exp:
    error_title = "Sink SLR filed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Sink SLR: " + sink_slr[0])
    print ("Response: " + sink_slr[0])
    print (json.dumps(sink_slr[1], indent=3))


# Source SLR verify
print ("------------------------------------")
print("Source SLR verify")
try:
    source_slr_verified = slr_verify(host=account_host, account_id=account_id, headers=headers, slr_to_verify=source_slr[1]['data']['slr']['attributes']['slr'], data_template=source_ssr_payload)
except Exception as exp:
    error_title = "Source SLR verification filed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Source SLR verify: " + source_slr_verified[0])
    print ("Response: " + source_slr_verified[0])
    print (json.dumps(source_slr_verified[1], indent=3))

# Sink SLR verify
print ("------------------------------------")
print("Sink SLR verify")
try:
    sink_slr_verified = slr_verify(host=account_host, account_id=account_id, headers=headers, slr_to_verify=sink_slr[1]['data']['slr']['attributes']['slr'], data_template=sink_ssr_payload)
except Exception as exp:
    error_title = "Sink SLR verification filed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Sink SLR verify: " + sink_slr_verified[0])
    print ("Response: " + sink_slr_verified[0])
    print (json.dumps(sink_slr_verified[1], indent=3))


# Surrogate Source
print ("------------------------------------")
print("Get Surrogate")
try:
    sur = surrogate(host=account_host, account_id=account_id, headers=headers, service_id=source_service_id)
except Exception as exp:
    error_title = "Consenting failed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Get Surrogate Source: " + sur[0])
    print ("Response: " + sur[0])
    print (json.dumps(sur[1], indent=3))


# Surrogate Sink
print ("------------------------------------")
print("Get Surrogate")
try:
    sur = surrogate(host=account_host, account_id=account_id, headers=headers, service_id=sink_service_id)
except Exception as exp:
    error_title = "Consenting failed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Get Surrogate Sink: " + sur[0])
    print ("Response: " + sur[0])
    print (json.dumps(sur[1], indent=3))


# Give consent
print ("------------------------------------")
print("Give Consent")
try:
    consenting = give_consent(host=account_host, account_id=account_id, source_slr_id=source_slr_id, sink_slr_id=sink_slr_id, headers=headers, data=consent_record_payload)
except Exception as exp:
    error_title = "Consenting failed"
    print(error_title + ": " + repr(exp))
else:
    request_statuses.append("Give Consent: " + consenting[0])
    print ("Response: " + consenting[0])
    print (json.dumps(consenting[1], indent=3))


print ("------------------------------------")
print("Request report")
for request in request_statuses:
    print(request)

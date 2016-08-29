# -*- coding: utf-8 -*-
from json import loads

from requests import get, post

from Templates import Service_ID_A, Service_ID_B, Sequences

sq = Sequences("UI", {})

operator_url = "http://localhost:5000/"

slr_flow1 = get("http://127.0.0.1:5000/api/1.2/slr/account/2/service/1")
print(slr_flow1.url, slr_flow1.reason, slr_flow1.status_code, slr_flow1.text)
slr_flow2 = get("http://127.0.0.1:5000/api/1.2/slr/account/2/service/2")
print(slr_flow2.url, slr_flow2.reason, slr_flow2.status_code, slr_flow2.text)

sq.send_to("Operator_SLR", "Get consent form.")
# This format needs to be specified, even if done with url params instead.
ids = {"sink": Service_ID_B, "source": Service_ID_A}

req = get(operator_url + "api/1.2/cr/consent_form/account/2?sink={}&source={}".format(Service_ID_B, Service_ID_A))

print(req.url, req.reason, req.status_code, req.text)
js = loads(req.text)

sq.send_to("Operator_SLR", "Posting filled ConsentForm")
#js.update(sq.sequence)
req = post(operator_url + "api/1.2/cr/consent_form/account/2", json=js)
import json
print(req.url, req.reason, req.status_code, "\n" , json.dumps(loads(req.text), indent=2))


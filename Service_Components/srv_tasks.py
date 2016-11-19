# -*- coding: utf-8 -*-
from requests import post
from factory import create_celery_app
import urllib
celery = create_celery_app()

# TODO Possibly remove this on release
# @celery.task
# def CR_installer(crs_csrs_payload, sink_url, source_url):
#     # Get these as parameter or inside crs_csrs_payload
#     endpoint = "/api/1.2/cr/add_cr"
#     print(crs_csrs_payload)
#     source = post(source_url+endpoint, json=crs_csrs_payload["source"])
#     print(source.url, source.reason, source.status_code, source.text)
#
#     sink = post(sink_url+endpoint, json=crs_csrs_payload["sink"])
#     print(sink.url, sink.reason, sink.status_code, sink.text)


from sqlite3 import OperationalError, IntegrityError
import db_handler
from json import dumps, loads
from requests import get
from instance.settings import MYSQL_HOST, MYSQL_PASSWORD, MYSQL_USER, MYSQL_PORT, MYSQL_DB
from helpers import Helpers, CR_tool
@celery.task
def get_AuthToken(cr_id, operator_url, app_config):
    print(operator_url, cr_id)
    helpers = Helpers(app_config)
    print(cr_id)
    token = get("{}/api/1.2/cr/auth_token/{}".format(operator_url, cr_id))  # TODO Get api path from some config?
    print(token.url, token.reason, token.status_code, token.text)
    store_dict = {cr_id: dumps(loads(token.text.encode()))}
    helpers.storeToken(store_dict)

    cr_csr = helpers.get_cr_json(cr_id)
    cr_tool = CR_tool()
    cr_tool.cr = cr_csr

    user_id = cr_tool.get_surrogate_id()
    rs_id = cr_tool.get_rs_id()

    #req = get("http://service_components:7000/api/1.2/sink_flow/init")
    #print(req.url, req.status_code, req.content)

    data  = {"cr_id": cr_id,
             "user_id": user_id,
             "rs_id": urllib.quote_plus(rs_id)}
    print(dumps(data, indent=2))

    req = post("http://service_components:7000/api/1.2/sink_flow/dc", json=data)
    # req = get("http://service_components:7000/api/1.2/sink_flow/"
    #           "user/"+"95479a08-80cc-4359-ba28-b8ca23ff5572_53af88dc-33de-44be-bc30-e0826db9bd6c"+"/"
    #           "consentRecord/"+"cd431509-777a-4285-8211-95c5ac577537"+"/"
    #           "resourceSet/"+urllib.quote_plus("http://service_components:7000||9aebb487-0c83-4139-b12c-d7fcea93a3ad"))
    print(req.url, req.status_code, req.content)

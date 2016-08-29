# -*- coding: utf-8 -*-
from requests import post
from factory import create_celery_app

celery = create_celery_app()

@celery.task
def CR_installer(crs_csrs_payload, sink_url, source_url):
    # Get these as parameter or inside crs_csrs_payload
    endpoint = "/api/1.2/cr/add_cr"
    print(crs_csrs_payload)
    source = post(source_url+endpoint, json=crs_csrs_payload["source"])
    print(source.url, source.reason, source.status_code, source.text)

    sink = post(sink_url+endpoint, json=crs_csrs_payload["sink"])
    print(sink.url, sink.reason, sink.status_code, sink.text)

# TODO Possibly remove this on release
from requests import get
@celery.task
def get_AuthToken(cr_id, operator_url):
    ##
    print(cr_id)
    token = get("{}/api/1.2/cr/auth_token/{}".format(operator_url, cr_id))
    print(token.url, token.reason, token.status_code, token.text)
# -*- coding: utf-8 -*-
from factory import create_celery_app

celery = create_celery_app()

from requests import get
@celery.task
def get_AuthToken(cr_id, operator_url):
    ##
    print(cr_id)
    token = get("{}/api/1.2/cr/auth_token/{}".format(operator_url, cr_id))
    print(token.url, token.reason, token.status_code, token.text)


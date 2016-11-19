# -*- coding: utf-8 -*-
from kombu import Exchange, Queue

TIMEOUT = 8
KEYSIZE = 512

# TODO give these as parameter to init AccountManagerHandler

ACCOUNT_MANAGEMENT_URL = 'http://account:8080/'

ACCOUNT_MANAGEMENT_USER = "test_sdk"

ACCOUNT_MANAGEMENT_PASSWORD = "test_sdk_pw"

# Setting to /tmp or other ramdisk makes it faster.

DATABASE_PATH = "./db_Operator.sqlite"

SELERY_BROKER_URL = 'redis://redis:6379/0'

SELERY_RESULT_BACKEND = 'redis://redis:6379/0'

CERT_PATH = "./service_key.jwk"

CERT_KEY_PATH = "./service_key.jwk"

CERT_PASSWORD_PATH = "./cert_pw"

OPERATOR_UID = "41e19fcd-1951-455f-9169-a303f990f52d"

OPERATOR_ROOT_PATH = "/api/1.2"

OPERATOR_CR_PATH = "/cr"

OPERATOR_SLR_PATH = "/slr"

SERVICE_URL = "http://service_components:7000"

DEBUG_MODE = False

CELERY_QUEUES = (
    Queue('op_queue', Exchange('op_queue'), routing_key='op_queue'),
)

CELERY_DEFAULT_QUEUE = 'op_queue'

CELERY_ROUTES = {
    'CR_Installer': {'queue': 'op_queue','routing_key': "op_queue"},
}
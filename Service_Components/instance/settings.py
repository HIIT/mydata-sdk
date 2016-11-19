# -*- coding: utf-8 -*-
from kombu import Exchange, Queue

TIMEOUT = 8

KEYSIZE = 512

# Setting to /tmp or other ramdisk makes it faster.

DATABASE_PATH = "./db_Srv.sqlite"

SELERY_BROKER_URL = 'redis://redis:6379/0'

SELERY_RESULT_BACKEND = 'redis://redis:6379/0'

CERT_PATH = "./service_key.jwk"
CERT_KEY_PATH = "./service_key.jwk"
CERT_PASSWORD_PATH = "./cert_pw"

SERVICE_URL = "http://service_mockup:2000"



OPERATOR_URL = "http://operator_components:5000"




SERVICE_ROOT_PATH = "/api/1.2"



SERVICE_CR_PATH = "/cr"



SERVICE_SLR_PATH = "/slr"



DEBUG_MODE = False


CELERY_QUEUES = (
    Queue('srv_queue', Exchange('srv_queue'), routing_key='srv_queue'),
)

CELERY_DEFAULT_QUEUE = 'srv_queue'

CELERY_ROUTES = {
    'get_AuthToken': {'queue': 'srv_queue', 'routing_key': "srv_queue"}
}
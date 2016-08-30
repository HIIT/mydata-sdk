# Deployment

## Prerequisites

    Python2.7
    celery
    redis
    jsonschema
    flask
    flask-cors
    flask-restful
    jwcrypto
    pyjwkest
    cryptography

## Deployment

    Clone this repo.

    Checkout master-branch.

    cd Service_Mockup/
       
    sudo apt install python-pip
    
    sudo apt install celeryd redis-server
    
    sudo apt install build-essential libssl-dev libffi-dev python-dev
    
    export LC_ALL=C
    pip install virtualenv

    virtualenv virtual_env_2_7
    
    source virtual_env_2_7/bin/activate
    pip install -r requirements.txt

#### Configure

You can find configurable settings in /instance/settings.py

#### Start

    cd Service_Mockup/
    source virtual_env_2_7/bin/activate
    nohup python wsgi.py > srvmock_flask.log &


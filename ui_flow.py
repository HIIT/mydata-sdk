# -*- coding: utf-8 -*-
import json
import argparse
from requests import get, post

# TODO: Maybe these should be given as parameters
Service_ID_A = 10
Service_ID_B = 100


# TODO: Add more printing. Now user barely knows if initialization happened and did it succeed or not.
# Sends JSON-payloads to Account that create three new accounts.
# Needed in order to start_ui_flow() -function to work.
def initialize(operator_url):
    print ("\n##### CREATE USER ACCOUNTS #####")
    print("NOTE: Throws an error if run for second time as you cannot " \
          "create more accounts with same unique usernames. " \
          "(Will be fixed in later releases.)\n\n"
         )
    resp = post(operator_url + 'api/accounts/',
                json={"firstName": "Erkki", "lastName": "Esimerkki", "dateOfBirth": "31-05-2016",
                      "email": "erkki.esimerkki@examlpe.org", "username": "testUffser", "password": "Hello",
                      "acceptTermsOfService": "True"})
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))
    post(operator_url + 'api/accounts/',
         json={"firstName": "Iso", "lastName": "Pasi", "dateOfBirth": "31-05-2016", "email": "iso.pasi@examlpe.org",
               "username": "pasi", "password": "0nk0va", "acceptTermsOfService": "True"})
    post(operator_url + 'api/accounts/', json={"firstName": "Dude", "lastName": "Dudeson", "dateOfBirth": "31-05-2016",
                                               "email": "dude.dudeson@examlpe.org", "username": "mydata",
                                               "password": "Hello", "acceptTermsOfService": "True"})
    return


# TODO: Refactor and return something.
# First creates two Service Links by making a GET-request to Operator backend.
# Then gives a Consent for these Services by sending a Consent form as JSON-payload to Operator backend.
# Should print "201 Created" if the flow was excuted succesfully.
def start_ui_flow(operator_url):
    print("\n##### MAKE TWO SERVICE LINKS #####")
    slr_flow1 = get(operator_url + "api/1.2/slr/account/2/service/1")
    print(slr_flow1.url, slr_flow1.reason, slr_flow1.status_code, slr_flow1.text)
    slr_flow2 = get(operator_url + "api/1.2/slr/account/2/service/2")
    print(slr_flow2.url, slr_flow2.reason, slr_flow2.status_code, slr_flow2.text)

    # This format needs to be specified, even if done with url params instead.
    ids = {"sink": Service_ID_B, "source": Service_ID_A}

    print("\n##### GIVE CONSENT #####")
    req = get(operator_url + "api/1.2/cr/consent_form/account/2?sink={}&source={}".format(Service_ID_B, Service_ID_A))

    print(req.url, req.reason, req.status_code, req.text)
    js = json.loads(req.text)

    req = post(operator_url + "api/1.2/cr/consent_form/account/2", json=js)

    print(req.url, req.reason, req.status_code)
    print("\n")
    print(json.dumps(json.loads(req.text), indent=2))

    print("\n\n")
    return


if __name__ == '__main__':

    # Parse command line arguments
    parser = argparse.ArgumentParser()

    # TODO: Use boolean value instead of int.
    help_string_account_url = \
        "URL to Account. Defaults to 'http://localhost:8080'. \
        NOTE: Throws an error if run for second time as you cannot\
        create more accounts with same unique usernames.\
        (Will be fixed in later releases.)"
    parser.add_argument("--account_url",
                        help=help_string_account_url,
                        type=str,
                        default="http://localhost:8080/",
                        required=False)

    help_string_operator_url = \
        "URL to Operator backend. Defaults to 'http://localhost:5000/'."
    parser.add_argument("--operator_url",
                        help=help_string_operator_url,
                        type=str,
                        default="http://localhost:5000/",
                        required=False)

    args = parser.parse_args()

    initialize(args.account_url)

    start_ui_flow(args.operator_url)

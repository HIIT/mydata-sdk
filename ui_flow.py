# -*- coding: utf-8 -*-

import json
import argparse
from requests import get, post
from uuid import uuid4

# TODO: Maybe these should be given as parameters
#Service_ID_Source   = "57f3a57b0cf2fcf22eea33a2"  # MyLocation
#Service_ID_Sink     = "57f3a57b0cf2fcf22eea33a3"  # PHR
#Service_ID_Source   = "582b7df00cf2727145535753"  # MyLocation
#Service_ID_Sink     = "582b7df00cf2727145535754"  # PHR
Service_ID_Source   = "582f2bf50cf2f4663ec4f01f"  # MyLocation
Service_ID_Sink     = "582f2bf50cf2f4663ec4f020"  # PHR

# TODO: Add more printing. Now user barely knows if initialization happened and did it succeed or not.
# Sends JSON-payloads to Account that create three new accounts.
# Needed in order to start_ui_flow() -function to work.
def initialize(account_url):
    username = "example_username-" + str(uuid4())
    password = "example_password"

    print ("\n##### CREATE USER ACCOUNTS #####")
    print("NOTE: Throws an error if run for second time as you cannot "
          "create more accounts with same unique usernames. "
          "(Will be fixed in later releases.)\n\n"
         )
    user_data = {"data": {
        "type": "Account",
        "attributes": {
            'firstName': 'ExampleFirstName',
            'lastName': 'ExampleLastName',
            'dateOfBirth': '2010-05-14',
            'email': username + '@examlpe.org',
            'username': username,
            'password': password,
            'acceptTermsOfService': 'True'
            }
          }
        }
    resp = post(account_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstName"] = "Iso"
    user_data["data"]["attributes"]["lastName"] = "Pasi"
    user_data["data"]["attributes"]["email"] = "iso.pasi@example.org"
    user_data["data"]["attributes"]["username"] = "pasi"
    user_data["data"]["attributes"]["password"] = "0nk0va"
    resp = post(account_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstName"] = "Dude"
    user_data["data"]["attributes"]["lastName"] = "Dudeson"
    user_data["data"]["attributes"]["email"] = "dude.dudeson@example.org"
    user_data["data"]["attributes"]["username"] = "mydata"
    user_data["data"]["attributes"]["password"] = "Hello"
    resp = post(account_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))
    # post(account_url + 'api/accounts/',
    #      json={"firstName": "Iso", "lastName": "Pasi", "dateOfBirth": "31-05-2016", "email": "iso.pasi@examlpe.org",
    #            "username": "pasi", "password": "0nk0va", "acceptTermsOfService": "True"})
    # post(operator_url + 'api/accounts/', json={"firstName": "Dude", "lastName": "Dudeson", "dateOfBirth": "31-05-2016",
    #                                            "email": "dude.dudeson@examlpe.org", "username": "mydata",
    #                                            "password": "Hello", "acceptTermsOfService": "True"})
    return

# TODO: Refactor and return something.
# Creates two Service Links by making a GET-request to Operator backend.
def create_service_link(operator_url, service_id):
    print("\n##### CREATE A SERVICE LINK #####")
    slr_flow = get(operator_url + "api/1.2/slr/account/2/service/"+service_id)
    if not slr_flow.ok:
        print("Creation of first SLR failed with status ({}) reason ({}) and the following content:\n{}".format(
            slr_flow.status_code,
            slr_flow.reason,
            json.dumps(json.loads(slr_flow.content), indent=2)
        ))
        raise Exception("SLR flow failed.")
    print(slr_flow.url, slr_flow.reason, slr_flow.status_code, slr_flow.text)

    return


# TODO: Refactor and return something.
# Gives a Consent for these Services by sending a Consent form as JSON-payload to Operator backend.
# Should print "201 Created" if the Consent was executed succesfully.
def give_consent(operator_url, sink_id, source_id):

    print("\n##### GIVE CONSENT #####")

    # This format needs to be specified, even if done with url params instead.
    ids = {"sink": sink_id, "source": source_id}

    print("\n###### 1.FETCH CONSENT FORM ######")
    req = get(operator_url + "api/1.2/cr/consent_form/account/2?sink={}&source={}".format(sink_id, source_id))
    if not req.ok:
        print("Fetching consent form consent failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Consent flow failed.")

    print("\n###### 2.SEND CONSENT FORM ######")
    print(req.url, req.reason, req.status_code, req.text)
    js = json.loads(req.text)
    req = post(operator_url + "api/1.2/cr/consent_form/account/2", json=js)
    if not req.ok:
        print("Granting consent failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Consent flow failed.")

    print(req.url, req.reason, req.status_code)
    print("\n")
    print(json.dumps(json.loads(req.text), indent=2))

    print("\n\n")
    return


if __name__ == '__main__':

    # Parse command line arguments
    parser = argparse.ArgumentParser()

    # Urls
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

    # Skips
    help_string_skip_init = \
        "Should account init be skipped. Init is done by default. Specify this flag to skip init."
    parser.add_argument("--skip_init",
                        help=help_string_skip_init,
                        action="store_true",
                        required=False)

    help_string_skip_slr = \
        "Should account init be skipped. Init is done by default. Specify this flag to skip init."
    parser.add_argument("--skip_slr",
                        help=help_string_skip_slr,
                        action="store_true",
                        required=False)

    # IDs
    help_string_sink_id = \
        "ID of the Sink. \
        Check that this matches to what is specified in Service Registry. \
        Defaults to '{}'.".format(Service_ID_Sink)
    parser.add_argument("--sink_id",
                        help=help_string_sink_id,
                        type=str,
                        default=Service_ID_Sink,
                        required=False)

    help_string_source_id = \
        "ID of the Source. \
        Check that this matches to what is specified in Service Registry. \
        Defaults to '{}'.".format(Service_ID_Source)
    parser.add_argument("--source_id",
                        help=help_string_source_id,
                        type=str,
                        default=Service_ID_Source,
                        required=False)

#     exclusive_grp = parser.add_mutually_exclusive_group()
#     exclusive_grp.add_argument('--skip_init', action='store_true', dest='foo', help='skip init')
#     exclusive_grp.add_argument('--no-foo', action='store_false', dest='foo', help='do not do foo')

    args = parser.parse_args()

#     print 'Starting program', 'with' if args.foo else 'without', 'foo'
#     print 'Starting program', 'with' if args.no_foo else 'without', 'no_foo'

    # Just for user to see the given input
    print(args.account_url)
    print(args.operator_url)
    print(args.skip_init)
    print(args.sink_id)
    print(args.source_id)

    if not args.skip_init:
        # Do not skip init
        initialize(args.account_url)

    # SLR
    if not args.skip_slr:
        create_service_link(args.operator_url, args.sink_id)
        create_service_link(args.operator_url, args.source_id)

    # Consent
    give_consent(args.operator_url, args.sink_id, args.source_id)

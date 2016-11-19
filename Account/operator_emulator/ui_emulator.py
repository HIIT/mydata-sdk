# -*- coding: utf-8 -*-

"""
Minimum viable account - MyData Operator UI Emulator

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
headers = {'Content-Type': 'application/json'}

account_id = ""
particular_id = ""
contacts_id = ""


predefined_account_username = "testUser"
predefined_account_password = "Hello"

username = "example_username-" + str(uuid4())
password = "example_password"

account_template = {
    "data": {
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

particular_template_for_patch = {
    "data": {
        "type": "Particular",
        "attributes": {
            'lastname': 'NewExampleLastName'
        }
    }
}

contact_template = {
    "data": {
        "type": "Contact",
        "attributes": {
            'address1': 'Example address 1',
            'address2': 'Example address 2',
            'postalCode': '97584',
            'city': 'Example city',
            'state': 'Example state',
            'country': 'Example country',
            'type': 'Personal',
            'primary': 'True'
        }
    }
}

contact_template_for_patch = {
    "data": {
        "type": "Contact",
        "attributes": {
            'address1': 'Example address 1',
            'address2': 'Example address 2',
            'postalCode': '65784',
            'city': 'Example city',
            'state': 'Example state',
            'country': 'Example country',
            'type': 'Personal',
            'primary': 'False'
        }
    }
}

email_template = {
    "data": {
        "type": "Email",
        "attributes": {
            'email': 'erkki@example.com',
            'type': 'Personal',
            'primary': 'True'
        }
    }
}

email_template_for_patch = {
    "data": {
        "type": "Email",
        "attributes": {
            'email': 'pasi@example.org',
            'type': 'School',
            'primary': 'False'
        }
    }
}

telephone_template = {
    "data": {
        "type": "Telephone",
        "attributes": {
            'tel': '0501234567',
            'type': 'Personal',
            'primary': 'True'
        }
    }
}

telephone_template_for_patch = {
    "data": {
        "type": "Telephone",
        "attributes": {
            'tel': '+358 50 123 4567',
            'type': 'School',
            'primary': 'False'
        }
    }
}

setting_template = {
    "data": {
        "type": "Setting",
        "attributes": {
            'key': 'lang',
            'value': 'fi'
        }
    }
}

setting_template_for_patch = {
    "data": {
        "type": "Setting",
        "attributes": {
            'key': 'lang',
            'value': 'se'
        }
    }
}



def post(host=None, endpoint=None, headers=None, data=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if data is None:
        raise AttributeError("Provide data as parameter")

    url = host + endpoint
    print("Endpoint: " + endpoint)
    print("Headers: " + json.dumps(headers))
    print("Payload: " + json.dumps(data))

    req = requests.post(url, headers=headers, json=data)
    status_code = str(req.status_code)
    print ("Response status: " + str(req.status_code))
    try:
        response_data = json.loads(req.text)
    except Exception as exp:
        print(repr(exp))
        print("req.text: " + repr(req.text))
        response_data = repr(req.text)

    return status_code, response_data


def patch(host=None, endpoint=None, headers=None, data=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if data is None:
        raise AttributeError("Provide data as parameter")

    url = host + endpoint
    print("Endpoint: " + endpoint)
    print("Headers: " + json.dumps(headers))
    print("Payload: " + json.dumps(data))

    req = requests.patch(url, headers=headers, json=data)
    status_code = str(req.status_code)
    print ("Response status: " + str(req.status_code))
    try:
        response_data = json.loads(req.text)
    except Exception as exp:
        print(repr(exp))
        print("req.text: " + repr(req.text))
        response_data = repr(req.text)

    return status_code, response_data


def get(host=None, endpoint=None, headers=None, username=None, password=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")

    url = host + endpoint
    print("Endpoint: " + endpoint)
    print("Headers: " + json.dumps(headers))

    if username is not None and password is not None:
        req = requests.get(url, headers=headers, auth=HTTPBasicAuth(username=username, password=password))
    else:
        req = requests.get(url, headers=headers)
    status_code = str(req.status_code)
    print ("Response status: " + str(req.status_code))
    try:
        response_data = json.loads(req.text)
    except Exception as exp:
        print(repr(exp))
        print("req.text: " + repr(req.text))
        response_data = repr(req.text)

    return status_code, response_data


######### Actions

##################################
# Create Account and Authenticate
##################################
label = "# \n# Create Account and Authenticate \n#################################"
print(label)
request_statuses.append(label)

if not predefined_account_username and not predefined_account_password:
    #
    # Create Account
    title = "Create Account"
    print(title)
    try:
        account = post(host=account_host, endpoint="/api/accounts/", headers=headers, data=account_template)
    except Exception as exp:
        print(title + ": " + repr(exp))
        request_response = title + ": " + repr(exp)
        request_statuses.append(request_response)
        raise
    else:
        request_response = title + ": " + account[0] + ": " + json.dumps(account[1])
        print('request_response: ' + request_response)
        request_statuses.append(request_response)
        account_id = str(account[1]['data'].get("id", "None"))
        print ("Response " + account[0] + ": " + json.dumps(account[1]))
        print ("Account ID: " + account_id)

else:
    print("Using predefined account")
    username = predefined_account_username
    password = predefined_account_password

#
# Authenticate
print ("------------------------------------")
title = "Authenticate"
print(title)
try:
    api_auth = get(host=account_host, endpoint="/api/auth/user/", headers=headers, username=username, password=password)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + api_auth[0] + ": " + json.dumps(api_auth[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    apikey = str(api_auth[1].get("Api-Key", "None"))
    account_id = str(api_auth[1].get("account_id", "None"))
    headers['Api-Key'] = apikey
    print ("Response " + api_auth[0] + ": " + json.dumps(api_auth[1]))
    print ("apikey: " + apikey)

#
# ##################################
# # PARTICULARS
# ##################################
label = "# \n# PARTICULARS \n#################################"
print(label)
request_statuses.append(label)

title = "List Particulars"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/particulars/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    particular_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("particular_id: " + particular_id)


print ("------------------------------------")
title = "One Particular"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/particulars/" + particular_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entry[0] + ": " + json.dumps(entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("particular_id: " + str(entry[1]['data'].get("id", "None")))


print ("------------------------------------")
title = "Patch Particular"
print(title)
try:
    particular_template_for_patch['data']['id'] = str(particular_id)
    updated_entry = patch(host=account_host, endpoint="/api/accounts/" + account_id + "/particulars/" + particular_id + "/", headers=headers, data=particular_template_for_patch)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + updated_entry[0] + ": " + json.dumps(updated_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + updated_entry[0] + ": " + json.dumps(updated_entry[1]))


# ##################################
# # CONTACTS
# ##################################
label = "# \n# CONTACTS \n#################################"
print(label)
request_statuses.append(label)

title = "Add Contact"
print(title)
try:
    new_entry = post(host=account_host, endpoint="/api/accounts/" + account_id + "/contacts/", headers=headers, data=contact_template)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + new_entry[0] + ": " + json.dumps(new_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + new_entry[0] + ": " + json.dumps(new_entry[1]))

print ("------------------------------------")
title = "List Contacts"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/contacts/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    contacts_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("contacts_id: " + contacts_id)


print ("------------------------------------")
title = "One Contact"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/contacts/" + contacts_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("contacts_id: " + str(entry[1]['data'].get("id", "None")))


print ("------------------------------------")
title = "Patch Contact"
print(title)
try:
    contact_template_for_patch['data']['id'] = str(contacts_id)
    updated_entry = patch(host=account_host, endpoint="/api/accounts/" + account_id + "/contacts/" + contacts_id + "/", headers=headers, data=contact_template_for_patch)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + updated_entry[0] + ": " + json.dumps(updated_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + updated_entry[0] + ": " + json.dumps(updated_entry[1]))


# ##################################
# # EMAIL
# ##################################
label = "# \n# EMAIL \n#################################"
print(label)
request_statuses.append(label)

title = "Add Email"
print(title)
try:
    new_entry = post(host=account_host, endpoint="/api/accounts/" + account_id + "/emails/", headers=headers, data=email_template)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + new_entry[0] + ": " + json.dumps(new_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + new_entry[0] + ": " + json.dumps(new_entry[1]))

print ("------------------------------------")
title = "List Emails"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/emails/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    email_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("email_id: " + email_id)


print ("------------------------------------")
title = "One Email"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/emails/" + email_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("email_id: " + str(entry[1]['data'].get("id", "None")))


print ("------------------------------------")
title = "Patch Email"
print(title)
try:
    email_template_for_patch['data']['id'] = str(email_id)
    updated_entry = patch(host=account_host, endpoint="/api/accounts/" + account_id + "/emails/" + email_id + "/", headers=headers, data=email_template_for_patch)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + updated_entry[0] + ": " + json.dumps(updated_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + updated_entry[0] + ": " + json.dumps(updated_entry[1]))


# ##################################
# # TELEPHONE
# ##################################
label = "# \n# TELEPHONE \n#################################"
print(label)
request_statuses.append(label)

title = "Add Telephone"
print(title)
try:
    new_entry = post(host=account_host, endpoint="/api/accounts/" + account_id + "/telephones/", headers=headers, data=telephone_template)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + new_entry[0] + ": " + json.dumps(new_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + new_entry[0] + ": " + json.dumps(new_entry[1]))

print ("------------------------------------")
title = "List Telephones"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/telephones/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    telephones_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("telephones_id: " + telephones_id)


print ("------------------------------------")
title = "One Telephone"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/telephones/" + telephones_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("telephones_id: " + str(entry[1]['data'].get("id", "None")))


print ("------------------------------------")
title = "Patch Telephone"
print(title)
try:
    telephone_template_for_patch['data']['id'] = str(telephones_id)
    updated_entry = patch(host=account_host, endpoint="/api/accounts/" + account_id + "/telephones/" + telephones_id + "/", headers=headers, data=telephone_template_for_patch)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + updated_entry[0] + ": " + json.dumps(updated_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + updated_entry[0] + ": " + json.dumps(updated_entry[1]))


# ##################################
# # SETTINGS
# ##################################
label = "# \n# SETTINGS \n#################################"
print(label)
request_statuses.append(label)

title = "Add Setting"
print(title)
try:
    new_entry = post(host=account_host, endpoint="/api/accounts/" + account_id + "/settings/", headers=headers, data=setting_template)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + new_entry[0] + ": " + json.dumps(new_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + new_entry[0] + ": " + json.dumps(new_entry[1]))

print ("------------------------------------")
title = "List Settings"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/settings/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    settings_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("settings_id: " + settings_id)


print ("------------------------------------")
title = "One Setting"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/settings/" + settings_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("settings_id: " + str(entry[1]['data'].get("id", "None")))


print ("------------------------------------")
title = "Patch Setting"
print(title)
try:
    setting_template_for_patch['data']['id'] = str(settings_id)
    updated_entry = patch(host=account_host, endpoint="/api/accounts/" + account_id + "/settings/" + settings_id + "/", headers=headers, data=setting_template_for_patch)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + updated_entry[0] + ": " + json.dumps(updated_entry[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + updated_entry[0] + ": " + json.dumps(updated_entry[1]))


# ##################################
# # EVENT LOGS
# ##################################
# # label = "# \n# EVENT LOGS \n#################################"
# # print(label)
# # request_statuses.append(label)
# #
# # print ("------------------------------------")
# # title = "List Events"
# # print(title)
# # try:
# #     entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/logs/events/", headers=headers)
# # except Exception as exp:
# #     print(title + ": " + repr(exp))
# #     request_response = title + ": " + repr(exp)
# #     request_statuses.append(request_response)
# #     raise
# # else:
# #     request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
# #     print('request_response: ' + request_response)
# #     request_statuses.append(request_response)
# #     event_log_id = str(entries[1]['data'][0].get("id", "None"))
# #     print ("Response " + new_entry[0] + ": " + json.dumps(new_entry[1]))
# #     print ("event_log_id: " + event_log_id)
# #
# #
# # print ("------------------------------------")
# # title = "One Event"
# # print(title)
# # try:
# #     entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/logs/events/" + event_log_id + "/", headers=headers)
# # except Exception as exp:
# #     print(title + ": " + repr(exp))
# #     request_response = title + ": " + repr(exp)
# #     request_statuses.append(request_response)
# #     raise
# # else:
# #     request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
# #     print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
# #     print ("event_log_id: " + str(entry[1]['data'].get("id", "None")))
#
#
# ##################################
# # Service Link Records
# ##################################
label = "# \n# Service Link Records \n#################################"
print(label)
request_statuses.append(label)

print ("------------------------------------")
title = "Service Link Records"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    slr_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("slr_id: " + slr_id)


print ("------------------------------------")
title = "One Service Link Record"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("slr_id: " + str(entry[1]['data'].get("id", "None")))


##################################
# Service Link Status Records
##################################
label = "# \n# Service Link Status Records \n#################################"
print(label)
request_statuses.append(label)

print ("------------------------------------")
title = "Service Link Status Records"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/statuses/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    slsr_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("slsr_id: " + slsr_id)


print ("------------------------------------")
title = "One Service Link Status Record"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/statuses/" + slsr_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("slsr_id: " + str(entry[1]['data'].get("id", "None")))


##################################
# Consent Records
##################################
label = "# \n# Consent Records \n#################################"
print(label)
request_statuses.append(label)

print ("------------------------------------")
title = "Consent Records"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/consents/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    cr_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("cr_id: " + cr_id)


print ("------------------------------------")
title = "One Consent Record"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/consents/" + cr_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("cr_id: " + str(entry[1]['data'].get("id", "None")))


##################################
# Consent Status Records
##################################
label = "# \n# Consent Status Records \n#################################"
print(label)
request_statuses.append(label)

print ("------------------------------------")
title = "Consent Status Records"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/consents/" + cr_id + "/statuses/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    csr_id = str(entries[1]['data'][0].get("id", "None"))
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))
    print ("csr_id: " + csr_id)


print ("------------------------------------")
title = "One Consent Status Record"
print(title)
try:
    entry = get(host=account_host, endpoint="/api/accounts/" + account_id + "/servicelinks/" + slr_id + "/consents/" + cr_id + "/statuses/" + csr_id + "/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_statuses.append(title + ": " + entry[0] + ": " + json.dumps(entry[1]))
    request_statuses.append("csr_id: " + str(entry[1]['data'].get("id", "None")))
    print ("Response " + entry[0] + ": " + json.dumps(entry[1]))
    print ("csr_id: " + str(entry[1]['data'].get("id", "None")))


##################################
# Export Account
##################################
label = "# \n# Account Export \n#################################"
print(label)
request_statuses.append(label)

print ("------------------------------------")
title = "Account Export"
print(title)
try:
    entries = get(host=account_host, endpoint="/api/accounts/" + account_id + "/export/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + entries[0] + ": " + json.dumps(entries[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response " + entries[0] + ": " + json.dumps(entries[1]))



#################################
#################################
#################################
#################################
# REPORT #
#################################
print ("=====================================")
print("Request report")
for request in request_statuses:
    print(request)


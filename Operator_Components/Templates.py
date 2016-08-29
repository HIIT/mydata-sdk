# -*- coding: utf-8 -*-
from uuid import uuid4 as guid
from time import time
import logging
debug_log = logging.getLogger("debug")

Service_ID_A = 10
Service_ID_B = 100

Service_DescriptionA = {
    "name": "2"
}
Service_DescriptionB = {
    "name": "1"
}

Services = {"10": Service_DescriptionA,
            "100": Service_DescriptionB
            }

Consent_form_Out = {  # From Operator_CR to UI
    "source": {
        "service_id": "String",
        "rs_id": "String",
        "dataset": [
            {
                "datase_id": "String",
                "title": "String",
                "description": "String",
                "keyword": [],
                "publisher": "String",
                "distribution": {
                    "distribution_id": "String",
                    "access_url": "String"
                },
                "component_specification_label": "String",
                "selected": True
            }
        ]
    },
    "sink": {
        "service_id": "String",
        "dataset": [
            {
                "datase_id": "String",
                "title": "String",
                "description": "String",
                "keyword": [],
                "publisher": "String",
                "purposes": [

                    {
                        "title": "All your cats are belong to us",
                        "selected": True,
                        "required": True
                    },
                    {
                        "title": "Something random",
                        "selected": True,
                        "required": True
                    }
                ]
            }
        ]
    }

}

Consent_form_In = {
    "rs_id": ""
}


from instance.settings import SERVICE_URL
class ServiceRegistryHandler:
    def __init__(self):
        # Here could be some code to setup where ServiceRegistry is located etc
        pass

    def getService(self, service_id):
        return Services[str(service_id)]

    def getService_url(self, service_id):
        debug_log.info("getService_url got {} of type {} as parameter.".format(service_id, type(service_id)))
        if isinstance(service_id, unicode):
            service_id = service_id.encode()
        services = {
            "1": SERVICE_URL,
            "2": SERVICE_URL# Our Service_Mgmnt
        }
        return services[service_id]



import logging
from json import dumps, loads
class Sequences:
    def __init__(self, name, seq=False):
        '''

        :param name:
        :param seq:  seq should always be dictionary with "seq" field.
        '''
        self.logger = logging.getLogger("sequence")
        self.name = name
        self.sequence = {}

    def update(self, seq):
        self.sequence.update(seq)

    def send_to(self, to, msg=""):
        return self.seq_tool(msg, to, )

    def reply_to(self, to, msg=""):
        return self.seq_tool(msg, to, dotted=True)

    def task(self, content):

        return self.seq_tool(msg=content, box=False, to=self.name)

    def seq_tool(self, msg=None, to="Change_Me", box=False, dotted=False):

        if box:
            form = 'Note over {}: {}'.format(self.name, msg)
            return self.seq_form(form, self.sequence)
        elif dotted:
            form = "{}-->{}: {}".format(self.name, to, msg)
            return self.seq_form(form, self.sequence)
        else:
            form = "{}->{}: {}".format(self.name, to, msg)
            return self.seq_form(form, self.sequence)

    def dump_sequence(self):
        return ""

    def seq_form(self, line, seq):
        self.logger.info(dumps({"seq": line, "time": time()}))
        return {"seq": {}}

# -*- coding: utf-8 -*-
from uuid import uuid4 as guid
from time import time

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

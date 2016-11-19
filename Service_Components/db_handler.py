# -*- coding: utf-8 -*-
import logging

import MySQLdb

debug_log = logging.getLogger("debug")
def get_db(host, user, password, database, port):
    db = None
    if db is None:
        db = MySQLdb.connect(host=host, user=user, passwd=password, db=database, port=port)
    return db


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))



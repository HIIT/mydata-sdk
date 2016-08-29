# -*- coding: utf-8 -*-
import sqlite3


def get_db(db_path):
    db = None
    if db is None:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row

        try:
            init_db(db)
        except Exception as e:
            pass
    return db



def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def init_db(conn):
    # create db for codes
    conn.execute('''CREATE TABLE cr_tbl
        (rs_id TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE rs_id_tbl
        (rs_id TEXT PRIMARY KEY     NOT NULL,
         used           BOOL    NOT NULL);''')
    conn.execute('''CREATE TABLE session_store
        (code TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    conn.commit()

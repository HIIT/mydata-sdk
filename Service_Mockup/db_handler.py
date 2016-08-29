# -*- coding: utf-8 -*-
import sqlite3


DATABASE = '/tmp/db_Service.sqlite'

def get_db():
    db = None#getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)#g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        try:
            init_db(db)
        except Exception as e:
            pass
    return db



def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def sqlite_create_table(conn, table_name, table_columns):
    conn.cursor.execute("CREATE TABLE {} ({});".format(table_name, ",".join(table_columns)))
    conn.commit()

def init_db(conn):
    # create db for codes
   # conn.execute('''CREATE TABLE codes  (ID TEXT PRIMARY KEY     NOT NULL,  code           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE code_and_user_mapping
        (code TEXT PRIMARY KEY     NOT NULL,
         user_id           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE surrogate_and_user_mapping
        (user_id TEXT PRIMARY KEY     NOT NULL,
         surrogate_id           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE storage
        (ID TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    #sqlite_create_table(conn, "codes", ["id", "text", "code": "text"}) # Create table for codes
    #sqlite_create_table(conn, "")
    conn.commit()
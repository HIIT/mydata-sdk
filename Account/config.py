# -*- coding: utf-8 -*-

from os import urandom

# Statement for enabling the development environment
DEBUG = True

# Enable more detailed logging
SUPER_DEBUG = True

# Application URL prefix
## Only leading slash
URL_PREFIX = ''

# Logger
LOG_FORMATTER = '%(asctime)s - %(name)s in function %(funcName)s at line: %(lineno)s - %(levelname)s - %(message)s'
LOG_PATH = './logs/'
LOG_FILE = LOG_PATH + 'account.log'
LOG_TO_FILE = False

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the database
# Flask-MySQLdb - http://flask-mysqldb.readthedocs.org/en/latest/
MYSQL_HOST = 'localhost'  # Name of host to connect to. Default: use the local host via a UNIX socket (where applicable)
MYSQL_USER = 'mydataaccount'  # User to authenticate as. Default: current effective user.
MYSQL_PASSWORD = 'wr8gabrA'  # Password to authenticate with. Default: no password.
MYSQL_DB = 'MyDataAccount'  # Database to use. Default: no default database.
MYSQL_PORT = 3306  # TCP port of MySQL server. Default: 3306.
#MYSQL_UNIX_SOCKET = ''  # Location of UNIX socket. Default: use default location or TCP for remote hosts.
#MYSQL_CONNECT_TIMEOUT = '10'  # Abort if connect is not completed within given number of seconds. Default: 10
#MYSQL_READ_DEFAULT_FILE = ''  # MySQL configuration file to read, see the MySQL documentation for mysql_options().
#MYSQL_USE_UNICODE = ''  # If True, CHAR and VARCHAR and TEXT columns are returned as Unicode strings, using the configured character set.
MYSQL_CHARSET = 'utf8'  # If present, the connection character set will be changed to this character set, if they are not equal. Default: utf-8
MYSQL_SQL_MODE = 'TRADITIONAL'  # If present, the session SQL mode will be set to the given string.
#MYSQL_CURSORCLASS = ''  # If present, the cursor class will be set to the given string.


# Application threads. A common general assumption is
# using 2 per available processor cores - to handle
# incoming requests using one and performing background
# operations using the other.
THREADS_PER_PAGE = 1

# Enable protection against *Cross-site Request Forgery (CSRF)*
CSRF_ENABLED = True

# Use a secure, unique and absolutely secret key for
# signing the data.
CSRF_SESSION_KEY = str(urandom(24))

# Secret key for signing cookies
SECRET_KEY = str(urandom(24))

# http://flask-restful-cn.readthedocs.org/en/0.3.5/reqparse.html#error-handling
BUNDLE_ERRORS = True

# Flask-Login
LOGIN_VIEW = "signin"  # https://flask-login.readthedocs.org/en/latest/#customizing-the-login-process
LOGIN_MESSAGE = "Authentication required"  # https://flask-login.readthedocs.org/en/latest/#customizing-the-login-process
SESSION_PROTECTION = "strong"  # https://flask-login.readthedocs.org/en/latest/#session-protection
# Optional cookie settings: https://flask-login.readthedocs.org/en/latest/#cookie-settings


# Default locations
AVATAR_URL = 'img/avatars/mydata-avatar.png' # Default icon for Account

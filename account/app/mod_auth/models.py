# -*- coding: utf-8 -*-

# Import dependencies
from app.helpers import get_custom_logger

logger = get_custom_logger('mod_auth_models')


# Define a User model for Flask-Login
# https://flask-login.readthedocs.org/en/latest/#your-user-class
class User():

    account_id = ""
    identity_id = ""
    username = ""
    firstname = ""
    lastname = ""
    email = ""
    avatar = ""
    date_of_birth = ""

    active = False

    def __init__(self, account_id, identity_id, username, firstname="", lastname="", email="", img_url="", date_of_birth="", active=True):
        self.account_id = account_id
        self.identity_id = identity_id
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.avatar = img_url
        self.date_of_birth = date_of_birth

        self.active = active

    @property
    def is_authenticated(self):
        """
        Returns True if the user is authenticated, i.e. they have provided valid credentials.
        (Only authenticated users will fulfill the criteria of login_required.)
        """

        return True

    @property
    def is_active(self):
        """
        Returns True if this is an active user - in addition to being authenticated,
        they also have activated their account, not been suspended, or any condition
        your application has for rejecting an account.
        Inactive accounts may not log in (without being forced of course).
        """

        return self.active

    @property
    def is_anonymous(self):
        """
        Returns True if this is an anonymous user. (Actual users should return False instead.)
        """

        return False

    def get_id(self):
        """
        Returns a unicode that uniquely identifies this user, and can be used to load the user
        from the user_loader callback.

        Note that this must be a unicode - if the ID is natively an int or some other type,
        you will need to convert it to unicode.
        """

        return unicode(self.account_id)

    def get_identity_id(self):
        return unicode(self.identity_id)

    def get_username(self):
        return str(self.username)

    def get_firstname(self):
        return str(self.firstname)

    def get_lastname(self):
        return str(self.lastname)

    def get_email(self):
        return str(self.email)

    def get_date_of_birth(self):
        return str(self.date_of_birth)

    def __repr__(self):
        return 'User < account_id=%s, identity_id=%s, username=%s, firstname=%s, lastname=%s, email=%s, date_of_birth=%s >' % \
               (self.account_id, self.identity_id, self.username, self.firstname, self.lastname, self.email, self.date_of_birth)

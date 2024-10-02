#!/usr/bin/env python3
""" define SessionAuth class """
from api.v1.auth.auth import Auth
import uuid
from typing import Dict
from models.user import User


class SessionAuth(Auth):
    """ class SessionAuth """
    user_id_by_session_id: Dict[str, str] = {}

    def create_session(self, user_id: str = None) -> str:
        """ creates a Session ID for a user_id:
        Return None if user_id is None
        Return None if user_id is not a string
        Otherwise:
            Generate a Session ID using uuid module and uuid4()
            Use this Session ID as key of the dictionary
            user_id_by_session_id - the value for this key must be user_id
            Return the Session ID
        """
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid.uuid4())
        # print("session {}".format(session_id))
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ returns a User ID based on a Session ID:
        Return None if session_id is None
        Return None if session_id is not a string
        Return the value (the User ID) for the key session_id in dict
        user_id_by_session_id.
        """
        if session_id is None or type(session_id) is not str:
            return None
        return self.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None):
        """
         returns a User instance based on a cookie value
        """
        cookie = self.session_cookie(request)
        session_id = self.user_id_for_session_id(cookie)
        user_id = User.get(session_id)
        return user_id

    def destroy_session(self, request=None):
        """ Deletes user session / login(out) """
        cookie_data = self.session_cookie(request)
        if cookie_data is None:
            return False
        if not self.user_id_for_session_id(cookie_data):
            return False
        del self.user_id_by_session_id[cookie_data]
        return True

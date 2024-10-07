#!/usr/bin/env python3
""" Basic authentification """
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ basic auth class """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """the Base64 part of the Authorization header for a
        Basic Authentication:
        """
        if auth_header is None or type(auth_header) is not str:
            return None
        if not auth_header.startswith('Basic '):
            return None
        return auth_header[6:]

    def decode_base64_authorization_header(self, b64_auth_header: str) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header
        """
        if b64_auth_header is None or type(b64_auth_header) is not str:
            return None
        try:
            b64 = base64.b64decode(b64_auth_header)
            b64_decode = b64.decode('utf-8')
        except Exception:
            return None
        return b64_decode

    def extract_user_credentials(self, dec_b64_auth_header: str) -> (str, str):
        """returns the user email and password from
        the Base64 decoded value.
        """
        if dec_b64_auth_header is None or type(dec_b64_auth_header) is not str:
            return (None, None)
        if ":" not in dec_b64_auth_header:
            return (None, None)
        return dec_b64_auth_header.split(':', 1)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password."""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request"""
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        extract_base64 = self.extract_base64_authorization_header(auth_header)
        decode_base64 = self.decode_base64_authorization_header(extract_base64)
        user_credentials = self.extract_user_credentials(decode_base64)
        user_email = user_credentials[0]
        user_password = user_credentials[1]
        user_credentials = self.user_object_from_credentials(
            user_email, user_password)
        return user_credentials

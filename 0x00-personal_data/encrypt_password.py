#!/usr/bin/env python3
"""
hash pass
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ def hash """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ check valid"""
    # hashed = hash_password(password)
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

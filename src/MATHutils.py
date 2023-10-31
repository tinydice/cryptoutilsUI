import hashlib

def hash160(data):
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def sha256(data):
    '''one round of sha256'''
    return hashlib.sha256(data).digest()

def hash256(data):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
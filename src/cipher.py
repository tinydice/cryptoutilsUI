import hashlib
from src.constants import *
from src.utils import bits_to_bytes

def _xor(a: bytes, b: bytes):
    return bytes(x ^ y for x, y in zip(a, b))

def _round_function(i: int, passphrase: bytes, e: int, salt: bytes, r: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        bytes([i]) + passphrase,
        salt + r,
        (BASE_ITERATION_COUNT << e) // ROUND_COUNT,
        dklen=len(r),
    )

def _get_salt(identifier: int):
    identifier_len = bits_to_bytes(ID_LENGTH_BITS)
    return CUSTOMIZATION_STRING + identifier.to_bytes(identifier_len, "big")


def encrypt(master_secret: bytes, passphrase: bytes, iteration_exponent: int, identifier: int):
    l = master_secret[: len(master_secret) // 2]
    r = master_secret[len(master_secret) // 2 :]

    salt = _get_salt(identifier)

    for i in range(ROUND_COUNT):
        f = _round_function(i, passphrase, iteration_exponent, salt, r)
        l, r = r, _xor(l, f)
    return r + l

def decrypt(encrypted_master_secret: bytes, passphrase: bytes, iteration_exponent: int, identifier: int):

    l = encrypted_master_secret[: len(encrypted_master_secret) // 2]
    r = encrypted_master_secret[len(encrypted_master_secret) // 2 :]
    salt = _get_salt(identifier)
    for i in reversed(range(ROUND_COUNT)):
        f = _round_function(i, passphrase, iteration_exponent, salt, r)
        l, r = r, _xor(l, f)
    return r + l

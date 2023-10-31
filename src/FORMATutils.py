from bech32 import *
from .ECCutils import *
from .MATHutils import *

def convert_path(path_string):
    components = path_string.split('/')[1:]  # Split the string and remove the leading 'm'
    path = []
    for component in components:
        if "'" in component:
            index = int(component.replace("'", ""))
            path.append((index, True))
        else:
            index = int(component)
            path.append((index, False))

    return path

def get_pubkey(private_key_bytes):
    """
    This function returns SEC encoded public key from byte-encoded private key
    """
    secret = int.from_bytes(private_key_bytes, "big")
    private_key = PrivateKey(secret)
    public_key = private_key.point
    return public_key.sec(compressed=True)

def pubkey_to_P2PKH(pubkey_bytes):
    return encode_base58_checksum(b'\x00' + hash160(pubkey_bytes))

def pubkey_to_P2SHpP2WPKH(pubkey_bytes):
    redeem_script = b'\x00\x14' + hash160(pubkey_bytes)
    script_hash = b'\x05' + hash160(redeem_script)
    return encode_base58_checksum(script_hash)

def pubkey_to_bech32(pubkey_bytes):
    step1 = hash160(pubkey_bytes)
    step2 = bytes_to_byte_groups(step1, 5)
    step3 = b'\x00' + step2
    return bech32_encode('bc', step3)

def bytes_priv_to_wif(secret_bytes, compressed=True, testnet=False):
    # prepend b'\xef' on testnet, b'\x80' on mainnet
    if testnet:
        prefix = b'\xef'
    else:
        prefix = b'\x80'
    # append b'\x01' if compressed
    if compressed:
        suffix = b'\x01'
    else:
        suffix = b''
    # encode_base58_checksum the whole thing
    return encode_base58_checksum(prefix + secret_bytes + suffix)

def wif_to_hex_prv(wif):
    hex_wif = hex(int.from_bytes(decode_base58(wif), 'big'))[3:-6]
    hex_prv = hex_wif[1:-4]
    return hex_prv

def wif_to_P2PKH(wif):
    hex_prv = wif_to_hex_prv(wif)
    private_key = bytes.fromhex(hex_prv)
    public_key = get_pubkey(private_key)
    public_address = pubkey_to_P2PKH(public_key)
    return public_address

def wif_to_P2SHpP2WPKH(wif):
    hex_prv = wif_to_hex_prv(wif)
    private_key = bytes.fromhex(hex_prv)
    public_key = get_pubkey(private_key)
    public_address = pubkey_to_P2SHpP2WPKH(public_key)
    return public_address

def wif_to_bech32(wif):
    hex_prv = wif_to_hex_prv(wif)
    private_key = bytes.fromhex(hex_prv)
    public_key = get_pubkey(private_key)
    public_address = pubkey_to_bech32(public_key)
    return public_address
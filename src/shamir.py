import hmac
import secrets
from typing import Dict, Iterable, List, NamedTuple, Sequence, Set
from src.cipher import *
from src.constants import *
from src.share import *
from src.utils import *

class RawShare(NamedTuple):
    x: int
    data: bytes

class ShareGroup:
    def __init__(self) -> None:
        self.shares: Set[Share] = set()

    def add(self, share: Share):
        self.shares.add(share)

    def to_raw_shares(self):
        return [RawShare(s.index, s.value) for s in self.shares]

    def common_parameters(self):
        return next(iter(self.shares)).common_parameters()

    def group_parameters(self):
        return next(iter(self.shares)).group_parameters()

    def member_threshold(self):
        return next(iter(self.shares)).member_threshold

    def is_complete(self):
        if self.shares:
            return len(self.shares) >= self.member_threshold()
        else:
            return False

class EncryptedEntropy:
    def __init__(self, identifier: int, iteration_exponent: int, ciphertext: bytes):
        self.identifier = identifier
        self.iteration_exponent = iteration_exponent
        self.ciphertext = ciphertext

    @classmethod
    def from_entropy(cls, master_secret: bytes, passphrase: bytes, identifier: int, iteration_exponent: int):
        ciphertext = encrypt(master_secret, passphrase, iteration_exponent, identifier)

        return EncryptedEntropy(identifier, iteration_exponent, ciphertext)
    def to_entropy(self, passphrase: bytes):
        return decrypt(self.ciphertext, passphrase, self.iteration_exponent, self.identifier)

RANDOM_BYTES = secrets.token_bytes

def _precompute_exp_log():
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log

EXP_TABLE, LOG_TABLE = _precompute_exp_log()

def _interpolate(shares: Sequence[RawShare], x: int):
    x_coordinates = set(share.x for share in shares)

    share_value_lengths = set(len(share.data) for share in shares)

    if x in x_coordinates:
        for share in shares:
            if share.x == x:
                return share.data

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(LOG_TABLE[share.x ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - LOG_TABLE[share.x ^ x]
            - sum(LOG_TABLE[share.x ^ other.x] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                EXP_TABLE[(LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share.data, result)
        )

    return result

def _create_digest(random_data: bytes, shared_secret: bytes):
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]

def _split_secret(threshold: int, share_count: int, shared_secret: bytes):
    if threshold == 1:
        return [RawShare(i, shared_secret) for i in range(share_count)]

    random_share_count = threshold - 2

    shares = [
        RawShare(i, RANDOM_BYTES(len(shared_secret))) for i in range(random_share_count)
    ]

    random_part = RANDOM_BYTES(len(shared_secret) - DIGEST_LENGTH_BYTES)
    digest = _create_digest(random_part, shared_secret)

    base_shares = shares + [
        RawShare(DIGEST_INDEX, digest + random_part),
        RawShare(SECRET_INDEX, shared_secret),
    ]

    for i in range(random_share_count, share_count):
        shares.append(RawShare(i, _interpolate(base_shares, i)))

    return shares

def _recover_secret(threshold: int, shares: Sequence[RawShare]):
    if threshold == 1:
        return next(iter(shares)).data

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    return shared_secret


def decode_mnemonics(mnemonics: Iterable[str]):
    common_params: Set[ShareCommonParameters] = set()
    shares = ShareGroup()
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        shares.add(share)

    return shares

def split_ems(
    encrypted_entropy: EncryptedEntropy,
    member_threshold: int,
    member_count:int):

    shares = _split_secret(1, 1, encrypted_entropy.ciphertext)

    tempShares = _split_secret(member_threshold, member_count, shares[0].data)

    return [
            Share(
                encrypted_entropy.identifier,
                encrypted_entropy.iteration_exponent,
                0, 1, 1,
                member_index,
                member_threshold,
                value)
            for member_index, value in _split_secret(member_threshold, member_count, shares[0].data)
        ]

def _random_identifier():
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(member_threshold:int, member_count:int, entropyHash: bytes, passphrase: str, iteration_exponent: int = 1):
    passphrase = passphrase.encode('utf-8')
    identifier = _random_identifier()

    encrypted_entropy = EncryptedEntropy.from_entropy(entropyHash, passphrase, identifier, iteration_exponent)
    print(encrypted_entropy.ciphertext.hex())
    shares = split_ems(encrypted_entropy, member_threshold=member_threshold, member_count=member_count)
    return [share.mnemonic() for share in shares]


def recover_ems(shares):
    params = shares.common_parameters()

    group_shares = [
        RawShare(0, _recover_secret(shares.member_threshold(), shares.to_raw_shares()))
    ]

    ciphertext = _recover_secret(params.group_threshold, group_shares)
    return EncryptedEntropy(params.identifier, params.iteration_exponent, ciphertext)

def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b""):
    shares = decode_mnemonics(mnemonics)
    encrypted_entropy = recover_ems(shares)
    return encrypted_entropy.to_entropy(passphrase)
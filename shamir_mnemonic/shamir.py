import hmac
import secrets
from typing import Any, Dict, Iterable, List, NamedTuple, Sequence, Set, Tuple

from . import cipher
from .constants import (
    DIGEST_INDEX,
    DIGEST_LENGTH_BYTES,
    GROUP_PREFIX_LENGTH_WORDS,
    ID_EXP_LENGTH_WORDS,
    ID_LENGTH_BITS,
    SECRET_INDEX,
)
from .share import Share, ShareCommonParameters, ShareGroupParameters
from .utils import MnemonicError, bits_to_bytes


class RawShare(NamedTuple):
    x: int
    data: bytes


class ShareGroup:
    def __init__(self) -> None:
        self.shares: Set[Share] = set()

    def __iter__(self) -> Iterable[Share]:
        return iter(self.shares)

    def __len__(self) -> int:
        return len(self.shares)

    def __bool__(self) -> bool:
        return bool(self.shares)

    def __contains__(self, obj: Any) -> bool:
        return obj in self.shares

    def add(self, share: Share) -> None:
        if self.shares and self.group_parameters() != share.group_parameters():
            fields = zip(
                ShareGroupParameters._fields,
                self.group_parameters(),
                share.group_parameters(),
            )
            mismatch = next(name for name, x, y in fields if x != y)
            raise MnemonicError(
                f"Invalid set of mnemonics. The {mismatch} parameters don't match."
            )

        self.shares.add(share)

    def to_raw_shares(self) -> List[RawShare]:
        return [RawShare(s.index, s.value) for s in self.shares]

    def get_minimal_group(self) -> "ShareGroup":
        group = ShareGroup()
        group.shares = set(
            share for _, share in zip(range(self.member_threshold()), self.shares)
        )
        return group

    def common_parameters(self) -> ShareCommonParameters:
        return next(iter(self.shares)).common_parameters()

    def group_parameters(self) -> ShareGroupParameters:
        return next(iter(self.shares)).group_parameters()

    def member_threshold(self) -> int:
        return next(iter(self.shares)).member_threshold

    def is_complete(self) -> int:
        if self.shares:
            return len(self.shares) >= self.member_threshold()
        else:
            return False


class EncryptedMasterSecret:
    def __init__(self, identifier: int, iteration_exponent: int, ciphertext: bytes):
        self.identifier = identifier
        self.iteration_exponent = iteration_exponent
        self.ciphertext = ciphertext

    @classmethod
    def from_master_secret(
        cls,
        master_secret: bytes,
        passphrase: bytes,
        identifier: int,
        iteration_exponent: int,
    ) -> "EncryptedMasterSecret":
        ciphertext = cipher.encrypt(
            master_secret, passphrase, iteration_exponent, identifier
        )
        return EncryptedMasterSecret(identifier, iteration_exponent, ciphertext)

    def decrypt(self, passphrase: bytes) -> bytes:
        return cipher.decrypt(
            self.ciphertext, passphrase, self.iteration_exponent, self.identifier
        )


RANDOM_BYTES = secrets.token_bytes
"""Source of random bytes. Can be overriden for deterministic testing."""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
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


def _interpolate(shares: Sequence[RawShare], x: int) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share.x for share in shares)

    if len(x_coordinates) != len(shares):
        raise MnemonicError("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share.data) for share in shares)
    if len(share_value_lengths) != 1:
        raise MnemonicError(
            "Invalid set of shares. All share values must have the same length."
        )

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


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]


def _split_secret(
    threshold: int, share_count: int, shared_secret: bytes
) -> List[RawShare]:

    # If the threshold is 1, then the digest of the shared secret is not used.
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


def _recover_secret(threshold: int, shares: Sequence[RawShare]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return next(iter(shares)).data

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise MnemonicError("Invalid digest of the shared secret.")

    return shared_secret


def decode_mnemonics(mnemonics: Iterable[str]) -> Dict[int, ShareGroup]:
    common_params: Set[ShareCommonParameters] = set()
    groups: Dict[int, ShareGroup] = {}
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        common_params.add(share.common_parameters())
        group = groups.setdefault(share.group_index, ShareGroup())
        group.add(share)

    if len(common_params) != 1:
        raise MnemonicError(
            "Invalid set of mnemonics. "
            f"All mnemonics must begin with the same {ID_EXP_LENGTH_WORDS} words, "
            "must have the same group threshold and the same group count."
        )

    return groups


def split_ems(
    encrypted_master_secret: EncryptedMasterSecret,
    member_threshold: int,
    member_count:int,
) -> List[List[str]]:

    shares = _split_secret(1, 1, encrypted_master_secret.ciphertext)

    return [
            Share(
                encrypted_master_secret.identifier,
                encrypted_master_secret.iteration_exponent,
                0, 1, 1,
                member_index,
                member_threshold,
                value,
            )
            for member_index, value in _split_secret(
                member_threshold, member_count, shares[0].data
            )
        ]


def _random_identifier() -> int:
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(
    member_threshold:int,
    member_count:int,
    master_secret: bytes,
    passphrase: str,
    iteration_exponent: int = 1,
) -> List[List[str]]:

    identifier = _random_identifier()
    encrypted_master_secret = EncryptedMasterSecret.from_master_secret(
        master_secret, passphrase.encode('utf-8'), identifier, iteration_exponent
    )

    shares = split_ems(encrypted_master_secret, member_threshold=member_threshold, member_count=member_count)
    return [share.mnemonic() for share in shares]


def recover_ems(groups: Dict[int, ShareGroup]) -> EncryptedMasterSecret:
    params = next(iter(groups.values())).common_parameters()

    group_shares = [
        RawShare(
            group_index,
            _recover_secret(group.member_threshold(), group.to_raw_shares()),
        )
        for group_index, group in groups.items()
    ]

    ciphertext = _recover_secret(params.group_threshold, group_shares)
    return EncryptedMasterSecret(
        params.identifier, params.iteration_exponent, ciphertext
    )


def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b"") -> bytes:
    groups = decode_mnemonics(mnemonics)
    encrypted_master_secret = recover_ems(groups)
    return encrypted_master_secret.decrypt(passphrase)

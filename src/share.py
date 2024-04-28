from typing import Iterable, List, NamedTuple

import attr

from . import wordlist, rs1024
from src.constants import *
from src.utils import bits_to_bytes, bits_to_words, int_to_indices

WordIndex = int

def _int_to_word_indices(value: int, length: int) -> List[WordIndex]:
    """Converts an integer value to a list of base 1024 indices in big endian order."""
    return list(int_to_indices(value, length, radix_bits=RADIX_BITS))


def _int_from_word_indices(indices: Iterable[WordIndex]) -> int:
    """Converts a list of base 1024 indices in big endian order to an integer value."""
    value = 0
    for index in indices:
        value = value * RADIX + index
    return value

class ShareCommonParameters(NamedTuple):
    identifier: int
    iteration_exponent: int
    group_threshold: int
    group_count: int

class ShareGroupParameters(NamedTuple):
    identifier: int
    iteration_exponent: int
    group_index: int
    group_threshold: int
    group_count: int
    member_threshold: int

@attr.s(auto_attribs=True, frozen=True)
class Share:
    identifier: int
    iteration_exponent: int
    group_index: int
    group_threshold: int
    group_count: int
    index: int
    member_threshold: int
    value: bytes

    def common_parameters(self) -> ShareCommonParameters:
        return ShareCommonParameters(
            self.identifier,
            self.iteration_exponent,
            self.group_threshold,
            self.group_count,
        )

    def _encode_id_exp(self) -> List[WordIndex]:
        id_exp_int = (
            self.identifier << ITERATION_EXP_LENGTH_BITS
        ) + self.iteration_exponent
        return _int_to_word_indices(id_exp_int, ID_EXP_LENGTH_WORDS)

    def _encode_share_params(self) -> List[WordIndex]:
        # each value is 4 bits, for 20 bits total
        val = self.group_index
        val <<= 4
        val += self.group_threshold - 1
        val <<= 4
        val += self.group_count - 1
        val <<= 4
        val += self.index
        val <<= 4
        val += self.member_threshold - 1
        # group parameters are 2 words
        return _int_to_word_indices(val, 2)

    def words(self) -> List[str]:
        value_word_count = bits_to_words(len(self.value) * 8)
        value_int = int.from_bytes(self.value, "big")
        value_data = _int_to_word_indices(value_int, value_word_count)

        share_data = self._encode_id_exp() + self._encode_share_params() + value_data
        checksum = rs1024.create_checksum(share_data)

        return list(wordlist.words_from_indices(share_data + checksum))

    def mnemonic(self) -> str:
        return " ".join(self.words())

    @classmethod
    def from_mnemonic(cls, mnemonic: str) -> "Share":
        mnemonic_data = wordlist.mnemonic_to_indices(mnemonic)

        padding_len = (RADIX_BITS * (len(mnemonic_data) - METADATA_LENGTH_WORDS)) % 16

        id_exp_data = mnemonic_data[:ID_EXP_LENGTH_WORDS]
        id_exp_int = _int_from_word_indices(id_exp_data)

        identifier = id_exp_int >> ITERATION_EXP_LENGTH_BITS
        iteration_exponent = id_exp_int & ((1 << ITERATION_EXP_LENGTH_BITS) - 1)

        share_params_data = mnemonic_data[ID_EXP_LENGTH_WORDS : ID_EXP_LENGTH_WORDS + 2]
        share_params_int = _int_from_word_indices(share_params_data)
        share_params = int_to_indices(share_params_int, 5, 4)
        (
            group_index,
            group_threshold,
            group_count,
            index,
            member_threshold,
        ) = share_params

        value_data = mnemonic_data[
            ID_EXP_LENGTH_WORDS + 2 : -rs1024.CHECKSUM_LENGTH_WORDS
        ]
        value_byte_count = bits_to_bytes(RADIX_BITS * len(value_data) - padding_len)
        value_int = _int_from_word_indices(value_data)
        value = value_int.to_bytes(value_byte_count, "big")

        return cls(
            identifier,
            iteration_exponent,
            group_index,
            group_threshold + 1,
            group_count + 1,
            index,
            member_threshold + 1,
            value,
        )

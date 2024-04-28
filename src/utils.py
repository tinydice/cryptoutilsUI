from typing import Iterable
from . import constants

# class MnemonicError(Exception):
#     pass

def _round_bits(n: int, radix_bits: int) -> int:
    """Get the number of `radix_bits`-sized digits required to store a `n`-bit value."""
    return (n + radix_bits - 1) // radix_bits


def bits_to_bytes(n: int) -> int:
    """Round up bit count to whole bytes."""
    return _round_bits(n, 8)


def bits_to_words(n: int) -> int:
    """Round up bit count to a multiple of word size."""

    assert hasattr(constants, "RADIX_BITS"), "Declare RADIX_BITS *before* calling this"

    return _round_bits(n, constants.RADIX_BITS)


def int_to_indices(value: int, length: int, radix_bits: int) -> Iterable[int]:
    """Convert an integer value to indices in big endian order."""
    mask = (1 << radix_bits) - 1
    return ((value >> (i * radix_bits)) & mask for i in reversed(range(length)))

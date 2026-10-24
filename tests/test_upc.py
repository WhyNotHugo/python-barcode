"""Tests for UPC-A (``barcode.upc``).

UPC-A previously had no dedicated tests: only a single rendering in
``test_manually.py``. These pin checksum calculation, input trimming,
validation errors, and the ``make_ean`` conversion.
"""

from __future__ import annotations

import pytest

from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError
from barcode.upc import UPCA


@pytest.mark.parametrize(
    ("given", "full", "checksum"),
    [
        ("03600029145", "036000291452", 2),
        ("01234567890", "012345678905", 5),
        ("99999999999", "999999999993", 3),
        ("00000000000", "000000000000", 0),
        ("12345678901", "123456789012", 2),
    ],
)
def test_upca_checksums(given: str, full: str, checksum: int) -> None:
    upc = UPCA(given)
    assert upc.get_fullcode() == full
    assert upc.calculate_checksum() == checksum
    assert str(upc) == full


def test_upca_twelve_digit_input_is_trimmed_and_recomputed() -> None:
    # A 12th digit is dropped and the checksum recalculated from the
    # first eleven digits, so even a *wrong* supplied digit is ignored.
    assert UPCA("036000291452").get_fullcode() == "036000291452"
    assert UPCA("036000291459").get_fullcode() == "036000291452"


def test_upca_too_short_raises_number_of_digits() -> None:
    with pytest.raises(NumberOfDigitsError, match="UPC must have 11 digits, not 3"):
        UPCA("123")


def test_upca_non_digit_raises_illegal_character() -> None:
    with pytest.raises(
        IllegalCharacterError, match="UPC code can only contain numbers"
    ):
        UPCA("0360002914a")


def test_upca_make_ean_prefixes_a_zero() -> None:
    upc = UPCA("03600029145", make_ean=True)
    assert str(upc) == "0036000291452"
    assert upc.get_fullcode() == "0036000291452"
    # The stored code itself keeps its 12 digits (no leading zero).
    assert upc.upc == "036000291452"


def test_upca_without_make_ean_has_no_leading_zero() -> None:
    upc = UPCA("03600029145")
    assert str(upc) == "036000291452"
    assert upc.get_fullcode() == "036000291452"


def test_upca_build_is_95_modules() -> None:
    code = UPCA("03600029145").build()
    assert code == [
        "1010001101011110101011110001101000110100011010101011011"
        "0011101001100110101110010011101101100101"
    ]
    assert len(code[0]) == 95


def test_upca_to_ascii_uses_bars_and_underscores() -> None:
    ascii_code = UPCA("03600029145").to_ascii()
    assert ascii_code.startswith("|_|___||_|_||||_|_|_")
    assert set(ascii_code) <= {"|", "_"}


def test_upca_attributes() -> None:
    assert UPCA.name == "UPC-A"
    assert UPCA.digits == 11

"""Tests for Code 39 and PZN (``barcode.codex``).

``test_checksums.py`` pins a single checksum example for each; these
tests cover the wider behaviour: upper-casing, the checksum character
for a range of inputs, building every legal character, the error
paths, and PZN length/checksum validation.
"""

from __future__ import annotations

import pytest

from barcode.charsets import code39 as code39_charset
from barcode.codex import PZN
from barcode.codex import PZN8
from barcode.codex import Code39
from barcode.errors import BarcodeError
from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError


@pytest.mark.parametrize(
    ("given", "full"),
    [
        ("ABC", "ABCX"),
        ("A", "AA"),
        ("0", "00"),
        ("HELLO", "HELLOB"),
        ("12345", "12345F"),
        ("-", "--"),
        (" ", "  "),
    ],
)
def test_code39_appended_checksum_characters(given: str, full: str) -> None:
    code = Code39(given)
    assert code.code == full
    assert code.get_fullcode() == full
    assert str(code) == full


def test_code39_input_is_uppercased() -> None:
    assert Code39("abc").code == "ABCX"


def test_code39_without_checksum_keeps_code_unchanged() -> None:
    code = Code39("ABC", add_checksum=False)
    assert code.code == "ABC"
    assert code.get_fullcode() == "ABC"


def test_code39_empty_input_produces_checksum_zero_character() -> None:
    # The checksum of an empty string is 0, whose character is "0".
    assert Code39("").code == "0"


def test_code39_illegal_character_without_checksum() -> None:
    with pytest.raises(
        IllegalCharacterError, match="not valid for Code 39: @"
    ):
        Code39("A@B", add_checksum=False)


def test_code39_illegal_character_with_checksum_raises_key_error() -> None:
    # With the default add_checksum=True, the checksum is calculated
    # before the character validation runs, so an illegal character
    # surfaces as a KeyError from the charset map instead of an
    # IllegalCharacterError. This pins the current behaviour.
    with pytest.raises(KeyError):
        Code39("A@B")
    with pytest.raises(KeyError):
        Code39("a_b")


def test_code39_calculate_checksum_resums_the_full_code() -> None:
    # calculate_checksum() sums self.code as-is. After construction the
    # code already includes the checksum character, so calling it again
    # yields a different value ("N" for "ABCX", whose real checksum
    # character is "X"). This pins the current behaviour.
    assert Code39("ABC").calculate_checksum() == "N"


def test_code39_build_for_a_single_character() -> None:
    assert Code39("A", add_checksum=False).build() == [
        "10001011101110101110101000101110100010111011101"
    ]


@pytest.mark.parametrize("char", list(code39_charset.REF))
def test_code39_builds_every_legal_character(char: str) -> None:
    # Each symbol is framed by the start/stop pattern (EDGE) and joined
    # with the single-module separator (MIDDLE).
    expected = code39_charset.MIDDLE.join(
        [code39_charset.EDGE, code39_charset.MAP[char][1], code39_charset.EDGE]
    )
    assert Code39(char, add_checksum=False).build() == [expected]


def test_code39_name() -> None:
    assert Code39.name == "Code 39"


def test_pzn_too_short_raises_number_of_digits() -> None:
    with pytest.raises(NumberOfDigitsError, match="PZN must have 6 digits, not 5"):
        PZN("12345")


def test_pzn_non_digit_raises_illegal_character() -> None:
    with pytest.raises(IllegalCharacterError, match="PZN can only contain numbers"):
        PZN("12345a")


def test_pzn_input_longer_than_six_digits_is_trimmed() -> None:
    assert PZN("123456789").get_fullcode() == "PZN-1234562"


def test_pzn_checksum_of_ten_is_rejected() -> None:
    # 000003 has weighted sum 3 * 7 = 21, and 21 % 11 == 10, which is
    # not a representable PZN check digit.
    with pytest.raises(BarcodeError, match="Checksum can not be 10 for PZN"):
        PZN("000003")


def test_pzn8_uses_seven_digits() -> None:
    assert PZN8("1234567").get_fullcode() == "PZN-12345673"
    with pytest.raises(NumberOfDigitsError, match="PZN must have 7 digits, not 6"):
        PZN8("123456")

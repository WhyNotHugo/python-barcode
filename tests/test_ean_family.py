"""Tests for the EAN family (EAN-13, EAN-8, EAN-14, JAN).

Focuses on input validation, trimming of overlong input, checksum
calculation for a range of values, the guard-bar variants and JAN
country-code boundaries. The checksum/no_checksum interplay for
EAN-13 itself is already covered by ``test_ean.py``.
"""

from __future__ import annotations

import pytest

from barcode.ean import EAN8
from barcode.ean import EAN8_GUARD
from barcode.ean import EAN13
from barcode.ean import EAN13_GUARD
from barcode.ean import EAN14
from barcode.ean import JAN
from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError
from barcode.errors import WrongCountryCodeError


def test_ean13_trims_input_longer_than_twelve_digits() -> None:
    # Only the first 12 digits are used; the checksum is then (re)calculated.
    assert EAN13("8421671433229999").ean == "8421671433225"


def test_ean13_too_short_raises_number_of_digits() -> None:
    with pytest.raises(
        NumberOfDigitsError, match="EAN must have 12 digits, received 3"
    ):
        EAN13("123")


def test_ean13_non_digit_raises_illegal_character() -> None:
    with pytest.raises(IllegalCharacterError, match="EAN code can only contain numbers"):
        EAN13("84216714332a")


def test_ean13_empty_input_raises_illegal_character() -> None:
    with pytest.raises(IllegalCharacterError):
        EAN13("")


def test_ean13_checksum_of_explicit_value() -> None:
    ean = EAN13("842167143322")
    assert ean.calculate_checksum("123456789012") == 8
    assert ean.calculate_checksum("000000000000") == 0


def test_ean13_build_is_95_modules() -> None:
    code = EAN13("842167143322").build()
    assert code == [
        "1010100011001101100110010000101001000100110010101010111"
        "0010000101000010110110011011001001110101"
    ]
    assert len(code[0]) == 95


def test_ean13_guard_variant_fullcode_and_pattern() -> None:
    ean = EAN13_GUARD("842167143322")
    assert ean.get_fullcode() == "8 421671 433225 >"
    assert "G" in ean.build()[0]


def test_ean13_to_ascii_uses_bars_and_spaces() -> None:
    ascii_code = EAN13("842167143322").to_ascii()
    assert ascii_code == (
        "| | |   ||  || ||  ||  |    | |  |   |  ||  | | | | |||  |    "
        "| |    | || ||  || ||  |  ||| | |"
    )
    assert set(ascii_code) <= {"|", " "}


def test_ean13_repr_and_attributes() -> None:
    ean = EAN13("842167143322")
    assert repr(ean) == "<EuropeanArticleNumber13('8421671433225')>"
    assert EAN13.name == "EAN-13"
    assert EAN13.digits == 12


@pytest.mark.parametrize(
    ("given", "full", "checksum"),
    [
        ("1234567", "12345670", 0),
        ("0000000", "00000000", 0),
        ("9999999", "99999995", 5),
        ("4026770", "40267708", 8),
    ],
)
def test_ean8_checksums(given: str, full: str, checksum: int) -> None:
    ean = EAN8(given)
    assert ean.ean == full
    assert ean.calculate_checksum() == checksum


def test_ean8_trims_input_longer_than_seven_digits() -> None:
    assert EAN8("12345678901").ean == "12345670"


def test_ean8_too_short_raises_number_of_digits() -> None:
    with pytest.raises(NumberOfDigitsError, match="EAN must have 7 digits, received 3"):
        EAN8("123")


def test_ean8_non_digit_raises_illegal_character() -> None:
    with pytest.raises(IllegalCharacterError, match="EAN code can only contain numbers"):
        EAN8("123456a")


def test_ean8_build_is_67_modules() -> None:
    assert len(EAN8("6032299").build()[0]) == 67
    assert EAN8.name == "EAN-8"
    assert EAN8.digits == 7


def test_ean8_guard_variant_fullcode() -> None:
    assert EAN8_GUARD("6032299").get_fullcode() == "< 6032 2999 >"
    assert EAN8("6032299").get_fullcode() == "60322999"


@pytest.mark.parametrize(
    ("given", "full", "checksum"),
    [
        ("1234567890123", "12345678901231", 1),
        ("0000000000000", "00000000000000", 0),
        ("0590123412345", "05901234123457", 7),
        ("9999999999999", "99999999999997", 7),
    ],
)
def test_ean14_checksums(given: str, full: str, checksum: int) -> None:
    ean = EAN14(given)
    assert ean.ean == full
    assert ean.calculate_checksum() == checksum


def test_ean14_too_short_raises_number_of_digits() -> None:
    with pytest.raises(
        NumberOfDigitsError, match="EAN must have 13 digits, received 3"
    ):
        EAN14("123")


def test_ean14_non_digit_raises_illegal_character() -> None:
    with pytest.raises(IllegalCharacterError, match="EAN code can only contain numbers"):
        EAN14("123456789012a")


def test_ean14_build_is_102_modules() -> None:
    assert len(EAN14("1234567890123").build()[0]) == 102
    assert EAN14.name == "EAN-14"
    assert EAN14.digits == 13


@pytest.mark.parametrize(
    ("given", "full"),
    [
        ("450123456789", "4501234567896"),
        ("459123456789", "4591234567897"),
        ("490123456789", "4901234567894"),
        ("499123456789", "4991234567895"),
    ],
)
def test_jan_accepts_country_codes_at_the_boundaries(given: str, full: str) -> None:
    assert JAN(given).get_fullcode() == full


@pytest.mark.parametrize(
    "given",
    ["460123456789", "489123456789", "500123456789", "123456789012"],
)
def test_jan_rejects_country_codes_outside_the_ranges(given: str) -> None:
    with pytest.raises(
        WrongCountryCodeError, match="Country code isn't between 450-460 or 490-500"
    ):
        JAN(given)


def test_jan_country_code_is_checked_before_length() -> None:
    # Even a two-digit input reports the country code, not the length.
    with pytest.raises(WrongCountryCodeError):
        JAN("49")


def test_jan_non_numeric_prefix_raises_value_error() -> None:
    # JAN parses the first three characters with int() before validating,
    # so a non-numeric prefix surfaces a plain ValueError (not a
    # BarcodeError). This pins the current behaviour.
    with pytest.raises(ValueError, match="invalid literal for int"):
        JAN("49a123456789")

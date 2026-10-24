"""Tests for ISBN-13 / ISBN-10 / ISSN validation (``barcode.isxn``).

``test_checksums.py`` pins one checksum example per type; these tests
cover the surrounding contract: hyphen stripping, the ISBN-13 prefix
rules (978 / 979), ISBN-10's "supplied check digit is recomputed"
behaviour including ``X`` check digits, and ISSN conversion to EAN-13.
"""

from __future__ import annotations

import pytest

from barcode.errors import BarcodeError
from barcode.errors import NumberOfDigitsError
from barcode.errors import WrongCountryCodeError
from barcode.isxn import ISBN10
from barcode.isxn import ISBN13
from barcode.isxn import ISSN


def test_isbn13_strips_hyphens() -> None:
    isbn = ISBN13("978-3-16-148410-0")
    assert isbn.isbn13 == "9783161484100"
    assert isbn.get_fullcode() == "9783161484100"


def test_isbn13_rejects_non_bookland_prefix() -> None:
    with pytest.raises(
        WrongCountryCodeError, match="ISBN must start with 978 or 979"
    ):
        ISBN13("977123456789")


@pytest.mark.parametrize("given", ["979012345678", "979212345678"])
def test_isbn13_979_with_wrong_fourth_digit_raises_plain_barcode_error(
    given: str,
) -> None:
    with pytest.raises(BarcodeError, match="ISBN must start with 97910 or 97911") as e:
        ISBN13(given)
    # The base BarcodeError is raised, not one of its subclasses.
    assert type(e.value) is BarcodeError


def test_isbn13_979_prefixes() -> None:
    assert ISBN13("979123456789").get_fullcode() == "9791234567896"
    # The check actually accepts a fourth digit of 1 or 8, even though
    # the error message only mentions 97910 and 97911.
    assert ISBN13("979812345678").get_fullcode() == "9798123456781"


def test_isbn13_too_short_raises_number_of_digits() -> None:
    with pytest.raises(NumberOfDigitsError):
        ISBN13("978123")


def test_isbn10_documented_example() -> None:
    isbn = ISBN10("0132354187")
    assert isbn.isbn10 == "0132354187"
    assert str(isbn) == "0132354187"
    assert isbn.get_fullcode() == "9780132354189"


def test_isbn10_supplied_check_digit_is_ignored_and_recomputed() -> None:
    # Only the first nine digits are read; the check digit is always
    # recalculated, so a wrong (or placeholder) last character is fixed.
    assert ISBN10("0132354180").isbn10 == "0132354187"
    assert ISBN10("013235418X").isbn10 == "0132354187"


def test_isbn10_strips_hyphens() -> None:
    assert ISBN10("3-12-517154-7").isbn10 == "3125171547"


@pytest.mark.parametrize(
    ("given", "full"),
    [
        ("013235411", "013235411X"),
        ("123456789", "123456789X"),
        ("000000006", "000000006X"),
        ("999999993", "999999993X"),
    ],
)
def test_isbn10_x_check_digit(given: str, full: str) -> None:
    # When the weighted sum mod 11 is 10, the check digit is "X".
    assert ISBN10(given).isbn10 == full


def test_issn_checksum_x_and_conversion_to_ean() -> None:
    issn = ISSN("1144875")
    assert issn.issn == "1144875X"
    assert str(issn) == "1144875X"
    assert issn.get_fullcode() == "9771144875007"


def test_issn_make_ean_keeps_the_x_placeholder() -> None:
    # make_ean() interpolates the ISSN check digit verbatim (here "X");
    # the EAN-13 layer later replaces it with its own numeric checksum.
    assert ISSN("1144875").make_ean() == "977114487500X"


def test_issn_hyphens_and_supplied_check_digit_are_ignored() -> None:
    assert ISSN("1144-875").issn == "1144875X"
    assert ISSN("1144875X").issn == "1144875X"


def test_issn_numeric_checksum() -> None:
    issn = ISSN("2049363")
    assert issn.issn == "20493630"
    assert issn.get_fullcode() == "9772049363002"


def test_issn_short_input_is_not_validated() -> None:
    # ISSN performs no length validation: a five-digit input is padded
    # into a (meaningless) EAN-13 instead of raising. This pins the
    # current behaviour; see the PR description.
    issn = ISSN("12345")
    assert issn.issn == "123455"
    assert issn.get_fullcode() == "9771234550029"

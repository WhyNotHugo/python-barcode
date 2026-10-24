"""Tests for the barcode registry in ``barcode/__init__.py``.

Covers ``PROVIDED_BARCODES``, name lookup (including aliases and
case-insensitivity), and the ``BarcodeNotFoundError`` raised for
unknown names. Existing tests only exercise ``generate()`` and use
``get_barcode`` incidentally; the lookup contract itself is pinned here.
"""

from __future__ import annotations

import pytest

import barcode
from barcode.base import Barcode
from barcode.codabar import CODABAR
from barcode.codex import PZN
from barcode.codex import Code128
from barcode.codex import Code39
from barcode.codex import Gs1_128
from barcode.ean import EAN8
from barcode.ean import EAN8_GUARD
from barcode.ean import EAN13
from barcode.ean import EAN13_GUARD
from barcode.ean import EAN14
from barcode.ean import JAN
from barcode.errors import BarcodeNotFoundError
from barcode.isxn import ISBN10
from barcode.isxn import ISBN13
from barcode.isxn import ISSN
from barcode.itf import ITF
from barcode.upc import UPCA

EXPECTED_CLASSES = {
    "codabar": CODABAR,
    "code128": Code128,
    "code39": Code39,
    "ean": EAN13,
    "ean13": EAN13,
    "ean13-guard": EAN13_GUARD,
    "ean14": EAN14,
    "ean8": EAN8,
    "ean8-guard": EAN8_GUARD,
    "gs1": ISBN13,
    "gs1_128": Gs1_128,
    "gtin": EAN14,
    "isbn": ISBN13,
    "isbn10": ISBN10,
    "isbn13": ISBN13,
    "issn": ISSN,
    "itf": ITF,
    "jan": JAN,
    "nw-7": CODABAR,
    "pzn": PZN,
    "upc": UPCA,
    "upca": UPCA,
}


def test_provided_barcodes_is_the_sorted_name_list() -> None:
    assert barcode.PROVIDED_BARCODES == sorted(EXPECTED_CLASSES)
    assert len(barcode.PROVIDED_BARCODES) == 22


@pytest.mark.parametrize("name", sorted(EXPECTED_CLASSES))
def test_every_provided_name_resolves_to_its_class(name: str) -> None:
    cls = barcode.get_barcode_class(name)
    assert cls is EXPECTED_CLASSES[name]
    assert isinstance(cls, type)
    assert issubclass(cls, Barcode)


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("ean", "ean13"),
        ("gtin", "ean14"),
        ("isbn", "isbn13"),
        ("gs1", "isbn13"),
        ("nw-7", "codabar"),
        ("upc", "upca"),
    ],
)
def test_aliases_resolve_to_the_same_class(alias: str, canonical: str) -> None:
    assert barcode.get_barcode_class(alias) is barcode.get_barcode_class(canonical)


@pytest.mark.parametrize("name", ["EAN13", "Ean8", "UPCA", "CODE128", "Gs1_128"])
def test_lookup_is_case_insensitive(name: str) -> None:
    assert barcode.get_barcode_class(name) is EXPECTED_CLASSES[name.lower()]


@pytest.mark.parametrize("name", ["unknown", "", "ean13 ", "code-39", "upce"])
def test_unknown_name_raises_barcode_not_found(name: str) -> None:
    with pytest.raises(BarcodeNotFoundError, match="is not known"):
        barcode.get_barcode_class(name)


def test_unknown_name_error_message_names_the_barcode() -> None:
    with pytest.raises(BarcodeNotFoundError) as excinfo:
        barcode.get_barcode("nope")
    assert str(excinfo.value) == "The barcode 'nope' is not known."
    assert excinfo.value.msg == "The barcode 'nope' is not known."


def test_unknown_name_raises_even_when_a_code_is_given() -> None:
    with pytest.raises(BarcodeNotFoundError):
        barcode.get_barcode("unknown", "123")


def test_get_without_code_returns_the_class() -> None:
    assert barcode.get_barcode("ean13") is EAN13
    assert barcode.get_barcode("ean13", None) is EAN13


def test_get_with_code_returns_an_instance() -> None:
    result = barcode.get_barcode("ean13", "842167143322")
    assert isinstance(result, EAN13)
    assert isinstance(result, Barcode)


def test_get_passes_options_through_to_the_constructor() -> None:
    ean8 = barcode.get_barcode("ean8", "6032299", options={"guardbar": True})
    assert isinstance(ean8, EAN8)
    assert ean8.get_fullcode() == "< 6032 2999 >"


def test_get_class_is_an_alias_of_get_barcode_class() -> None:
    assert barcode.get_class is barcode.get_barcode_class
    assert barcode.get_class("upc") is UPCA


def test_get_barcode_is_the_get_function() -> None:
    assert barcode.get_barcode is barcode.get

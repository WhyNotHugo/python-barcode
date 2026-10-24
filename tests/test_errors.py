"""Tests for ``barcode.errors`` and the ``Barcode`` base class."""

from __future__ import annotations

import pytest

from barcode.base import Barcode
from barcode.ean import EAN13
from barcode.errors import BarcodeError
from barcode.errors import BarcodeNotFoundError
from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError
from barcode.errors import WrongCountryCodeError
from barcode.writer import SVGWriter


def test_barcode_error_stores_and_renders_its_message() -> None:
    err = BarcodeError("boom")
    assert err.msg == "boom"
    assert str(err) == "boom"


@pytest.mark.parametrize(
    "error_class",
    [
        IllegalCharacterError,
        BarcodeNotFoundError,
        NumberOfDigitsError,
        WrongCountryCodeError,
    ],
)
def test_specific_errors_are_barcode_errors(error_class: type[BarcodeError]) -> None:
    assert issubclass(error_class, BarcodeError)
    assert issubclass(error_class, Exception)
    assert str(error_class("details")) == "details"


def test_base_barcode_cannot_be_instantiated() -> None:
    with pytest.raises(NotImplementedError):
        Barcode("123")


def test_default_writer_is_the_svg_writer_class() -> None:
    assert Barcode.default_writer is SVGWriter


def test_instances_get_an_svg_writer_by_default() -> None:
    assert isinstance(EAN13("842167143322").writer, SVGWriter)

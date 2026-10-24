"""Tests for Codabar / NW-7 (``barcode.codabar``).

Codabar previously had no dedicated tests. Validation happens lazily
in ``build()`` rather than in the constructor, which these tests pin.
"""

from __future__ import annotations

import pytest

from barcode.codabar import CODABAR
from barcode.errors import BarcodeError
from barcode.errors import IllegalCharacterError


def test_codabar_str_and_fullcode_return_the_code() -> None:
    code = CODABAR("A123B")
    assert str(code) == "A123B"
    assert code.get_fullcode() == "A123B"


def test_codabar_build_pattern_with_default_widths() -> None:
    code = CODABAR("A123B").build()
    assert code == [
        "1100111110000011000001100110011001111100000110011001100000"
        "11001111100111110000011001100110011000001100000110011111"
    ]
    assert len(code[0]) == 114


def test_codabar_build_pattern_with_custom_widths() -> None:
    assert CODABAR("A123B", narrow=1, wide=3).build() == [
        "101110001000101010111000101010001011101110001010101000100010111"
    ]


def test_codabar_all_special_characters_build() -> None:
    # Digits plus the six specials $ : / . + - are all legal in the body.
    assert len(CODABAR("A$:/.+-B").build()[0]) == 192


def test_codabar_constructor_does_not_validate() -> None:
    # Construction stores the code verbatim; only build() complains.
    code = CODABAR("X123A")
    assert code.code == "X123A"


def test_codabar_bad_start_character_raises_on_build() -> None:
    with pytest.raises(BarcodeError, match="Codabar should start with either A,B,C or D"):
        CODABAR("X123A").build()


def test_codabar_lowercase_start_character_raises_on_build() -> None:
    with pytest.raises(BarcodeError, match="Codabar should start with either"):
        CODABAR("a123b").build()


def test_codabar_bad_end_character_raises_on_build() -> None:
    with pytest.raises(BarcodeError, match="Codabar should end with either A,B,C or D"):
        CODABAR("A123X").build()


def test_codabar_illegal_body_character_raises_on_build() -> None:
    with pytest.raises(
        IllegalCharacterError, match="Codabar can only contain numerics"
    ):
        CODABAR("A1@3B").build()


def test_codabar_empty_code_raises_index_error_on_build() -> None:
    # There is no explicit emptiness check; indexing the first
    # character of an empty code raises IndexError. Pins the current
    # behaviour.
    with pytest.raises(IndexError):
        CODABAR("").build()

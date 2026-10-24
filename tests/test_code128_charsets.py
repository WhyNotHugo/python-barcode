"""Tests for the Code 128 charset tables and encoder sequences.

``test_code128.py`` covers build stability and ``test_gs1_128.py``
covers GS1 sequences; these tests pin the charset dictionaries
themselves and plain Code 128 symbol sequences (start-code folding,
charset C digit pairing, odd trailing digits, control characters).
"""

from __future__ import annotations

import pytest

from barcode.charsets import code128
from barcode.codex import Code128
from barcode.errors import IllegalCharacterError


@pytest.mark.parametrize(
    ("char", "value"),
    [
        (" ", 0),
        ("0", 16),
        ("A", 33),
        ("\x00", 64),
        ("SHIFT", 98),
        ("TO_C", 99),
        ("TO_B", 100),
    ],
)
def test_code128_charset_a_values(char: str, value: int) -> None:
    assert code128.A[char] == value


@pytest.mark.parametrize(
    ("char", "value"),
    [
        ("0", 16),
        ("`", 64),
        ("a", 65),
        ("TO_C", 99),
        ("TO_A", 101),
    ],
)
def test_code128_charset_b_values(char: str, value: int) -> None:
    assert code128.B[char] == value


def test_code128_charset_sizes() -> None:
    assert len(code128.A) == 103
    assert len(code128.B) == 103


def test_code128_charset_c_switch_codes() -> None:
    assert code128.C == {"TO_B": 100, "TO_A": 101, "\xf1": 102}


def test_code128_start_and_switch_tables() -> None:
    assert code128.START_CODES == {"A": 103, "B": 104, "C": 105}
    assert code128.TO == {101: 103, 100: 104, 99: 105}


def test_code128_fnc1_character() -> None:
    # The FNC1 character U+00F1 is "ñ"; it is part of the legal input
    # set and maps to value 102 in charset C (and, coincidentally,
    # also in charset B).
    assert "\xf1" in code128.ALL
    assert code128.B["\xf1"] == 102


@pytest.mark.parametrize(
    ("given", "encoded"),
    [
        ("1234", [105, 12, 34]),  # pure charset C digit pairs
        ("12", [105, 12]),
        ("1", [104, 17]),  # single digit: folded to START_B
        ("12345", [105, 12, 34, 100, 21]),  # trailing digit via charset B
        ("AB", [104, 33, 34]),  # folded to START_B
        ("ab", [104, 65, 66]),  # lowercase requires charset B
        ("A\x01B", [104, 33, 101, 65, 34]),  # control char switches to A
    ],
)
def test_code128_encoded_sequences(given: str, encoded: list[int]) -> None:
    assert Code128(given).encoded == encoded


def test_code128_build_length_and_pattern() -> None:
    code = Code128("1234").build()
    assert len(code[0]) == 57
    assert Code128("12A").build() == [
        "11010011100101100111001011110111010100011000100100011001100011101011"
    ]


def test_code128_illegal_character_raises() -> None:
    with pytest.raises(
        IllegalCharacterError, match="not valid for Code 128: €"
    ):
        Code128("A€B")


def test_code128_empty_input_raises_index_error() -> None:
    # _try_to_optimize indexes the second symbol unconditionally, so
    # an empty code raises IndexError. Pins the current behaviour.
    with pytest.raises(IndexError):
        Code128("").encoded

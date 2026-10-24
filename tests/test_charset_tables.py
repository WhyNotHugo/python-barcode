"""Invariant tests for the encoding tables in ``barcode.charsets``.

The tables are data, but they encode the symbology specifications:
EAN's A/B/C pattern relationships, ITF's two-of-five property, the
Code 39 reference map, and so on. Pinning the invariants catches
accidental edits to the tables that no behavioural test would notice.
"""

from __future__ import annotations

from barcode.charsets import codabar
from barcode.charsets import code39
from barcode.charsets import code128
from barcode.charsets import ean
from barcode.charsets import itf
from barcode.charsets import upc


def test_ean_left_pattern_table() -> None:
    assert len(ean.LEFT_PATTERN) == 10
    for pattern in ean.LEFT_PATTERN:
        assert len(pattern) == 6
        assert set(pattern) <= {"A", "B"}


def test_ean_code_tables_shape() -> None:
    assert set(ean.CODES) == {"A", "B", "C"}
    for table in ean.CODES.values():
        assert len(table) == 10
        for pattern in table:
            assert len(pattern) == 7
            assert set(pattern) <= {"0", "1"}


def test_ean_c_patterns_are_the_complement_of_a() -> None:
    for i in range(10):
        complement = "".join("1" if b == "0" else "0" for b in ean.CODES["A"][i])
        assert ean.CODES["C"][i] == complement


def test_ean_b_patterns_are_the_reversed_c_patterns() -> None:
    for i in range(10):
        assert ean.CODES["B"][i] == ean.CODES["C"][i][::-1]


def test_upc_tables_reuse_the_ean_tables() -> None:
    assert upc.CODES["L"] == ean.CODES["A"]
    assert upc.CODES["R"] == ean.CODES["C"]
    assert upc.EDGE == ean.EDGE == "101"
    assert upc.MIDDLE == ean.MIDDLE == "01010"


def test_itf_table_has_the_two_of_five_property() -> None:
    assert itf.START == "NnNn"
    assert itf.STOP == "WnN"
    assert len(itf.CODES) == 10
    for pattern in itf.CODES:
        assert len(pattern) == 5
        assert set(pattern) <= {"N", "W"}
        # Interleaved 2 of 5: exactly two of the five elements are wide.
        assert pattern.count("W") == 2


def test_code39_tables_shape() -> None:
    assert len(code39.REF) == 43
    assert len(code39.CODES) == 43
    assert len(code39.MAP) == 43
    for pattern in code39.CODES:
        assert len(pattern) == 15
        assert set(pattern) <= {"0", "1"}
    assert code39.EDGE == "100010111011101"
    assert code39.MIDDLE == "0"


def test_code39_map_assigns_sequential_values() -> None:
    for index, char in enumerate(code39.REF):
        value, pattern = code39.MAP[char]
        assert value == index
        assert pattern == code39.CODES[index]


def test_code39_map_spot_values() -> None:
    assert code39.MAP["0"] == (0, "101000111011101")
    assert code39.MAP["A"] == (10, "111010100010111")
    assert code39.MAP["%"] == (42, "101000100010001")


def test_code128_pattern_table_shape() -> None:
    assert len(code128.CODES) == 106
    assert len(set(code128.CODES)) == 106
    for pattern in code128.CODES:
        assert len(pattern) == 11
        assert set(pattern) <= {"0", "1"}
    assert code128.STOP == "11000111010"


def test_codabar_tables_shape() -> None:
    assert len(codabar.CODES) == 16
    for pattern in codabar.CODES.values():
        assert len(pattern) == 7
        assert set(pattern) <= {"N", "n", "W", "w"}
    assert codabar.STARTSTOP == {
        "A": "NnWwNwN",
        "B": "NwNwNnW",
        "C": "NnNwNwW",
        "D": "NnNwWwN",
    }

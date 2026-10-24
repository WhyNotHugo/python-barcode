"""Tests for ITF (Interleaved 2 of 5, ``barcode.itf``).

Covers the odd-length zero padding, the interleaved bar/space
pattern produced by ``build()``, the narrow/wide scaling, and input
validation. Previously ITF only appeared in ``test_manually.py``.
"""

from __future__ import annotations

import pytest

from barcode.errors import IllegalCharacterError
from barcode.itf import ITF


def test_itf_even_length_is_kept_as_is() -> None:
    assert ITF("42").code == "42"
    assert str(ITF("42")) == "42"
    assert ITF("42").get_fullcode() == "42"


def test_itf_odd_length_is_padded_with_a_leading_zero() -> None:
    # Interleaved 2 of 5 encodes digit pairs, so odd input is padded.
    assert ITF("123").code == "0123"
    assert ITF("123").get_fullcode() == "0123"


def test_itf_build_pattern_for_a_digit_pair() -> None:
    assert ITF("12").build() == ["1100110011111001100000110011001111100000111110011"]
    assert ITF("00").build() == ["1100110011001100111110000011111000001100111110011"]


def test_itf_build_length_scales_with_pairs() -> None:
    assert len(ITF("12").build()[0]) == 49
    assert len(ITF("12345678").build()[0]) == 145


def test_itf_narrow_and_wide_widths_scale_the_pattern() -> None:
    itf = ITF("12", narrow=1, wide=2)
    assert itf.build() == ["1010110100101011001101"]
    default = ITF("12")
    assert (default.narrow, default.wide) == (2, 5)


@pytest.mark.parametrize("given", ["12a", "", "12 34", "12-34"])
def test_itf_non_digits_raise_illegal_character(given: str) -> None:
    with pytest.raises(
        IllegalCharacterError, match="ITF code can only contain numbers"
    ):
        ITF(given)

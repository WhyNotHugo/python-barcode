from __future__ import annotations

from barcode import get_barcode
from barcode.codex import Code128


def test_ean8_builds() -> None:
    ref = "1010100011000110100100110101111010101000100100010011100101001000101"
    ean = get_barcode("ean8", "40267708")
    bc = ean.build()
    assert ref == bc[0]


def test_ean8_builds_with_longer_bars() -> None:
    ref = "G0G01000110001101001001101011110G0G01000100100010011100101001000G0G"
    ean = get_barcode("ean8", "40267708", options={"guardbar": True})
    bc = ean.build()
    assert ref == bc[0]


# START_C symbol as produced by ``_build`` before any charset switch.
_START_C = 105


def _decode_code128_c(encoded: list[int]) -> str:
    """Decode a pure charset-C Code128 symbol list back to its digit string."""
    assert encoded[0] == _START_C
    return "".join(f"{n:02d}" for n in encoded[1:])


def test_code128_leading_99_not_stripped() -> None:
    # Regression test for #251: in charset C the pair "99" encodes to the code
    # number 99, which collided with the TO_C switch marker. ``_try_to_optimize``
    # therefore folded it away, silently dropping the leading "99" from the
    # barcode (e.g. "9912345678" was encoded as "12345678").
    bc = Code128("9912345678")
    assert bc.encoded == [_START_C, 99, 12, 34, 56, 78]
    assert _decode_code128_c(bc.encoded) == "9912345678"


def test_code128_other_leading_pairs_unaffected() -> None:
    # Pairs whose code number does not collide with a switch code always worked
    # and must keep working.
    for code, first_pair in (("0012345678", 0), ("1212345678", 12)):
        bc = Code128(code)
        assert bc.encoded[:2] == [_START_C, first_pair]
        assert _decode_code128_c(bc.encoded) == code


def test_code128_start_charset_folding_preserved() -> None:
    # The START-code folding optimisation (START_C + an immediate charset switch
    # collapsed into a single START code) must still apply for genuine switches.
    assert Code128("Wikipedia").encoded[0] == 104  # START_B

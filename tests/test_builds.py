from __future__ import annotations

from barcode import get_barcode
from barcode.charsets.code128 import START_CODES, CODES


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


def test_code128_builds() -> None:
    gen_000000 = get_barcode("code128", "000000")
    code_000000 = gen_000000.build()
    gen_999999 = get_barcode("code128", "999999")
    gen_999999._charset = "B" ## this will be swapped to C.
    code_999999 = gen_999999.build()
    assert gen_999999._charset == "C"
    assert len(code_000000[0]) == len(code_999999[0])
    assert code_000000[0].startswith(CODES[START_CODES["C"]])

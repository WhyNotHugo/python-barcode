from barcode import get_barcode


def test_ean8_builds():
    ref = "1010100011000110100100110101111010101000100100010011100101001000101"
    ean = get_barcode("ean8", "40267708")
    bc = ean.build()
    assert ref == bc[0]

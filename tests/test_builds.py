from barcode import get_barcode


def test_ean8_builds():
    ref = "1010100011000110100100110101111010101000100100010011100101001000101"
    ean = get_barcode("ean8", "40267708")
    bc = ean.build()
    assert ref == bc[0]


def test_ean8_builds_with_longer_bars():
    ref = "G0G01000110001101001001101011110G0G01000100100010011100101001000G0G"
    ean = get_barcode("ean8", "40267708", options={"guardbar": True})
    bc = ean.build()
    assert ref == bc[0]

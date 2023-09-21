from __future__ import annotations

from barcode.ean import EAN13


def test_ean_checksum() -> None:
    ean = EAN13("842169142322")  # input has 12 digits
    assert ean.calculate_checksum() == 0

    ean = EAN13("8421691423220")  # input has 13 digits
    assert ean.calculate_checksum() == 0

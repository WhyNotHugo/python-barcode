from __future__ import annotations

from barcode.ean import EAN13


def test_ean_checksum_generated() -> None:
    ean = EAN13("842167143322")  # input has 12 digits
    assert ean.calculate_checksum() == 5
    assert ean.ean == "8421671433225"


def test_ean_checksum_zeroed() -> None:
    ean = EAN13("842167143322", no_checksum=True)  # input has 12 digits
    assert ean.calculate_checksum() == 5
    assert ean.ean == "8421671433220"


def test_ean_checksum_supplied_and_generated() -> None:
    ean = EAN13("8421671433225")  # input has 13 digits
    assert ean.calculate_checksum() == 5
    assert ean.ean == "8421671433225"

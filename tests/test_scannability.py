"""Tests to verify that generated barcodes are scannable by barcode readers.

These tests generate barcodes, render them as images, and then decode them
using pyzbar to verify that the encoded data matches the expected value.

Requirements:
    - pyzbar: Python wrapper for zbar barcode reader
    - cairosvg: For converting SVG to PNG (for SVG writer tests)
    - Pillow: For image handling

System requirements:
    - libzbar0: zbar library (apt install libzbar0)
    - libcairo2: Cairo library (apt install libcairo2-dev)
"""

# mypy: ignore-errors

from __future__ import annotations

import io
from typing import TYPE_CHECKING
from typing import Any

import pytest

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

# Check for optional dependencies
try:
    from PIL import Image

    HAS_PIL = True
except ImportError:
    Image = None  # type: ignore[assignment]
    HAS_PIL = False

try:
    import pyzbar.pyzbar as _pyzbar  # type: ignore[import-untyped]

    pyzbar: Any = _pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

try:
    import cairosvg as _cairosvg  # type: ignore[import-untyped]

    cairosvg: Any = _cairosvg
    HAS_CAIROSVG = True
except ImportError:
    HAS_CAIROSVG = False


import barcode
from barcode.writer import ImageWriter
from barcode.writer import SVGWriter

# Skip all tests if required dependencies are not available
pytestmark = [
    pytest.mark.skipif(not HAS_PIL, reason="Pillow not installed"),
    pytest.mark.skipif(not HAS_PYZBAR, reason="pyzbar not installed"),
]


def decode_barcode(image: PILImage) -> list[str]:
    """Decode barcodes from an image and return list of decoded values."""
    if not HAS_PYZBAR:
        raise RuntimeError("pyzbar not installed")
    decoded = pyzbar.decode(image)
    return [d.data.decode("utf-8") for d in decoded]


def svg_to_image(svg_data: bytes, scale: float = 3.0) -> PILImage:
    """Convert SVG data to PIL Image."""
    if not HAS_CAIROSVG:
        raise RuntimeError("cairosvg not installed")
    if not HAS_PIL or Image is None:
        raise RuntimeError("Pillow not installed")
    assert Image is not None
    png_data = cairosvg.svg2png(bytestring=svg_data, scale=scale)
    return Image.open(io.BytesIO(png_data))


def generate_svg_barcode(
    barcode_type: str,
    code: str,
    **kwargs,
) -> bytes:
    """Generate an SVG barcode and return the SVG data as bytes."""
    bc = barcode.get(barcode_type, code, writer=SVGWriter(), options=kwargs)
    buffer = io.BytesIO()
    bc.write(buffer)
    return buffer.getvalue()


def generate_image_barcode(
    barcode_type: str,
    code: str,
    **kwargs,
) -> PILImage:
    """Generate a barcode image and return as PIL Image."""
    if not HAS_PIL or Image is None:
        raise RuntimeError("Pillow not installed")

    bc = barcode.get(barcode_type, code, writer=ImageWriter(), options=kwargs)
    buffer = io.BytesIO()
    bc.write(buffer)
    buffer.seek(0)
    return Image.open(buffer)


@pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg not installed")
class TestSVGScannability:
    """Tests verifying that SVG barcodes are scannable."""

    @pytest.mark.parametrize(
        ("barcode_type", "code", "expected"),
        [
            ("ean13", "5901234123457", "5901234123457"),
            ("ean8", "9638507", "96385074"),  # checksum added
            # UPC-A is decoded as EAN-13 with leading 0 by most scanners
            ("upca", "04210000526", "0042100005264"),
        ],
    )
    def test_svg_barcode_is_scannable(
        self,
        barcode_type: str,
        code: str,
        expected: str,
    ) -> None:
        """Verify that SVG barcodes can be decoded to their original value."""
        svg_data = generate_svg_barcode(barcode_type, code)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in {barcode_type} SVG"
        assert expected in decoded, (
            f"Expected {expected} in decoded values, got {decoded}"
        )

    @pytest.mark.parametrize(
        ("barcode_type", "code", "expected"),
        [
            ("ean13", "5901234123457", "5901234123457"),
            ("ean8", "9638507", "96385074"),
        ],
    )
    def test_svg_barcode_with_guardbar_is_scannable(
        self,
        barcode_type: str,
        code: str,
        expected: str,
    ) -> None:
        """Verify that SVG barcodes with guardbars can be decoded."""
        svg_data = generate_svg_barcode(barcode_type, code, guardbar=True)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, (
            f"No barcode detected in {barcode_type} SVG with guardbar"
        )
        assert expected in decoded, (
            f"Expected {expected} in decoded values, got {decoded}"
        )

    @pytest.mark.parametrize("addon", ["12", "52495"])
    def test_svg_ean13_with_addon_main_code_is_scannable(self, addon: str) -> None:
        """Verify that EAN-13 with addon has scannable main code.

        Note: Most barcode readers decode the main barcode and addon separately,
        or may not support addon decoding at all. We verify the main code is readable.
        """
        code = "5901234123457"
        svg_data = generate_svg_barcode("ean13", code, addon=addon)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, "No barcode detected in EAN-13 with addon"
        assert code in decoded, (
            f"Expected main code {code} in decoded values, got {decoded}"
        )

    @pytest.mark.parametrize("addon", ["12", "52495"])
    def test_svg_upca_with_addon_main_code_is_scannable(self, addon: str) -> None:
        """Verify that UPC-A with addon has scannable main code."""
        code = "04210000526"
        expected = "042100005264"  # with checksum
        svg_data = generate_svg_barcode("upca", code, addon=addon)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, "No barcode detected in UPC-A with addon"
        # UPC-A may be decoded as EAN-13 with leading 0
        decoded_matches = [d for d in decoded if expected in d or d in expected]
        assert decoded_matches, f"Expected {expected} in decoded values, got {decoded}"


class TestImageScannability:
    """Tests verifying that PNG/image barcodes are scannable."""

    @pytest.mark.parametrize(
        ("barcode_type", "code", "expected"),
        [
            ("ean13", "5901234123457", "5901234123457"),
            ("ean8", "9638507", "96385074"),
            ("upca", "04210000526", "042100005264"),
        ],
    )
    def test_image_barcode_is_scannable(
        self,
        barcode_type: str,
        code: str,
        expected: str,
    ) -> None:
        """Verify that image barcodes can be decoded to their original value."""
        image = generate_image_barcode(barcode_type, code)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in {barcode_type} image"
        # UPC-A may be decoded as EAN-13 with leading 0
        decoded_matches = [d for d in decoded if expected in d or d in expected]
        assert decoded_matches, f"Expected {expected} in decoded values, got {decoded}"

    @pytest.mark.parametrize(
        ("barcode_type", "code", "expected"),
        [
            ("ean13", "5901234123457", "5901234123457"),
            ("ean8", "9638507", "96385074"),
        ],
    )
    def test_image_barcode_with_guardbar_is_scannable(
        self,
        barcode_type: str,
        code: str,
        expected: str,
    ) -> None:
        """Verify that image barcodes with guardbars can be decoded."""
        image = generate_image_barcode(barcode_type, code, guardbar=True)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, (
            f"No barcode detected in {barcode_type} image with guardbar"
        )
        assert expected in decoded, (
            f"Expected {expected} in decoded values, got {decoded}"
        )

    @pytest.mark.parametrize("addon", ["12", "52495"])
    def test_image_ean13_with_addon_main_code_is_scannable(self, addon: str) -> None:
        """Verify that EAN-13 with addon has scannable main code."""
        code = "5901234123457"
        image = generate_image_barcode("ean13", code, addon=addon)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, "No barcode detected in EAN-13 with addon"
        assert code in decoded, (
            f"Expected main code {code} in decoded values, got {decoded}"
        )


class TestISXNScannability:
    """Tests verifying that ISBN/ISSN barcodes are scannable."""

    @pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg not installed")
    @pytest.mark.parametrize(
        ("barcode_type", "code", "expected_prefix"),
        [
            ("isbn13", "978-3-16-148410-0", "978316148410"),
            ("isbn10", "3-12-517154-7", "978312517154"),  # converted to ISBN-13
            ("issn", "0317-8471", "9770317847"),  # ISSN as EAN-13
        ],
    )
    def test_svg_isxn_is_scannable(
        self,
        barcode_type: str,
        code: str,
        expected_prefix: str,
    ) -> None:
        """Verify that ISBN/ISSN SVG barcodes are scannable."""
        svg_data = generate_svg_barcode(barcode_type, code)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in {barcode_type} SVG"
        # Check that decoded value starts with expected prefix
        matches = [d for d in decoded if d.startswith(expected_prefix)]
        assert matches, (
            f"Expected decoded value starting with {expected_prefix}, got {decoded}"
        )

    @pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg not installed")
    @pytest.mark.parametrize("addon", ["52495"])
    def test_svg_isbn_with_addon_is_scannable(self, addon: str) -> None:
        """Verify that ISBN-13 with price addon has scannable main code."""
        code = "978-3-16-148410-0"
        svg_data = generate_svg_barcode("isbn13", code, addon=addon)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, "No barcode detected in ISBN-13 with addon"
        matches = [d for d in decoded if d.startswith("978316148410")]
        assert matches, f"Expected ISBN-13 in decoded values, got {decoded}"


class TestCode128Scannability:
    """Tests verifying that Code128 barcodes are scannable."""

    @pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg not installed")
    @pytest.mark.parametrize(
        "code",
        [
            "Example123",
            "ABC-123-XYZ",
            "1234567890",
        ],
    )
    def test_svg_code128_is_scannable(self, code: str) -> None:
        """Verify that Code128 SVG barcodes are scannable."""
        svg_data = generate_svg_barcode("code128", code)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in Code128 SVG for '{code}'"
        assert code in decoded, f"Expected {code} in decoded values, got {decoded}"

    @pytest.mark.parametrize(
        "code",
        [
            "Example123",
            "TEST-456",
        ],
    )
    def test_image_code128_is_scannable(self, code: str) -> None:
        """Verify that Code128 image barcodes are scannable."""
        image = generate_image_barcode("code128", code)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in Code128 image for '{code}'"
        assert code in decoded, f"Expected {code} in decoded values, got {decoded}"


class TestCode39Scannability:
    """Tests verifying that Code39 barcodes are scannable."""

    @pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg not installed")
    @pytest.mark.parametrize(
        "code",
        [
            "HELLO",
            "ABC123",
            "TEST-42",
        ],
    )
    def test_svg_code39_is_scannable(self, code: str) -> None:
        """Verify that Code39 SVG barcodes are scannable.

        Note: Code39 may include a checksum character at the end.
        """
        svg_data = generate_svg_barcode("code39", code)
        image = svg_to_image(svg_data)
        decoded = decode_barcode(image)

        assert len(decoded) >= 1, f"No barcode detected in Code39 SVG for '{code}'"
        # Code39 may have checksum character appended
        decoded_matches = [d for d in decoded if d.startswith(code)]
        assert decoded_matches, f"Expected value starting with {code}, got {decoded}"

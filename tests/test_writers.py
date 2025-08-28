from __future__ import annotations

import os
from io import BytesIO
from typing import assert_type

from barcode import EAN13
from barcode.writer import Image
from barcode.writer import ImageWriter
from barcode.writer import SVGWriter

PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, "test_outputs")

if Image is not None:

    def test_saving_image_to_byteio() -> None:
        rv = BytesIO()
        EAN13(str(100000902922), writer=ImageWriter()).write(rv)

        with open(f"{TESTPATH}/somefile.jpeg", "wb") as f:
            EAN13("100000011111", writer=ImageWriter()).write(f)

    def test_saving_rgba_image() -> None:
        rv = BytesIO()
        EAN13(str(100000902922), writer=ImageWriter()).write(rv)

        with open(f"{TESTPATH}/ean13-with-transparent-bg.png", "wb") as f:
            writer = ImageWriter(mode="RGBA")

            EAN13("100000011111", writer=writer).write(
                f, options={"background": "rgba(255,0,0,0)"}
            )

    def test_none_writer_typed_as_bytes_or_image() -> None:
        writer: ImageWriter | None = None
        bc = EAN13("100000011111", writer=writer)
        assert_type(bc, EAN13[bytes] | EAN13[Image.Image])

else:

    def test_none_writer_typed_as_bytes() -> None:
        bc = EAN13("100000011111", writer=None)
        assert_type(bc, EAN13[bytes])


def test_saving_svg_to_byteio() -> None:
    rv = BytesIO()
    EAN13(str(100000902922), writer=SVGWriter()).write(rv)

    with open(f"{TESTPATH}/somefile.svg", "wb") as f:
        EAN13("100000011111", writer=SVGWriter()).write(f)


def test_saving_svg_to_byteio_with_guardbar() -> None:
    rv = BytesIO()
    EAN13(str(100000902922), writer=SVGWriter(), guardbar=True).write(rv)

    with open(f"{TESTPATH}/somefile_guardbar.svg", "wb") as f:
        EAN13("100000011111", writer=SVGWriter(), guardbar=True).write(f)


def test_none_writer_defaults_to_svg_writer() -> None:
    # A None writer, even when statically typed as an image writer,
    # still falls back to the default SVG writer at runtime.
    writer: ImageWriter | None = None
    bc = EAN13("100000011111", writer=writer)
    assert isinstance(bc.writer, SVGWriter)
    assert isinstance(bc.render(), bytes)

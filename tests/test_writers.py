from __future__ import annotations

import os
from io import BytesIO
from xml.dom.minidom import Element
from xml.dom.minidom import parseString

from barcode import EAN13
from barcode.writer import ImageWriter
from barcode.writer import SVGWriter
from barcode.writer import mm2px

PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, "test_outputs")

if ImageWriter is not None:
    from PIL import ImageOps

    def test_saving_image_to_byteio() -> None:
        assert ImageWriter is not None  # workaround for mypy

        rv = BytesIO()
        EAN13(str(100000902922), writer=ImageWriter()).write(rv)

        with open(f"{TESTPATH}/somefile.jpeg", "wb") as f:
            EAN13("100000011111", writer=ImageWriter()).write(f)

    def test_saving_rgba_image() -> None:
        assert ImageWriter is not None  # workaround for mypy

        rv = BytesIO()
        EAN13(str(100000902922), writer=ImageWriter()).write(rv)

        with open(f"{TESTPATH}/ean13-with-transparent-bg.png", "wb") as f:
            writer = ImageWriter(mode="RGBA")

            EAN13("100000011111", writer=writer).write(
                f, options={"background": "rgba(255,0,0,0)"}
            )

    def test_image_center_text_false_left_aligns_text() -> None:
        assert ImageWriter is not None  # workaround for mypy

        writer = ImageWriter()
        image = EAN13("100000902922", writer=writer).render(
            {"center_text": False, "quiet_zone": 6.5, "module_height": 15.0}
        )
        assert not isinstance(image, bytes)  # workaround for mypy

        below_bars = (0, int(mm2px(17, writer.dpi)), image.width, image.height)
        text_box = ImageOps.invert(image.convert("L")).crop(below_bars).getbbox()
        assert text_box is not None
        assert text_box[0] >= int(mm2px(6.5, writer.dpi))


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


def _svg_texts(barcode: EAN13, **options: object) -> list[Element]:
    rv = BytesIO()
    barcode.write(rv, options=options)
    return parseString(rv.getvalue()).getElementsByTagName("text")


def test_svg_text_is_centered_by_default() -> None:
    [text] = _svg_texts(EAN13("100000902922", writer=SVGWriter()))

    assert "text-anchor:middle;" in text.getAttribute("style")


def test_svg_center_text_false_left_aligns_text() -> None:
    [text] = _svg_texts(EAN13("100000902922", writer=SVGWriter()), center_text=False)

    assert "text-anchor:start;" in text.getAttribute("style")
    assert text.getAttribute("x") == "6.500mm"


def test_svg_center_text_false_keeps_guardbar_blocks_centered() -> None:
    texts = _svg_texts(
        EAN13("100000902922", writer=SVGWriter(), guardbar=True), center_text=False
    )

    assert len(texts) > 1
    assert all("text-anchor:middle;" in text.getAttribute("style") for text in texts)

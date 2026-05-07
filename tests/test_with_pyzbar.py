import pytest

pytest.importorskip("pyzbar")
pytest.importorskip("PIL")

import os
import barcode
from barcode.base import Barcode
from barcode.writer import ImageWriter, SVGWriter
from pyzbar.pyzbar import decode
from PIL import Image
from io import BytesIO


try:
    import cairosvg
    import cairocffi
    cairocffi.Context(cairocffi.ImageSurface(cairocffi.FORMAT_ARGB32, 1, 1))
    HAS_CAIROSVG = True
except (ImportError, OSError):
    HAS_CAIROSVG = False


def get_normalized_code(barcode_instance: Barcode, code: str) -> str:
    if isinstance(barcode_instance, barcode.UPCA) and len(code) > 12:
        return code[-12:] ## return last 12, because may be leftpadded with zero from pyzbar.
    return code


def perform_pyzbar_validation(barcode_instance: Barcode, img: Image, from_svg: bool = False) -> None:
    try:
        classname = type(barcode_instance).name
        decoded = decode(img)
        assert decoded, f"{classname} failed to decode"
    except AssertionError as e:
        filename = f"pyzbar_decode_fail_{classname}{"_from_svg" if from_svg else ""}.png"
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_outputs")
        os.makedirs(directory, exist_ok=True)
        img.save(os.path.join(directory, filename))
        raise

    normalized_code = get_normalized_code(barcode_instance, decoded[0].data.decode("ascii"))
    fullcode_classes = (
        barcode.Gs1_128,
        barcode.ISBN10,
        barcode.ISSN,
    )
    expected_code = str(barcode_instance if not isinstance(barcode_instance, fullcode_classes) else barcode_instance.get_fullcode())
    assert normalized_code == expected_code, f"{classname}: invalid"
    return True


def get_valid_barcode_tuples() -> tuple[tuple[Barcode, str]]:
    VALID_EAN8_CODE = "73513544"
    VALID_EAN13CODE = "1000009029223"
    VALID_BARCODES = (
        (barcode.EAN8, VALID_EAN8_CODE),
        (barcode.EAN8_GUARD, VALID_EAN8_CODE),
        (barcode.EAN13, VALID_EAN13CODE),
        (barcode.EAN13_GUARD, VALID_EAN13CODE),
        (barcode.UPCA, "036000291452"),
        (barcode.Code128, "A99BCDEF1234678"),
        (barcode.Code39, "QWERTY"),
        (barcode.JAN, "4901234567894"),
        (barcode.ISSN, "1234567"), ## uses get_fullcode to validate, since __str__ returns issn value
        (barcode.ISBN10, "306406152"), ## uses get_fullcode to validate, since __str__ returns isbn10 value
        (barcode.ISBN13, "9783064061521"),
        (barcode.Gs1_128, "YYYyyyy"), ## use get_fullcode to validate, since code prefixes with "\xf1" character on init
        (barcode.ITF, "10000090292221"),
        (barcode.PZN, "1234567"),
        #(barcode.CODABAR, ""), ## pyzbar does not support decoding this
        #(barcode.EAN14, "10000090292221"), ## pyzbar does not support decoding this, but I wonder if ITF is not essentially this, can't scan image with phone either. is useful for testing 
    )
    return VALID_BARCODES


def test_imagewriter() -> None:
    for barcode_class, valid_code in get_valid_barcode_tuples():
        ## maybe consider using barcode.get_barcode() and using strings instead of classes.
        barcode_instance = barcode_class(valid_code, writer=ImageWriter())
        img = barcode_instance.render()

        assert img, f"{type(barcode_instance).name} Failed to render"
        perform_pyzbar_validation(barcode_instance, img)


def test_ean14_png_decode_failure() -> None:
    '''We expect this to fail for now, but if that stops this test can probably be removed. and added to get_valid_barcode_tuples'''
    barcode_instance = barcode.get_barcode("EAN14", "10000090292221", writer=ImageWriter())
    img = barcode_instance.render()
    assert img, f"{type(barcode_instance).name} Failed to render"
    try:
        validation_success = perform_pyzbar_validation(barcode_instance, img)
    except AssertionError:
        validation_success = False
    assert validation_success == False, "We expected failure, but this succeeded."


@pytest.mark.skipif(not HAS_CAIROSVG, reason="cairosvg is not installed or can't load library")
def test_svgwriter() -> None:
    for barcode_class, valid_code in get_valid_barcode_tuples():
        barcode_instance = barcode_class(valid_code, writer=SVGWriter())
        svg_data = barcode_instance.render()
        buf = BytesIO()
        cairosvg.svg2png(bytestring=svg_data, write_to=buf, scale=2) ## scale it so antialiasing does not happen
        buf.seek(0)
        img = Image.open(buf)

        assert img, f"{barcode_class} Failed to render"
        perform_pyzbar_validation(barcode_instance, img, from_svg=True)


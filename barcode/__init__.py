"""This package provides a simple way to create standard barcodes.
It needs no external packages to be installed, the barcodes are
created as SVG objects. If Pillow is installed, the barcodes can also be
rendered as images (all formats supported by Pillow).
"""
import os
from typing import BinaryIO
from typing import Dict
from typing import Optional
from typing import Union

from barcode.codabar import CODABAR
from barcode.codex import PZN
from barcode.codex import Code39
from barcode.codex import Code128
from barcode.codex import Gs1_128
from barcode.ean import EAN8
from barcode.ean import EAN8_GUARD
from barcode.ean import EAN13
from barcode.ean import EAN13_GUARD
from barcode.ean import EAN14
from barcode.ean import JAN
from barcode.errors import BarcodeNotFoundError
from barcode.isxn import ISBN10
from barcode.isxn import ISBN13
from barcode.isxn import ISSN
from barcode.itf import ITF
from barcode.upc import UPCA
from barcode.version import version  # noqa: F401

__BARCODE_MAP = {
    "ean8": EAN8,
    "ean8-guard": EAN8_GUARD,
    "ean13": EAN13,
    "ean13-guard": EAN13_GUARD,
    "ean": EAN13,
    "gtin": EAN14,
    "ean14": EAN14,
    "jan": JAN,
    "upc": UPCA,
    "upca": UPCA,
    "isbn": ISBN13,
    "isbn13": ISBN13,
    "gs1": ISBN13,
    "isbn10": ISBN10,
    "issn": ISSN,
    "code39": Code39,
    "pzn": PZN,
    "code128": Code128,
    "itf": ITF,
    "gs1_128": Gs1_128,
    "codabar": CODABAR,
    "nw-7": CODABAR,
}

PROVIDED_BARCODES = list(__BARCODE_MAP)
PROVIDED_BARCODES.sort()


def get(
    name: str,
    code: Optional[str] = None,
    writer=None,
    options: Optional[dict] = None,
):
    """Helper method for getting a generator or even a generated code.

    :param name: The name of the type of barcode desired.
    :param code: The actual information to encode. If this parameter is
        provided, a generated barcode is returned. Otherwise, the barcode class
        is returned.
    :param Writer writer: An alternative writer to use when generating the
        barcode.
    :param options: Additional options to be passed on to the barcode when
        generating.
    """
    options = options or {}
    try:
        barcode = __BARCODE_MAP[name.lower()]
    except KeyError as e:
        raise BarcodeNotFoundError(f"The barcode {name!r} is not known.") from e
    if code is not None:
        return barcode(code, writer, **options)

    return barcode


def get_class(name):
    return get_barcode(name)


def generate(
    name: str,
    code: str,
    writer=None,
    output: Union[str, os.PathLike, BinaryIO, None] = None,
    writer_options: Union[Dict, None] = None,
    text: Union[str, None] = None,
):
    """Shortcut to generate a barcode in one line.

    :param name: Name of the type of barcode to use.
    :param code: Data to encode into the barcode.
    :param writer: A writer to use (e.g.: ImageWriter or SVGWriter).
    :param output: Destination file-like or path-like where to save the generated
     barcode.
    :param writer_options: Options to pass on to the writer instance.
    :param text: Text to render under the barcode.
    """
    from barcode.base import Barcode

    writer = writer or Barcode.default_writer()
    writer.set_options(writer_options or {})

    barcode = get(name, code, writer)

    if isinstance(output, str):
        return barcode.save(output, writer_options, text)
    if output:
        barcode.write(output, writer_options, text)
        return None

    raise TypeError("'output' cannot be None")


get_barcode = get
get_barcode_class = get_class

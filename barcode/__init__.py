# -*- coding: utf-8 -*-

"""

pyBarcode
=========

This package provides a simple way to create standard barcodes.
It needs no external packages to be installed, the barcodes are
created as SVG objects. If PIL (Python Imaging Library) is
installed, the barcodes can also be rendered as images (all
formats supported by PIL).
"""

from barcode.errors import BarcodeNotFoundError
from barcode.codex import Code39, PZN, Code128
from barcode.ean import EAN8, EAN13, EAN14, JAN
from barcode.isxn import ISBN10, ISBN13, ISSN
from barcode.upc import UPCA
from barcode.itf import ITF
from barcode.version import version  # noqa: F401

try:
    _strbase = basestring  # lint:ok
except NameError:
    _strbase = str


__BARCODE_MAP = dict(
    ean8=EAN8,
    ean13=EAN13,
    ean=EAN13,
    gtin=EAN14,
    ean14=EAN14,
    jan=JAN,
    upc=UPCA,
    upca=UPCA,
    isbn=ISBN13,
    isbn13=ISBN13,
    gs1=ISBN13,
    isbn10=ISBN10,
    issn=ISSN,
    code39=Code39,
    pzn=PZN,
    code128=Code128,
    itf=ITF,
)

PROVIDED_BARCODES = list(__BARCODE_MAP.keys())
PROVIDED_BARCODES.sort()


def get(name, code=None, writer=None):
    try:
        barcode = __BARCODE_MAP[name.lower()]
    except KeyError:
        raise BarcodeNotFoundError('The barcode {0!r} you requested is not '
                                   'known.'.format(name))
    if code is not None:
        return barcode(code, writer)
    else:
        return barcode


def get_class(name):
    return get_barcode(name)


def generate(name, code, writer=None, output=None, writer_options=None,
             text=None, pil=False):
    options = writer_options or {}
    barcode = get(name, code, writer)
    if pil:
        return barcode.render(writer_options, text)
    if isinstance(output, _strbase):
        fullname = barcode.save(output, options, text)
        return fullname
    else:
        barcode.write(output, options, text)


get_barcode = get
get_barcode_class = get_class

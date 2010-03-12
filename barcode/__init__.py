# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode

pyBarcode
=========

This package provides a simple way to create standard barcodes.
It needs no external packages to be installed, because the barcodes where
created as SVG images.
"""

__author__ = 'Thorsten Weimann <thorsten.weimann@gmx.net>'
__version__ = '0.4b1'
__license__ = 'MIT'


from barcode.errors import BarcodeNotFoundError
from barcode.codex import Code39, PZN
from barcode.ean import EAN8, EAN13, JAN
from barcode.isxn import ISBN10, ISBN13, ISSN
from barcode.upc import UPCA


__BARCODE_MAP = dict(
    ean8=EAN8,
    ean13=EAN13,
    ean=EAN13,
    gtin=EAN13,
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
)

PROVIDED_BARCODES = __BARCODE_MAP.keys()
PROVIDED_BARCODES.sort()


def get_barcode(name, code=None, writer=None):
    try:
        barcode = __BARCODE_MAP[name.lower()]
    except KeyError:
        raise BarcodeNotFoundError('The barcode {0!r} you requested is not '
                                   'known.'.format(name.lower()))
    if code is not None:
        return barcode(code, writer)
    else:
        return barcode


def get_barcode_class(name):
    return get_barcode(name)


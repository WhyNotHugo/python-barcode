# -*- coding: utf-8 -*-

"""barcode

pyBarcode
=========

This package provides a simple way to create standard barcodes.
It needs no external packages to be installed, because the barcodes where
created as SVG images.
"""
__docformat__ = 'restructuredtext en'

from errors import BarcodeNotFoundError
import codex
import ean
import isxn
import upc


BARCODE_MAP = {
    'ean8': ean.EAN8,
    'ean13': ean.EAN13,
    'ean': ean.EAN13,
    'jan': ean.JAN,
    'upc': upc.UPCA,
    'upca': upc.UPCA,
    'isbn': isxn.ISBN13,
    'isbn13': isxn.ISBN13,
    'isbn10': isxn.ISBN10,
    'issn': isxn.ISSN,
    'code39': codex.Code39,
}

def get_barcode(name, code=None, writer=None):
    try:
        barcode = BARCODE_MAP[name.lower()]
    except KeyError:
        raise BarcodeNotFoundError('The barcode "%s" you requested is not '
                                   'known.' % name.lower())
    if code is not None:
        return barcode(code, writer)
    else:
        return barcode

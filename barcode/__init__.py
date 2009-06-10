# -*- coding: utf-8 -*-

from errors import BarcodeNotFoundError
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

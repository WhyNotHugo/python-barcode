# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.upc

"""
__docformat__ = 'restructuredtext en'

from barcode.ean import EuropeanArticleNumber13


class UniversalProductCodeA(EuropeanArticleNumber13):
    """Initializes new UPC-A barcode. Can be rendered as EAN-13 by passing
    `True` to the `make_ean` argument.

    :parameters:
        upc : String
            The upc number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        make_ean : Boolean
            Render barcode as EAN-13 with leading 0 (default: False).
    """

    name = 'UPC-A'

    digits = 11

    def __init__(self, upc, writer=None, make_ean=False):
        if make_ean:
            UniversalProductCodeA.digits = 12
            upc = '0' + upc
        self.upc = upc
        EuropeanArticleNumber13.__init__(self, upc, writer)

    def __unicode__(self):
        return self.upc

    __str__ = __unicode__


UPCA = UniversalProductCodeA

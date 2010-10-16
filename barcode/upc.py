# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.upc

"""
__docformat__ = 'restructuredtext en'

from barcode.ean import EuropeanArticleNumber13


class UniversalProductCodeA(EuropeanArticleNumber13):

    name = 'UPC A'

    digits = 11

    def __init__(self, upc, writer=None):
        self.upc = upc
        EuropeanArticleNumber13.__init__(self, upc, writer)

    def __unicode__(self):
        return self.upc


UPCA = UniversalProductCodeA

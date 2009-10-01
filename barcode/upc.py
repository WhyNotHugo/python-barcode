# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.upc

"""
__docformat__ = 'restructuredtext en'

from ean import EuropeanArticleNumber13


class UniversalProductCodeA(EuropeanArticleNumber13):

    name = 'UPC A'

    def __init__(self, upc, writer=None):
        self.upc = upc
        upc = '0' + upc
        EuropeanArticleNumber13.__init__(self, upc, writer)

    def __unicode__(self):
        return self.upc


UPCA = UniversalProductCodeA

# -*- coding: utf-8 -*-

"""barcode.upc

"""
__docformat__ = 'restructuredtext en'

from ean import EuropeanArticleNumber13


class UniversalProductCodeA(EuropeanArticleNumber13):

    def __init__(self, upc, writer=None):
        self.upc = upc
        upc = u'0' + upc
        EuropeanArticleNumber13.__init__(self, upc, writer)

    def __unicode__(self):
        return self.upc


UPCA = UniversalProductCodeA

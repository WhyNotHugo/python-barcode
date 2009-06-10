# -*- coding: utf-8 -*-

"""barcode.isxn

"""
__docformat__ = 'restructuredtext en'

from ean import EuropeanArticleNumber13
from errors import *


class InternationalStandardBookNumber13(EuropeanArticleNumber13):

    def __init__(self, isbn, writer=None):
        self.isbn13 = isbn
        if isbn[:3] not in (u'978', '979'):
            raise WrongCountryCodeError('ISBN must start with 978 or 979.')
        EuropeanArticleNumber13.__init__(self, isbn, writer)


class InternationalStandardBookNumber10(InternationalStandardBookNumber13):

    def __init__(self, isbn, writer=None):
        isbn = isbn[:9]
        if len(isbn) != 9:
            raise NumberOfDigitsError('ISBN-10 has 9 or 10 digits, not '
                                      '%d.' % len(isbn))
        isbn += unicode(self._calculate_checksum())
        InternationalStandardBookNumber13.__init__(self, u'978'+isbn, writer)
        self.isbn10 = isbn

    def _calculate_checksum(self):
        tmp = sum([x*int(y) for x, y in enumerate(self.isbn10[:9],
                                                  start=1)]) % 11
        if tmp == 10:
            return u'X'
        else:
            return tmp

    def __unicode__(self):
        return self.isbn10


class InternationalStandardSerialNumber(EuropeanArticleNumber13):

    def __init__(self, issn, writer=None):
        issn = issn[:7]
        if len(issn) != 7:
            raise NumberOfDigitsError('ISSN has 7 digits, not %d.' % len(issn))
        issn += unicode(self._calculate_checksum())
        EuropeanArticleNumber13.__init__(self, self.make_ean(), writer)
        self.issn = issn

    def _calculate_checksum(self):
        tmp = 11 - sum([x*int(y) for x, y in enumerate(reversed(self.issn[:7]),
                                                       start=2)]) % 11
        if tmp == 10:
            return u'X'
        else:
            return tmp

    def make_ean(self):
        return u'977%s00%s' % (self.issn[:7], self._calculate_checksum())

    def __unicode__(self):
        return self.issn


# Shortcuts
ISBN13 = InternationalStandardBookNumber13
ISBN10 = InternationalStandardBookNumber10
ISSN = InternationalStandardSerialNumber

# -*- coding: utf-8 -*-

"""barcode.ean

"""
__docformat__ = 'restructuredtext en'

from base import Barcode
from errors import *


# EAN13 Specs (all sizes in mm)
SIZES = dict(SC0=0.27, SC1=0.297, SC2=0.33, SC3=0.363, SC4=0.396, SC5=0.445,
             SC6=0.495, SC7=0.544, SC8=0.61, SC9=0.66)
EDGE = u'101'
MIDDLE = u'01010'
CODES = {
    'A': (u'0001101', u'0011001', u'0010011', u'0111101', u'0100011',
          u'0110001', u'0101111', u'0111011', u'0110111', u'0001011'),
    'B': (u'0100111', u'0110011', u'0011011', u'0100001', u'0011101',
          u'0111001', u'0000101', u'0010001', u'0001001', u'0010111'),
    'C': (u'1110010', u'1100110', u'1101100', u'1000010', u'1011100',
          u'1001110', u'1010000', u'1000100', u'1001000', u'1110100'),
}
LEFT_PATTERN = (u'AAAAAA', u'AABABB', u'AABBAB', u'AABBBA', u'ABAABB',
                u'ABBAAB', u'ABBBAA', u'ABABAB', u'ABABBA', u'ABBABA')


class EuropeanArticleNumber13(Barcode):
    """Represents an EAN-13 barcode."""

    name = u'EAN-13'

    def __init__(self, ean, writer=None):
        """Initializes EAN13 object.

        :parameters:
            ean : Unicode
                The ean number as Unicodestring.
            writer : barcode.writer Instance
                The writer to render the barcode (default: SVGWriter).
        """
        ean = ean[:12]
        if not ean.isdigit():
            raise IllegalCharacterError('Code can only contain numbers.')
        if len(ean) != 12:
            raise NumberOfDigitsError('EAN-Code must have 12 digits, not '
                                      '%d.' % len(ean))
        self.ean = ean
        self.ean += unicode(self.calculate_checksum())
        self.writer = writer or Barcode.default_writer

    def __unicode__(self):
        return self.ean

    def get_fullcode(self):
        return self.ean

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """
        sum_ = lambda x, y: int(x) + int(y)
        evensum = reduce(sum_, self.ean[::2])
        oddsum = reduce(sum_, self.ean[1::2])
        return 10 - ((evensum + oddsum * 3) % 10)

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as Unicodestring
        :rtype: Unicode
        """
        code = EDGE
        pattern = LEFT_PATTERN[int(self.ean[0])]
        for i, number in enumerate(self.ean[:6]):
            code += CODES[pattern[i]][int(number)]
        code += MIDDLE
        for number in self.ean[6:]:
            code += CODES['C'][int(number)]
        code += EDGE
        return [code]

    def to_ascii(self):
        """Returns an ascii representation of the barcode.

        :rtype: Unicode
        """
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace(u'1', u'|').replace(u'0', u' ')
        return u'\n'.join(code)

    def render(self, write_text=True, **writer_options):
        options = dict(module_width=SIZES['SC2'])
        options.update(writer_options)
        return Barcode.render(self, write_text, **options)


class JapanArticleNumber(EuropeanArticleNumber13):
    """Represents an JAN barcode."""

    name = u'JAN'

    valid_country_codes = range(450, 460) + range(490, 500)

    def __init__(self, jan, writer=None):
        if int(jan[:3]) not in JapanArticleNumber.valid_country_codes:
            raise WrongCountryCodeError
        EuropeanArticleNumber13.__init__(self, jan, writer)


class EuropeanArticleNumber8(EuropeanArticleNumber13):
    """Represents an EAN-8 barcode."""

    name = u'EAN-8'

    def __init__(self, ean, writer=None):
        """See EuropeanArticleNumber13.__init__ for details."""
        ean = ean[:7]
        if not ean.isdigit():
            raise IllegalCharacterError('Code can only contain numbers.')
        if len(ean) != 7:
            raise NumberOfDigitsError('EAN-8 must have 7 digits, not '
                                      '%d.' % len(ean))
        self.ean = ean
        self.ean += unicode(self.calculate_checksum())
        self.writer = writer or Barcode.default_writer

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """
        sum_ = lambda x, y: int(x) + int(y)
        evensum = reduce(sum_, self.ean[::2])
        oddsum = reduce(sum_, self.ean[1::2])
        return 10 - ((evensum * 3 + oddsum) % 10)

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as Unicodestring
        :rtype: Unicode
        """
        code = EDGE
        for i, number in enumerate(self.ean[:4]):
            code += CODES['A'][int(number)]
        code += MIDDLE
        for number in self.ean[6:]:
            code += CODES['C'][int(number)]
        code += EDGE
        return [code]


# Shortcuts
EAN13 = EuropeanArticleNumber13
EAN8 = EuropeanArticleNumber8
JAN = JapanArticleNumber

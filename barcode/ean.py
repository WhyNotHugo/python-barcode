# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from barcode.base import Barcode
from barcode.charsets import ean as _ean
from barcode.errors import *

"""Module: barcode.ean

:Provided barcodes: EAN-14, EAN-13, EAN-8, JAN
"""
__docformat__ = 'restructuredtext en'

# Python 3
try:
    reduce
except NameError:
    from functools import reduce


# EAN13 Specs (all sizes in mm)
SIZES = dict(SC0=0.27, SC1=0.297, SC2=0.33, SC3=0.363, SC4=0.396, SC5=0.445,
             SC6=0.495, SC7=0.544, SC8=0.61, SC9=0.66)


class EuropeanArticleNumber13(Barcode):
    """Initializes EAN13 object.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = 'EAN-13'

    digits = 12

    def __init__(self, ean, writer=None, **kwargs):
        no_checksum = False
        if "no_checksum" in kwargs.keys():
            no_checksum = kwargs["no_checksum"]
        ean = ean[:self.digits]
        if not ean.isdigit():
            raise IllegalCharacterError('EAN code can only contain numbers.')
        if len(ean) != self.digits:
            raise NumberOfDigitsError('EAN must have {0} digits, not '
                                      '{1}.'.format(self.digits, len(ean)))
        self.ean = ean
        # If no checksum
        if no_checksum:
            # Add a thirteen char if given in parameter,
            # otherwise pad with zero
            self.ean = '{0}{1}'.format(
                ean, ean[self.digits] if len(ean) > self.digits else 0
            )
        else:
            self.ean = '{0}{1}'.format(ean, self.calculate_checksum())
        self.writer = writer or Barcode.default_writer()

    def __unicode__(self):
        return self.ean

    __str__ = __unicode__

    def get_fullcode(self):
        return self.ean

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """
        def sum_(x, y): return int(x) + int(y)
        evensum = reduce(sum_, self.ean[::2])
        oddsum = reduce(sum_, self.ean[1::2])
        return (10 - ((evensum + oddsum * 3) % 10)) % 10

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as string
        :rtype: String
        """
        code = _ean.EDGE[:]
        pattern = _ean.LEFT_PATTERN[int(self.ean[0])]
        for i, number in enumerate(self.ean[1:7]):
            code += _ean.CODES[pattern[i]][int(number)]
        code += _ean.MIDDLE
        for number in self.ean[7:]:
            code += _ean.CODES['C'][int(number)]
        code += _ean.EDGE
        return [code]

    def to_ascii(self):
        """Returns an ascii representation of the barcode.

        :rtype: String
        """
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace('1', '|').replace('0', ' ')
        return '\n'.join(code)

    def render(self, writer_options=None, text=None):
        options = dict(module_width=SIZES['SC2'])
        options.update(writer_options or {})
        return Barcode.render(self, options, text)


class JapanArticleNumber(EuropeanArticleNumber13):
    """Initializes JAN barcode.

    :parameters:
        jan : String
            The jan number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = 'JAN'

    valid_country_codes = list(range(450, 460)) + list(range(490, 500))

    def __init__(self, jan, writer=None):
        if int(jan[:3]) not in JapanArticleNumber.valid_country_codes:
            raise WrongCountryCodeError("Country code isn't between 450-460 "
                                        "or 490-500.")
        EuropeanArticleNumber13.__init__(self, jan, writer)


class EuropeanArticleNumber8(EuropeanArticleNumber13):
    """Represents an EAN-8 barcode. See EAN13's __init__ for details.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = 'EAN-8'

    digits = 7

    def __init__(self, ean, writer=None):
        EuropeanArticleNumber13.__init__(self, ean, writer)

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as string
        :rtype: String
        """
        code = _ean.EDGE[:]
        for number in self.ean[:4]:
            code += _ean.CODES['A'][int(number)]
        code += _ean.MIDDLE
        for number in self.ean[4:]:
            code += _ean.CODES['C'][int(number)]
        code += _ean.EDGE
        return [code]


class EuropeanArticleNumber14(EuropeanArticleNumber13):
    """Represents an EAN-14 barcode. See EAN13's __init__ for details.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = 'EAN-14'
    digits = 13

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """

        def sum_(x, y): return int(x) + int(y)

        evensum = reduce(sum_, self.ean[::2])
        oddsum = reduce(sum_, self.ean[1::2])
        return (10 - (((evensum * 3) + oddsum) % 10)) % 10


# Shortcuts
EAN14 = EuropeanArticleNumber14
EAN13 = EuropeanArticleNumber13
EAN8 = EuropeanArticleNumber8
JAN = JapanArticleNumber

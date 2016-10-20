# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from barcode.base import Barcode
from barcode.charsets import upc as _upc
from barcode.errors import *

try:
    reduce
except NameError:
    from functools import reduce

"""Module: barcode.upc

:Provided barcodes: UPC-A
"""
__docformat__ = 'restructuredtext en'


class UniversalProductCodeA(Barcode):
    """Initializes new UPC-A barcode.

    :parameters:
        upc : String
            The upc number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        make_ean: boolean
    """

    name = 'UPC-A'

    digits = 11

    def __init__(self, upc, writer=None, make_ean=False):
        self.ean = make_ean
        upc = upc[:self.digits]
        if not upc.isdigit():
            raise IllegalCharacterError('UPC code can only contain numbers.')
        if len(upc) != self.digits:
            raise NumberOfDigitsError('UPC must have {0} digits, not '
                                      '{1}.'.format(self.digits, len(upc)))
        self.upc = upc
        self.upc = '{}{}'.format(upc, self.calculate_checksum())
        self.writer = writer or Barcode.default_writer()

    def __unicode__(self):
        if self.ean:
            return '0' + self.upc
        else:
            return self.upc

    __str__ = __unicode__

    def get_fullcode(self):
        if self.ean:
            return '0' + self.upc
        else:
            return self.upc

    def calculate_checksum(self):
        """Calculates the checksum for UPCA/UPC codes

        :return: The checksum for 'self.upc'
        :rtype: Integer
        """
        def sum_(x, y): return int(x) + int(y)
        upc = self.upc[0:self.digits]
        oddsum = reduce(sum_, upc[::2])
        evensum = reduce(sum_, upc[1::2])
        check = (evensum + oddsum * 3) % 10
        if check == 0:
            return 0
        else:
            return 10 - check

    def build(self):
        """Builds the barcode pattern from 'self.upc'

        :return: The pattern as string
        :rtype: String
        """
        code = _upc.EDGE[:]

        for i, number in enumerate(self.upc[0:6]):
            code += _upc.CODES['L'][int(number)]

        code += _upc.MIDDLE

        for number in self.upc[6:]:
            code += _upc.CODES['R'][int(number)]

        code += _upc.EDGE

        return [code]

    def to_ascii(self):
        """Returns an ascii representation of the barcode.

        :rtype: String
        """

        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace('1', '|').replace('0', '_')
        return '\n'.join(code)

    def render(self, writer_options=None, text=None):
        options = dict(module_width=0.33)
        options.update(writer_options or {})
        return Barcode.render(self, options, text)

UPCA = UniversalProductCodeA

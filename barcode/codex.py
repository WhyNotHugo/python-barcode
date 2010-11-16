# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.codex

"""
__docformat__ = 'restructuredtext en'

import string

from barcode.base import Barcode
from barcode.errors import *


# Code stuff
MIN_SIZE = 0.2
MIN_QUIET_ZONE = 2.54
REF = (tuple(string.digits) + tuple(string.ascii_uppercase) +
       ('-', '.', ' ', '$', '/', '+', '%'))
B = '1'
E = '0'
CODES = (
    '101000111011101', '111010001010111', '101110001010111',
    '111011100010101', '101000111010111', '111010001110101',
    '101110001110101', '101000101110111', '111010001011101',
    '101110001011101', '111010100010111', '101110100010111',
    '111011101000101', '101011100010111', '111010111000101',
    '101110111000101', '101010001110111', '111010100011101',
    '101110100011101', '101011100011101', '111010101000111',
    '101110101000111', '111011101010001', '101011101000111',
    '111010111010001', '101110111010001', '101010111000111',
    '111010101110001', '101110101110001', '101011101110001',
    '111000101010111', '100011101010111', '111000111010101',
    '100010111010111', '111000101110101', '100011101110101',
    '100010101110111', '111000101011101', '100011101011101',
    '100010001000101', '100010001010001', '100010100010001',
    '101000100010001',
)

EDGE = '100010111011101'
MIDDLE = '0'

# MAP for assigning every symbol (REF) to (reference number, barcode)
MAP = dict(zip(REF, enumerate(CODES)))


class Code39(Barcode):
    """Initializes a new Code39 instance.

    :parameters:
        code : String
            Code39 string without \* and checksum (added automatically if
            `add_checksum` is True).
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        add_checksum : Boolean
            Add the checksum to code or not (default: True).
    """

    name = 'Code 39'

    def __init__(self, code, writer=None, add_checksum=True):
        code = code.upper()
        for char in code:
            if char not in REF:
                raise IllegalCharacterError('Character {0!r} not valid for '
                                            'Code 39.'.format(char))
        self.code = code
        if add_checksum:
            self.code += self.calculate_checksum()
        self.writer = writer or Barcode.default_writer()

    def __unicode__(self):
        return self.code

    def get_fullcode(self):
        return self.code

    def calculate_checksum(self):
        check = sum([MAP[x][0] for x in self.code]) % 43
        for k, v in MAP.iteritems():
            if check == v[0]:
                return k

    def build(self):
        chars = [EDGE]
        for char in self.code:
            chars.append(MAP[char][1])
        chars.append(EDGE)
        return [MIDDLE.join(chars)]

    def render(self, writer_options):
        options = dict(module_width=MIN_SIZE, quiet_zone=MIN_QUIET_ZONE)
        options.update(writer_options or {})
        return Barcode.render(self, options)


class PZN(Code39):
    """Initializes new German number for pharmaceutical products.

    :parameters:
        pzn : String
            Code to render.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = 'Pharmazentralnummer'

    digits = 6

    def __init__(self, pzn, writer=None):
        pzn = pzn[:self.digits]
        if not pzn.isdigit():
            raise IllegalCharacterError('PZN can only contain numbers.')
        if len(pzn) != self.digits:
            raise NumberOfDigitsError('PZN must have {0} digits, not '
                                      '{1}.'.format(self.digits, len(pzn)))
        self.pzn = pzn
        self.pzn = '{0}{1}'.format(pzn, self.calculate_checksum())
        Code39.__init__(self, 'PZN-{0}'.format(self.pzn), writer,
                        add_checksum=False)

    def get_fullcode(self):
        return 'PZN-{0}'.format(self.pzn)

    def calculate_checksum(self):
        sum_ = sum([int(x) * int(y) for x, y in enumerate(self.pzn, start=2)])
        checksum = sum_ % 11
        if checksum == 10:
            raise BarcodeError('Checksum can not be 10 for PZN.')
        else:
            return checksum

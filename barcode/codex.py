# -*- coding: utf-8 -*-

"""barcode.codex

"""
__docformat__ = 'restructuredtext en'

import string

from base import Barcode
from errors import *


# Code stuff
MIN_SIZE = 0.2
MIN_QUIET_ZONE = 2.54
REF = (tuple([unicode(x) for x in string.digits + string.ascii_uppercase]) +
       (u'-', u'.', u' ', u'$', u'/', u'+', u'%'))
B = u'1'
E = u'0'
CODES = (
    u'101000111011101', u'111010001010111', u'101110001010111',
    u'111011100010101', u'101000111010111', u'111010001110101',
    u'101110001110101', u'101000101110111', u'111010001011101',
    u'101110001011101', u'111010100010111', u'101110100010111',
    u'111011101000101', u'101011100010111', u'111010111000101',
    u'101110111000101', u'101010001110111', u'111010100011101',
    u'101110100011101', u'101011100011101', u'111010101000111',
    u'101110101000111', u'111011101010001', u'101011101000111',
    u'111010111010001', u'101110111010001', u'101010111000111',
    u'111010101110001', u'101110101110001', u'101011101110001',
    u'111000101010111', u'100011101010111', u'111000111010101',
    u'100010111010111', u'111000101110101', u'100011101110101',
    u'100010101110111', u'111000101011101', u'100011101011101',
    u'100010001000101', u'100010001010001', u'100010100010001',
    u'101000100010001',
)

EDGE = u'100010111011101'
MIDDLE = u'0'

# MAP for assigning every symbol (REF) to (reference number, barcode)
MAP = dict(zip(REF, enumerate(CODES)))


class Code39(Barcode):

    name = u'Code 39'

    def __init__(self, code, writer=None, add_checksum=True):
        """Initializes a new Code39 instance.

        :parameters:
            code : Unicode
                Code39 string without \* and checksum (added automatically if
                `add_checksum` is True).
            writer : barcode.writer Instance
                The writer to render the barcode (default: SVGWriter).
            add_checksum : Boolean
                Add the checksum to code or not.
        """
        code = code.upper()
        for char in code:
            if char not in REF:
                raise IllegalCharacterError('Character "%s" not valid for '
                                            'Code 39.' % char)
        self.code = code
        if add_checksum:
            self.code += self.calculate_checksum()
        self.writer = writer or Barcode.default_writer

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
        c = EDGE
        for char in self.code:
            c += MAP[char][1]
            c += MIDDLE
        c += EDGE
        return [c]

    def render(self, write_text=True, **writer_options):
        options = dict(module_width=MIN_SIZE, quiet_zone=MIN_QUIET_ZONE)
        options.update(writer_options)
        return Barcode.render(self, write_text, **options)


class PZN(Code39):
    """German number for pharmaceutical products."""

    name = u'Pharmazentralnummer'

    def __init__(self, pzn, writer=None):
        pzn = pzn[:6]
        if not pzn.isdigit():
            raise IllegalCharacterError('PZN can only contain numbers.')
        if len(pzn) != 6:
            raise NumberOfDigitsError('PZN must have 6 digits, not '
                                      '%d.' % len(pzn))
        self.pzn = pzn
        self.pzn += self.calculate_checksum()
        Code39.__init__(self, u'PZN-%s' % self.pzn, writer, add_checksum=False)

    def get_fullcode(self):
        return u'PZN-%s' % self.pzn

    def calculate_checksum(self):
        sum_ = sum([int(x) * int(y) for x, y in enumerate(self.pzn, start=2)])
        checksum = sum_ % 11
        if checksum == 10:
            raise BarcodeError('Checksum can not be 10 for PZN.')
        else:
            return unicode(checksum)

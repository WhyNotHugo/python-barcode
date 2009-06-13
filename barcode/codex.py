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
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101', u'101010101', u'101010101',
    u'101010101',
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

    def render(self, write_text=True, writer_options=None):
        options = dict(module_width=MIN_SIZE, quiet_zone=MIN_QUIET_ZONE)
        if writer_options is not None:
            options.update(writer_options)
        return Barcode.render(self, write_text, options)

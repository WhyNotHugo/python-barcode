# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

"""
Needs PIL (Python Imaging Library) to be installed.
"""

import os

from .writerbase import BaseWriter, mm2px

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print('PIL not found.')
    print('Please install PIL (easy_install pil) to use this writer.')
    raise


PATH = os.path.dirname(os.path.abspath(__file__))
FONT = os.path.join(PATH, 'DejaVuSansMono.ttf')


class ImageWriter(BaseWriter):

    def __init__(self):
        BaseWriter.__init__(self, self._init, self._paint_module,
                            self._paint_text, self._finish)
        self.format = 'PNG'
        self.dpi = 300
        self._image = None
        self._draw = None

    def _init(self, code):
        size = self.calculate_size(len(code[0]), len(code), self.dpi)
        self._image = Image.new('RGB', size, self.background)
        self._draw = ImageDraw.Draw(self._image)

    def _paint_module(self, xpos, ypos, width, color):
        size = [(mm2px(xpos, self.dpi), mm2px(ypos, self.dpi)),
                (mm2px(xpos+width, self.dpi), mm2px(ypos+self.module_height,
                                                    self.dpi))]
        self._draw.rectangle(size, outline=color, fill=color)

    def _paint_text(self, xpos, ypos):
        pos = (mm2px(xpos, self.dpi), mm2px(ypos, self.dpi))
        font = ImageFont.truetype(FONT, self.font_size)
        self._draw.text(pos, self.text, font=font, fill=self.foreground)

    def _finish(self):
        return self._image

    def save(self, filename, output):
        filename = '{0}.{1}'.format(filename, self.format.lower())
        output.save(filename, self.format.upper())
        return filename

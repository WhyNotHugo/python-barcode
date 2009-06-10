# -*- coding: utf-8 -*-

"""barcode.writer.svg

"""
__docformat__ = 'restructuredtext en'

from writerbase import BaseWriter


# SVG stuff
DOCUMENT = u"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
    "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
%s
</svg>
"""
MODULE = (u'<rect x="%.3fmm" y="%.3fmm" width="%.3fmm" height="%.3fmm" '
          u'style="fill:%s;" />')
TEXT = (u'<text x="%.3fmm" y="%.3fmm" style="fill:%s;font-size:%dpt;'
        u'text-anchor:middle;">%s</text>')


class SVGWriter(BaseWriter):

    def __init__(self, **options):
        self.module_width = options.get('module_width', 10)
        self.module_height = options.get('module_height', 10)
        self.font_size = options.get('font_size', 10)
        self.quiet_zone = options.get('quiet_zone', 6.5)
        self.background = options.get('background', u'white')
        self.foreground = options.get('foreground', u'black')
        self.text = options.get('text', u'')
        self._document = DOCUMENT

    def render(self, code):
        lines = []
        ypos = 1.0
        for line in code:
            # Left quiet zone is x startposition
            xpos = self.quiet_zone
            for mod in line:
                if mod == u'0':
                    color = self.background
                else:
                    color = self.foreground
                lines.append(MODULE % (xpos, ypos, self.module_width,
                                       self.module_height, color))
                xpos += self.module_width
            # Add right quiet zone to every line
            lines.append(MODULE % (xpos, ypos, self.quiet_zone,
                                   self.module_height, self.background))
            ypos += self.module_height
        if self.text:
            ypos += self.font_size / 3.54 + 1
            xpos = xpos / 2.0
            lines.append(TEXT % (xpos, ypos, self.foreground, self.font_size,
                                 self.text))
        return self._document % (u'\n'.join(lines), )


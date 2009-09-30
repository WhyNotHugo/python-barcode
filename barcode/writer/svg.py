# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.writer.svg

"""
__docformat__ = 'restructuredtext en'

import xml.dom

from writerbase import BaseWriter


# SVG stuff
#DOCUMENT = u"""<?xml version="1.0" encoding="UTF-8"?>
#<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
#    "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
#
#<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
#%s
#</svg>
#"""
#MODULE = (u'<rect x="%.3fmm" y="%.3fmm" width="%.3fmm" height="%.3fmm" '
#          u'style="fill:%s;" />')
#TEXT = (u'<text x="%.3fmm" y="%.3fmm" style="fill:%s;font-size:%dpt;'
#        u'text-anchor:middle;">%s</text>')

SIZE = '{0:.3f}mm'


def _set_attributes(element, **attributes):
    for key, value in attributes.items():
        element.setAttribute(key, value)


def create_svg_object():
    imp = xml.dom.getDOMImplementation()
    doctype = imp.createDocumentType(
        'svg',
        '-//W3C//DTD SVG 1.1//EN',
        'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'
    )
    document = imp.createDocument('http://www.w3.org/2000/svg', 'svg', doctype)
    _set_attributes(document.documentElement, version='1.1',
                    xmlns='http://www.w3.org/2000/svg')
    return document


class SVGWriter(BaseWriter):

    def __init__(self, **options):
        BaseWriter.__init__(self)
        self.compress = False
        self.set_options(**options)
        #self._document = DOCUMENT
        self._document = create_svg_object()

    def _create_bar_element(self, xpos, ypos, width, color):
        element = self._document.createElement('rect')
        attributes = dict(x=SIZE.format(xpos), y=SIZE.format(ypos),
                          width=SIZE.format(width),
                          height=SIZE.format(self.module_height),
                          style='fill:{0};'.format(color))
        _set_attributes(element, **attributes)
        return element

    def _create_text_element(self, xpos, ypos):
        element = self._document.createElement('text')
        element.data = self.text
        attributes = dict(x=SIZE.format(xpos), y=SIZE.format(ypos),
                          style='fill:{0};font-size:{1}pt;text-anchor:'
                                'middle;'.format(self.foreground,
                                                 self.font_size))
        _set_attributes(element, **attributes)
        return element

    def render(self, code):
        root = self._document.documentElement
        ypos = 1.0
        for line in code:
            # Left quiet zone is x startposition
            xpos = self.quiet_zone
            for mod in line:
                if mod == '0':
                    color = self.background
                else:
                    color = self.foreground
                new_child = self._create_bar_element(xpos, ypos,
                                                     self.module_width, color)
                root.appendChild(new_child)
                xpos += self.module_width
            # Add right quiet zone to every line
            new_child = self._create_bar_element(xpos, ypos, self.quiet_zone,
                                                 self.background)
            root.appendChild(new_child)
            ypos += self.module_height
        if self.text:
            # Todo
            ypos += self.font_size / 3.54 + 1
            xpos = xpos / 2.0
            root.appendChild(self._create_text_element(xpos, ypos))
        svg = self._document.toprettyxml(encoding='UTF-8')
        if self.compress:
            # Do compression
            return ('svgz', None)
        return ('svg', svg)

#    def render(self, code):
#        lines = []
#        ypos = 1.0
#        for line in code:
#            # Left quiet zone is x startposition
#            xpos = self.quiet_zone
#            for mod in line:
#                if mod == u'0':
#                    color = self.background
#                else:
#                    color = self.foreground
#                lines.append(MODULE % (xpos, ypos, self.module_width,
#                                       self.module_height, color))
#                xpos += self.module_width
#            # Add right quiet zone to every line
#            lines.append(MODULE % (xpos, ypos, self.quiet_zone,
#                                   self.module_height, self.background))
#            ypos += self.module_height
#        if self.text:
#            ypos += self.font_size / 3.54 + 1
#            xpos = xpos / 2.0
#            lines.append(TEXT % (xpos, ypos, self.foreground, self.font_size,
#                                 self.text))
#        return self._document % (u'\n'.join(lines), )


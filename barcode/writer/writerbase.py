# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.writer.writerbase

"""
__docformat__ = 'restructuredtext en'


class BaseWriter(object):
    """Baseclass for all writers."""

    def __init__(self):
        """Initializes the basic writer options. Childclasses can add more
        attributes and can set them directly or using
        `self.set_options(option=value)`.
        """
        self.module_width = 10
        self.module_height = 10
        self.font_size = 10
        self.quiet_zone = 6.5
        self.background = 'white'
        self.foreground = 'black'
        self.text = ''

    def set_options(self, **options):
        """Sets the given keyword arguments as instance attributes (only if
        they are known).

        :parameters:
            options : Keyword arguments
                All known instance attributes and more if the childclass has
                defined them before this call.

        :rtype: None
        """
        for key, val in options.items():
            key = key.lstrip('_')
            if hasattr(self, key):
                setattr(self, key, val)

    def render(self, code):
        """Renders the barcode to whatever the inheriting writer provides.
        Childclasses must implement this.
        """
        raise NotImplementedError

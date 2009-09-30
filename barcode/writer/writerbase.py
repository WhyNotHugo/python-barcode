# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.writer.writerbase

Callback specification
======================

paint_module
------------

Is called::

    callback_paint_module(xpos, ypos, width, color)

paint_text
----------

Is called::

    callback_paint_text(xpos, ypos) using self.text as text
    
finish
------

Is called::

    return callback_finish() and should return the rendered output

"""
__docformat__ = 'restructuredtext en'


class BaseWriter(object):
    """Baseclass for all writers."""

    def __init__(self, paint_module=None, paint_text=None, finish=None):
        """Initializes the basic writer options. Childclasses can add more
        attributes and can set them directly or using
        `self.set_options(option=value)`.
        
        :parameters:
            paint_module : Function
                Callback for painting one barcode module.
            paint_text : Function
                Callback for painting the text under the barcode.
            finish : Function
                Callback for doing something with the completely rendered
                output.
        """
        self.__paint_module = paint_module
        self.__paint_text = paint_text
        self.__finish = finish
        self.module_width = 10
        self.module_height = 10
        self.font_size = 10
        self.quiet_zone = 6.5
        self.background = 'white'
        self.foreground = 'black'
        self.text = ''

    def register_callback(self, action, callback):
        """Register one of the two callbacks if not given at instance
        creation.
        
        :parameters:
            action : String
                Can be 'module', 'text' or 'finish'.
            callback : Function
                The callback function for the given action.
        """
        if action == 'module':
            self.__paint_module = callback
        elif action == 'text':
            self.__paint_text = callback
        elif action == 'finish':
            self.__finish = callback
            
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
        Calls `self.__paint_module()` and `self.__paint_text`.
        
        :parameters:
            code : List
                List of strings matching the writer spec (only contain 0 or 1).
        """
        ypos = 1.0
        for line in code:
            # Left quiet zone is x startposition
            xpos = self.quiet_zone
            for mod in line:
                if mod == '0':
                    color = self.background
                else:
                    color = self.foreground
                self.__paint_module(xpos, ypos, self.module_width, color)
                xpos += self.module_width
            # Add right quiet zone to every line
            self.__paint_module(xpos, ypos, self.quiet_zone, self.background)
            ypos += self.module_height
        if self.text:
            ypos += self.font_size / 3.54 + 1
            xpos = xpos / 2.0
            self.__paint_text(xpos, ypos)
        return self.__finish()

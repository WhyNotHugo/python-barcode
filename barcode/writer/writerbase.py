# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

"""

Callback specification
======================

initialize
----------

Is called::

    callback_initialize(raw_code)

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


def mm2px(mm, dpi=300):
    return (mm * dpi) / 25.4


class BaseWriter(object):
    """Baseclass for all writers."""

    def __init__(self, initialize=None, paint_module=None, paint_text=None,
                 finish=None):
        """Initializes the basic writer options. Childclasses can add more
        attributes and can set them directly or using
        `self.set_options(option=value)`.

        :parameters:
            initialize : Function
                Callback for initializing the inheriting writer.
            paint_module : Function
                Callback for painting one barcode module.
            paint_text : Function
                Callback for painting the text under the barcode.
            finish : Function
                Callback for doing something with the completely rendered
                output.
        """
        self._callbacks = dict(initialize=initialize, paint_module=paint_module,
                               paint_text=paint_text, finish=finish)
        self.module_width = 10
        self.module_height = 10
        self.font_size = 10
        self.quiet_zone = 6.5
        self.background = 'white'
        self.foreground = 'black'
        self.text = ''
        self.text_distance = 5

    def calculate_size(self, modules_per_line, number_of_lines, dpi=300):
        """Calculates the size of the barcode in pixel.

        :parameters:
            modules_per_line : Integer
                Number of mudules in one line.
            number_of_lines : Integer
                Number of lines of the barcode.
            dpi : Integer
                DPI to calculate.

        :returns: Width and height of the barcode in pixel.
        :rtype: Tuple
        """
        width = 2 * self.quiet_zone + modules_per_line * self.module_width
        height = 1.0 + self.module_height * number_of_lines
        if self.text:
            height += self.font_size + self.text_distance
        return int(mm2px(width, dpi)), int(mm2px(height, dpi))

    def save(self, filename, output):
        """Saves the rendered output to `filename`.

        :parameters:
            filename : String
                Filename without extension.
            output : String
                The rendered output.

        :returns: The full filename with extension.
        :rtype: String
        """
        raise NotImplementedError

    def register_callback(self, action, callback):
        """Register one of the three callbacks if not given at instance
        creation.

        :parameters:
            action : String
                One of 'initialize', 'paint_module', 'paint_text', 'finish'.
            callback : Function
                The callback function for the given action.
        """
        self._callbacks[action] = callback

    def set_options(self, **options):
        """Sets the given keyword arguments as instance attributes (only
        if they are known).

        :parameters:
            options : Keyword arguments
                All known instance attributes and more if the childclass
                has defined them before this call.

        :rtype: None
        """
        for key, val in options.items():
            key = key.lstrip('_')
            if hasattr(self, key):
                setattr(self, key, val)

    def render(self, code):
        """Renders the barcode to whatever the inheriting writer provides,
        using the registered callbacks.

        :parameters:
            code : List
                List of strings matching the writer spec
                (only contain 0 or 1).
        """
        print(self.font_size)
        if self._callbacks['initialize'] is not None:
            self._callbacks['initialize'](code)
        ypos = 1.0
        for line in code:
            # Left quiet zone is x startposition
            xpos = self.quiet_zone
            for mod in line:
                if mod == '0':
                    color = self.background
                else:
                    color = self.foreground
                self._callbacks['paint_module'](xpos, ypos, self.module_width,
                                                color)
                xpos += self.module_width
            # Add right quiet zone to every line
            self._callbacks['paint_module'](xpos, ypos, self.quiet_zone,
                                            self.background)
            ypos += self.module_height
        if self.text and self._callbacks['paint_text'] is not None:
            ypos += self.text_distance
            xpos = xpos / 2.0
            self._callbacks['paint_text'](xpos, ypos)
        return self._callbacks['finish']()


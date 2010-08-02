# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.base

"""

from barcode.writer import SVGWriter


class Barcode(object):

    name = ''

    raw = None

    digits = 0

    default_writer = SVGWriter

    # str() function is only a workaround for the unicode_literals
    # Error: TypeError: set_options() keywords must be strings
    default_writer_options = {
        str('module_width'): 0.2,
        str('module_height'): 15.0,
        str('quiet_zone'): 6.5,
        str('font_size'): 10,
        str('text_distance'): 5.0,
        str('background'): 'white',
        str('foreground'): 'black',
        str('text'): '',
    }

    def to_ascii(self):
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace('1', 'X').replace('0', ' ')
        return '\n'.join(code)

    def build(self):
        raise NotImplementedError

    def get_fullcode(self):
        """Returns the full code, encoded in the barcode.

        :returns: Full human readable code.
        :rtype: String
        """
        raise NotImplementedError

    def save(self, filename, **kw):
        """Renders the barcode and saves it in `filename`.

        :parameters:
            filename : String
                Filename to save the barcode in (without filename
                extension).
            kw : Keyword Arguments
                The same as in `self.render`.

        :returns: The full filename with extension.
        :rtype: String
        """
        output = self.render(**kw)
        _filename = self.writer.save(filename, output)
        return _filename

    def write(self, fp, **kw):
        """Renders the barcode and writes it to the file like object
        `fp`.

        :parameters:
            fp : File like object
                Object to write the raw data in.
            kw : Keyword Arguments
                The same as in `self.render`.
        """
        output = self.render(**kw)
        if hasattr(output, 'tostring'):
            fp.write(output.tostring())
        else:
            fp.write(output)

    def render(self, write_text=True, **writer_options):
        """Renders the barcode using `self.writer`.

        :parameters:
            write_text : Boolean
                Write the Code under the barcode.
            writer_options : Keyword arguments
                Options for `self.writer`, see writer docs for details.

        :returns: Output of the writers render method.
        """
        options = Barcode.default_writer_options.copy()
        if write_text:
            options[str('text')] = self.get_fullcode()
        options.update(writer_options)
        self.writer.set_options(**options)
        code = self.build()
        raw = Barcode.raw = self.writer.render(code)
        return raw

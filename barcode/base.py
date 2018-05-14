# -*- coding: utf-8 -*-

from __future__ import unicode_literals

"""barcode.base

"""

from barcode.writer import SVGWriter


class Barcode(object):

    name = ''

    digits = 0

    default_writer = SVGWriter

    default_writer_options = {
        'module_width': 0.2,
        'module_height': 15.0,
        'quiet_zone': 6.5,
        'font_size': 10,
        'text_distance': 5.0,
        'background': 'white',
        'foreground': 'black',
        'write_text': True,
        'text': '',
    }

    def to_ascii(self):
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace('1', 'X').replace('0', ' ')
        return '\n'.join(code)

    def __repr__(self):
        return '<{0}({1!r})>'.format(self.__class__.__name__,
                                     self.get_fullcode())

    def build(self):
        raise NotImplementedError

    def get_fullcode(self):
        """Returns the full code, encoded in the barcode.

        :returns: Full human readable code.
        :rtype: String
        """
        raise NotImplementedError

    def save(self, filename, options=None, text=None):
        """Renders the barcode and saves it in `filename`.

        :parameters:
            filename : String
                Filename to save the barcode in (without filename
                extension).
            options : Dict
                The same as in `self.render`.
            text : str (unicode on Python 2)
                Text to render under the barcode.

        :returns: The full filename with extension.
        :rtype: String
        """
        if text:
            output = self.render(options, text)
        else:
            output = self.render(options)

        _filename = self.writer.save(filename, output)
        return _filename

    def write(self, fp, options=None, text=None):
        """Renders the barcode and writes it to the file like object
        `fp`.

        :parameters:
            fp : File like object
                Object to write the raw data in.
            options : Dict
                The same as in `self.render`.
            text : str (unicode on Python 2)
                Text to render under the barcode.
        """
        output = self.render(options, text)
        if hasattr(output, 'tostring'):
            output.save(fp, format=self.writer.format)
        else:
            fp.write(output)

    def render(self, writer_options=None, text=None):
        """Renders the barcode using `self.writer`.

        :parameters:
            writer_options : Dict
                Options for `self.writer`, see writer docs for details.
            text : str (unicode on Python 2)
                Text to render under the barcode.

        :returns: Output of the writers render method.
        """
        options = Barcode.default_writer_options.copy()
        options.update(writer_options or {})
        if options['write_text'] or text is not None:
            if text is not None:
                options['text'] = text
            else:
                options['text'] = self.get_fullcode()
        self.writer.set_options(options)
        code = self.build()
        raw = self.writer.render(code)
        return raw

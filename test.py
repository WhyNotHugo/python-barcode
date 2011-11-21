# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

"""

Performs some tests with pyBarcode. All created barcodes where saved in the
tests subdirectory with a tests.html to watch them.

"""
__docformat__ = 'restructuredtext en'

import codecs
import os
import sys
import webbrowser

from barcode import get_barcode, get_barcode_class, __version__
try:
    from barcode.writer import ImageWriter
except ImportError:
    ImageWriter = None


PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, 'tests')
HTMLFILE = os.path.join(TESTPATH, 'tests.html')

HTML = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
    "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <title>pyBarcode {version} Test</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    </head>
    <body>
        <h1>pyBarcode {version} Tests</h1>
        {body}
    </body>
</html>
"""

OBJECTS = ('<p><h2>{name}</h2><br />\n'
           '<object data="{filename}" type="image/svg+xml">\n'
           '<param name="src" value="{filename}" /></object>')

IMAGES = ('<h3>As PNG-Image</h3><br />\n'
          '<img src="{filename}" alt="{name}" /></p>\n')

NO_PIL = '<h3>PIL was not found. No PNG-Image created.</h3></p>\n'

TESTCODES = (
    ('ean8', '40267708'),
    ('ean13', '5901234123457'),
    ('upca', '36000291453'),
    ('jan', '4901234567894'),
    ('isbn10', '3-12-517154-7'),
    ('isbn13', '978-3-16-148410-0'),
    ('issn', '1144875X'),
    ('code39', 'Example Code 39'),
    ('pzn', '487780'),
)


def test():
    if not os.path.isdir(TESTPATH):
        try:
            os.mkdir(TESTPATH)
        except OSError, e:
            print('Test not run.')
            print('Error:', e)
            sys.exit(1)
    objects = []
    append = lambda x, y: objects.append(OBJECTS.format(filename=x, name=y))
    append_img = lambda x, y: objects.append(IMAGES.format(filename=x, name=y))
    options = dict(module_width=0.495, module_height=25.0)
    for codename, code in TESTCODES:
        bcode = get_barcode(codename, code)
        filename = bcode.save(os.path.join(TESTPATH, codename))
        print('Code: {0}, Input: {1}, Output: {2}'.format(
            bcode.name, code, bcode.get_fullcode()))
        append(filename, bcode.name)
        if ImageWriter is not None:
            bcodec = get_barcode_class(codename)
            bcode = bcodec(code, writer=ImageWriter())
            opts = dict(font_size=14, text_distance=1)
            if codename.startswith('i'):
                opts['center_text'] = False
            filename = bcode.save(os.path.join(TESTPATH, codename), opts)
            append_img(filename, bcode.name)
        else:
            objects.append(NO_PIL)
    # Save htmlfile with all objects
    with codecs.open(HTMLFILE, 'w', encoding='utf-8') as f:
        obj = '\n'.join(objects)
        f.write(HTML.format(version=__version__, body=obj))


if __name__ == '__main__':
    test()
    webbrowser.open(HTMLFILE)

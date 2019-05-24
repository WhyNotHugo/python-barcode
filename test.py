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
import unittest

from barcode import get_barcode, get_barcode_class, version
try:
    from barcode.writer import ImageWriter
except ImportError:
    ImageWriter = None  # lint:ok


PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, 'tests')
HTMLFILE = os.path.join(TESTPATH, 'index.html')

HTML = """<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>pyBarcode {version} Test</title>
    </head>
    <body>
        <h1>pyBarcode {version} Tests</h1>
        {body}
    </body>
</html>
"""

OBJECTS = ('<p><h2>{name}</h2><br>\n'
           '<img src="{filename}" alt="SVG {name}">\n')

IMAGES = ('<h3>As PNG-Image</h3><br>\n'
          '<img src="{filename}" alt="PNG {name}"></p>\n')

NO_PIL = '<h3>Pillow was not found. No PNG-Image created.</h3></p>\n'

TESTCODES = (
    ('ean8', '40267708'),
    ('ean13', '5901234123457'),
    ('ean14', '12345678911230'),
    ('upca', '36000291453'),
    ('jan', '4901234567894'),
    ('isbn10', '3-12-517154-7'),
    ('isbn13', '978-3-16-148410-0'),
    ('issn', '1144875X'),
    ('code39', 'Example Code 39'),
    ('pzn', '487780'),
    ('code128', 'Example Code 128 998866'),
    ('itf', '12341234'),
)


def test():
    if not os.path.isdir(TESTPATH):
        try:
            os.mkdir(TESTPATH)
        except OSError as e:
            print('Test not run.')
            print('Error:', e)
            sys.exit(1)
    objects = []
    append = lambda x, y: objects.append(OBJECTS.format(filename=x, name=y))
    append_img = lambda x, y: objects.append(IMAGES.format(filename=x, name=y))
    options = dict(module_width=0.495, module_height=25.0)
    for codename, code in TESTCODES:
        bcode = get_barcode(codename, code)
        if codename.startswith('i'):
            options['center_text'] = False
        else:
            options['center_text'] = True
        filename = bcode.save(os.path.join(TESTPATH, codename),
                              options=options)
        print('Code: {0}, Input: {1}, Output: {2}'.format(
            bcode.name, code, bcode.get_fullcode()))
        append(os.path.basename(filename), bcode.name)
        if ImageWriter is not None:
            bcodec = get_barcode_class(codename)
            bcode = bcodec(code, writer=ImageWriter())
            opts = dict(font_size=14, text_distance=1)
            if codename.startswith('i'):
                opts['center_text'] = False
            else:
                opts['center_text'] = True
            filename = bcode.save(os.path.join(TESTPATH, codename),
                                  options=opts)
            append_img(os.path.basename(filename), bcode.name)
        else:
            objects.append(NO_PIL)
    # Save htmlfile with all objects
    with codecs.open(HTMLFILE, 'w', encoding='utf-8') as f:
        obj = '\n'.join(objects)
        f.write(HTML.format(version=version, body=obj))


class TestBarcodeBuilds(unittest.TestCase):

    def test_ean8(self):
        ref = ('1010100011000110100100110101111010101000100'
               '100010011100101001000101')
        ean = get_barcode('ean8', '40267708')
        bc = ean.build()
        self.assertEqual(ref, bc[0])


class TestChecksums(unittest.TestCase):

    def test_code39(self):
        code39 = get_barcode('code39', 'Code39')
        self.assertEqual('CODE39W', code39.get_fullcode())

    def test_pzn(self):
        pzn = get_barcode('pzn', '103940')
        self.assertEqual('PZN-1039406', pzn.get_fullcode())

    def test_ean13(self):
        ean = get_barcode('ean13', '400614457735')
        self.assertEqual('4006144577350', ean.get_fullcode())

    def test_ean8(self):
        ean = get_barcode('ean8', '6032299')
        self.assertEqual('60322999', ean.get_fullcode())

    def test_jan(self):
        jan = get_barcode('jan', '491400614457')
        self.assertEqual('4914006144575', jan.get_fullcode())

    def test_ean14(self):
        ean = get_barcode('ean14', '1234567891258')
        self.assertEqual('12345678912589', ean.get_fullcode())

    def test_isbn10(self):
        isbn = get_barcode('isbn10', '376926085')
        self.assertEqual('3769260856', isbn.isbn10)

    def test_isbn13(self):
        isbn = get_barcode('isbn13', '978376926085')
        self.assertEqual('9783769260854', isbn.get_fullcode())

    def test_gs1_128(self):
        gs1_128 = get_barcode('gs1_128', '00376401856400470087')
        self.assertEqual('00376401856400470087', gs1_128.get_fullcode())


if __name__ == '__main__':
    test()
    print('\nNow open {htmlfile} in your browser.'.format(htmlfile=HTMLFILE))
    if '-v' not in sys.argv:
        sys.argv.append('-v')
    unittest.main()


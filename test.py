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

from barcode import BARCODE_MAP, get_barcode, __version__


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

OBJECTS = ('<p><h2>%(name)s</h2><br />\n'
           '<object data="%(file)s" type="image/svg+xml">\n'
           '<param name="src" value="%(file)s" /></object></p>')


def test():
    if not os.path.isdir(TESTPATH):
        try:
            os.mkdir(TESTPATH)
        except OSError, e:
            print('Test not run.')
            print('Error:', e)
            sys.exit(1)
    objects = []
    # Test EAN-8
    ean8 = get_barcode('ean8', '40267708')
    name = ean8.save(os.path.join(TESTPATH, 'ean8'))
    objects.append(OBJECTS % {'file': name, 'name': ean8.name})
    # Test EAN-13
    ean13 = get_barcode('ean13', '5901234123457')
    name = ean13.save(os.path.join(TESTPATH, 'ean13'))
    objects.append(OBJECTS % {'file': name, 'name': ean13.name})
    # Test UPC-A
    upca = get_barcode('upca', '36000291452')
    name = upca.save(os.path.join(TESTPATH, 'upca'))
    objects.append(OBJECTS % {'file': name, 'name': upca.name})
    # Test JAN
    jan = get_barcode('jan', '4901234567894')
    name = jan.save(os.path.join(TESTPATH, 'jan.svg'))
    objects.append(OBJECTS % {'file': name, 'name': jan.name})
    # Test ISBN-10
    isbn10 = get_barcode('isbn10', '3-12-517154-7')
    name = isbn10.save(os.path.join(TESTPATH, 'isbn10'))
    objects.append(OBJECTS % {'file': name, 'name': isbn10.name})
    # Test ISBN-13
    isbn13 = get_barcode('isbn13', '978-3-16-148410-0')
    name = isbn13.save(os.path.join(TESTPATH, 'isbn13'))
    objects.append(OBJECTS % {'file': name, 'name': isbn13.name})
    # Test ISSN
    issn = get_barcode('issn', '1144875X')
    name = issn.save(os.path.join(TESTPATH, 'issn'))
    objects.append(OBJECTS % {'file': name, 'name': issn.name})
    # Test Code 39
    code39 = get_barcode('code39', 'Example Code 39')
    name = code39.save(os.path.join(TESTPATH, 'code39'))
    objects.append(OBJECTS % {'file': name, 'name': code39.name})
    # Test PZN
    pzn = get_barcode('pzn', '487780')
    name = pzn.save(os.path.join(TESTPATH, 'pzn'))
    objects.append(OBJECTS % {'file': name, 'name': pzn.name})
    # Save htmlfile with all objects
    with codecs.open(HTMLFILE, 'w', encoding='utf-8') as f:
        obj = '\n'.join(objects)
        f.write(HTML.format(version=__version__, body=obj))


if __name__ == '__main__':
    test()
    webbrowser.open(HTMLFILE)

# -*- coding: utf-8 -*-

"""

Perform some tests with pyBarcode. All created barcodes where saved in the
tests subdirectory with a tests.html to watch them.

"""
__docformat__ = 'restructuredtext en'

import codecs
import os

from barcode import BARCODE_MAP, get_barcode


PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, 'tests')
HTMLFILE = os.path.join(TESTPATH, 'tests.html')

HTML = u"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
    "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <title>pyBarcode v0.2 Test</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    </head>
    <body>
        <h1>pyBarcode v0.2 Tests</h1>
        %s
    </body>
</html>
"""

OBJECTS = (u'<p><h2>%(name)s</h2><br />\n'
           u'<object data="%(file)s" type="image/svg+xml">\n'
           u'<param name="src" value="%(file)s" /></object></p>')


def test():
    objects = []
    # Test EAN-8
    ean8 = get_barcode('ean8', u'40267708')
    ean8.save(os.path.join(TESTPATH, 'ean8.svg'))
    objects.append(OBJECTS % {'file': u'ean8.svg', 'name': ean8.name})
    # Test EAN-13
    ean13 = get_barcode('ean13', u'5901234123457')
    ean13.save(os.path.join(TESTPATH, 'ean13.svg'))
    objects.append(OBJECTS % {'file': u'ean13.svg', 'name': ean13.name})
    # Test UPC-A
    upca = get_barcode('upca', u'36000291452')
    upca.save(os.path.join(TESTPATH, 'upca.svg'))
    objects.append(OBJECTS % {'file': u'upca.svg', 'name': upca.name})
    # Test JAN
    jan = get_barcode('jan', u'4901234567894')
    jan.save(os.path.join(TESTPATH, 'jan.svg'))
    objects.append(OBJECTS % {'file': u'jan.svg', 'name': jan.name})
    # Test ISBN-10
    isbn10 = get_barcode('isbn10', u'3-12-517154-7')
    isbn10.save(os.path.join(TESTPATH, 'isbn10.svg'))
    objects.append(OBJECTS % {'file': u'isbn10.svg', 'name': isbn10.name})
    # Test ISBN-13
    isbn13 = get_barcode('isbn13', u'978-3-16-148410-0')
    isbn13.save(os.path.join(TESTPATH, 'isbn13.svg'))
    objects.append(OBJECTS % {'file': u'isbn13.svg', 'name': isbn13.name})
    # Test ISSN
    issn = get_barcode('issn', u'1144875X')
    issn.save(os.path.join(TESTPATH, 'issn.svg'))
    objects.append(OBJECTS % {'file': u'issn.svg', 'name': issn.name})
    # Test Code 39
    code39 = get_barcode('code39', u'Example Code 39')
    code39.save(os.path.join(TESTPATH, 'code39.svg'))
    objects.append(OBJECTS % {'file': u'code39.svg', 'name': code39.name})
    # Test PZN
    pzn = get_barcode('pzn', u'487780')
    pzn.save(os.path.join(TESTPATH, 'pzn.svg'))
    objects.append(OBJECTS % {'file': u'pzn.svg', 'name': pzn.name})
    # Save htmlfile with all objects
    with codecs.open(HTMLFILE, 'w', encoding='utf-8') as f:
        obj = u'\n'.join(objects)
        f.write(HTML % obj)


if __name__ == '__main__':
    test()

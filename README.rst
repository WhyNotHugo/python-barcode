pyBarcode
=========

This library provides a simple way to create barcodes using only the
Python standardlib. The barcodes where created as SVG objects.

Report bugs at http://bitbucket.org/whitie/pybarcode/issues/


Requirements
------------

    - Python 2.6 or above, but not the 3.x series
    - Program to open SVG objects (your browser should do it)
    - Optional: PIL to render barcodes as images (PNG, JPG, ...)


Installation
------------

Unpack the downloaded file, cd into the pyBarcode directory and run
`python setup.py install`. Or just copy the barcode dir somewhere in
your PYTHONPATH.


Provided Barcodes
-----------------

EAN-8, EAN-13, UPC-A, JAN, ISBN-10, ISBN-13, ISSN, Code 39, PZN


Todo
----

    - Add documentation
    - Add more codes

Usage
-----

Interactive::

    >>> import barcode
    >>> barcode.PROVIDED_BARCODES
    [u'code39', u'ean', u'ean13', u'ean8', u'gs1', u'gtin', u'isbn', u'isbn10',
     u'isbn13', u'issn', u'jan', u'pzn', u'upc', u'upca']
    >>> EAN = barcode.get_barcode_class('ean13')
    >>> EAN
    <class 'barcode.ean.EuropeanArticleNumber13'>
    >>> ean = EAN(u'5901234123457')
    >>> ean
    <barcode.ean.EuropeanArticleNumber13 object at 0x00BE98F0>
    >>> fullname = ean.save('ean13_barcode')
    >>> fullname
    u'ean13_barcode.svg'
    # Example with PNG
    >>> from barcode.writer import ImageWriter
    >>> ean = EAN(u'5901234123457', writer=ImageWriter())
    >>> fullname = ean.save('ean13_barcode')
    u'ean13_barcode.png'
    # New in v0.4.2
    >>> from StringIO import StringIO
    >>> fp = StringIO()
    >>> ean.write(fp)
    # or
    >>> f = open('/my/new/file', 'wb')
    >>> ean.write(f) # PIL (ImageWriter) produces RAW format here
    # New in v0.5.0
    >>> from barcode import generate
    >>> name = generate('EAN13', u'5901234123457', output='barcode_svg')
    >>> name
    u'barcode_svg.svg'
    # with file like object
    >>> fp = StringIO()
    >>> generate('EAN13', u'5901234123457', writer=ImageWriter(), output=fp)
    >>>

Now open ean13_barcode.[svg|png] in a graphic app or simply in your browser
and see the created barcode. That's it.


Changelog
---------

v0.5.0: Added new generate function to do all generation in one step.
        Moved writer from a subpackage to a module (this breaks some
        existing code). UPC is now rendered as real UPC, not as EAN13
        with the leading "0".

v0.4.3: Fixed bug in new write method (related to PIL) and updated docs.

v0.4.2: Added write method to support file like objects as target.

v0.4.1: Bugfix release. Removed redundancy in input validation.
        EAN8 was broken. It now works as expected.

v0.4: Removed **options from writers __init__ method. These options never
      had effect. They were always overwritten by default_options.
      New config option available: text_distance (the distance between
      barcode and text).

v0.4b2: Basic documentation included. The barcode object now has a new
        attribute called `raw` to have the rendered output without saving
        to disk.

v0.4b1: Support for rendering barcodes as images is implemented.
        PIL is required to use it.

v0.3: Compression for SVG output now works.

v0.3b1: Writer API has changed for simple adding new (own) writers.
        SVG output is now generated with xml.dom module instead of
        stringformatting (makes it more robust).

v0.2.1: API of render changed. Now render takes keyword arguments
        instead of a dict.

v0.2: More tests added.

v0.1: First release.


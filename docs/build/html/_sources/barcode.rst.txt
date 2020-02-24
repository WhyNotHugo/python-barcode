Introduction
============

This package was created to have barcodes available with pure-python.
Pillow_ is required for exporting for exporting images (png, jpg), although not
for SVGs.

All you need to create a barcode is to know the system (EAN, UPC, ...)
and the code (e.g. for EAN-13: 123456789102). As you see, you do not
need the checksum, it will be calculated automatically. In some systems
(Code 39) the checksum is optional, there you can give the `add_checksum`
keyword argument (default is True).

As of version 0.7beta3 Python 3 is supported, but not well tested.

.. _Pillow: https://python-pillow.org/

Creating barcodes as SVG
------------------------

To generate barcodes as SVG objects, you can use the default writer
(simply not specify a writer).

Quick example::

    >>> import barcode
    >>> ean = barcode.get('ean13', '123456789102')
    # Now we look if the checksum was added
    >>> ean.get_fullcode()
    '1234567891026'
    >>> filename = ean.save('ean13')
    >>> filename
    'ean13.svg'
    >>> options = dict(compress=True)
    >>> filename = ean.save('ean13', options)
    >>> filename
    'ean13.svgz'

Now you have ean13.svg and the compressed ean13.svgz in your current
working directory. Open it and see the result.

Creating barcodes as Image
--------------------------

.. versionadded:: 0.4b1

To generate barcodes as images, you must provide the ImageWriter to the
`get` function. Without any options, the images are rendered
as PNG.

Quick example::

    >>> import barcode
    >>> from barcode.writer import ImageWriter
    >>> ean = barcode.get('ean13', '123456789102', writer=ImageWriter())
    >>> filename = ean.save('ean13')
    >>> filename
    'ean13.png'

Introduction
============

This package was created to have barcodes available without having
PIL_ (Python Imaging Library) installed. As of version 0.4b1 PIL
is also supported for creating barcodes.

All you need to create a barcode is to know the system (EAN, UPC, ...)
and the code (e.g. for EAN-13: 123456789102). As you see, you do not
need the checksum, it will be calculated automatically. In some systems
(Code 39) the checksum is optional, there you can give the `add_checksum`
keyword argument (default is True).

.. _PIL: http://www.pythonware.com/products/pil

Creating barcodes as SVG
------------------------

To generate barcodes as SVG objects, you can use the default writer
(simply not specify a writer).

Quick example::

    >>> import barcode
    >>> ean = barcode.get_barcode('ean', '123456789102')
    >>> ean.get_fullcode()
    u'1234567891026'
    >>> filename = ean.save('ean13')
    >>> filename
    u'ean13.svg'
    >>> filename = ean.save('ean13', compress=True)
    >>> filename
    u'ean13.svgz'

Now you have ean13.svg and the compressed ean13.svgz in your current
working directory. Open it and see the result.

Creating barcodes as Image
--------------------------

To generate barcodes as images, you must provide the ImageWriter to the
`get_barcode` function. Without any options, the images were rendered
as PNG.

Quick example::

    >>> import barcode
    >>> from barcode.writer import ImageWriter
    >>> ean = barcode.get_barcode('ean', '123456789102', writer=ImageWriter())
    >>> filename = ean.save('ean13')
    >>> filename
    u'ean13.png'


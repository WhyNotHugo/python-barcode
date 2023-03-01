Getting started
===============

Installation
------------

The usual way is to use pip:

.. code:: shell

    pip install python-barcode

Don't forget to add this to our app's dependencies.

If you'll be exporting to images (eg: not just SVG), you'll need the "images" extras:

.. code:: shell

    pip install "python-barcode[images]"
    # Note: keep the quotes, most shells don't play nice with square brackets.

Usage
-----

Let's start off with some code samples.

Keep in mind that checksums are calculated automatically -- you don't need to do the
math before passing the value for the barcode.

In some systems (Code 39) the checksum is optional. For these, you can provide the
``add_checksum=False`` keyword argument.


Generating SVG files
~~~~~~~~~~~~~~~~~~~~

.. code:: python

    from io import BytesIO

    from barcode import EAN13
    from barcode.writer import SVGWriter

    # Write to a file-like object:
    rv = BytesIO()
    EAN13("100000902922", writer=SVGWriter()).write(rv)

    # Or to an actual file:
    with open("somefile.svg", "wb") as f:
        EAN13(str(100000011111), writer=SVGWriter()).write(f)

Generating image files
~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.4b1

.. attention::

  Keep in mind that SVG files are vectorized, so they will scale a lot better than
  images. It's recommended to use images only if your medium or target usages does not
  support SVG.

.. code:: python

    from io import BytesIO

    from barcode import EAN13
    from barcode.writer import ImageWriter

    # Write to a file-like object:
    rv = BytesIO()
    EAN13(str(100000902922), writer=ImageWriter()).write(rv)

    # Or to an actual file:
    with open("somefile.jpeg", "wb") as f:
        EAN13("100000011111", writer=ImageWriter()).write(f)

Interactive generating an SVG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using an interactive python interpreter to generate SVG files.

.. code:: pycon

    >>> import barcode
    >>> barcode.PROVIDED_BARCODES
    ['code128', 'code39', 'ean', 'ean13', 'ean14', 'ean8', 'gs1', 'gs1_128', 'gtin', 'isbn', 'isbn10', 'isbn13', 'issn', 'itf', 'jan', 'pzn', 'upc', 'upca']
    >>> EAN = barcode.get_barcode_class('ean13')
    >>> EAN
    <class 'barcode.ean.EuropeanArticleNumber13'>
    >>> my_ean = EAN('5901234123457')
    >>> my_ean
    <EuropeanArticleNumber13('5901234123457')>
    >>> fullname = my_ean.save('ean13_barcode')
    >>> fullname
    'ean13_barcode.svg'
    >>>

You can check the generated files (e.g.: ``ean13_barcode.svg``) by opening them with
any graphical app (e.g.: Firefox).

Interactive generating a PNG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using an interactive python interpreter to generate PNG files.

.. code:: pycon

    >>> import barcode
    >>> from barcode.writer import ImageWriter
    >>> EAN = barcode.get_barcode_class('ean13')
    >>> my_ean = EAN('5901234123457', writer=ImageWriter())
    >>> fullname = my_ean.save('ean13_barcode')
    >>> fullname
    'ean13_barcode.png'
    >>> from io import BytesIO
    >>> fp = BytesIO()
    >>> my_ean.write(fp)
    >>> my_ean
    <EuropeanArticleNumber13('5901234123457')>
    >>> with open("path/to/file", "wb") as f:
    ...     my_ean.write(f)  # Pillow (ImageWriter) produces RAW format here
    ...
    >>> from barcode import generate
    >>> name = generate('EAN13', '5901234123457', output='barcode_svg')
    >>> name
    'barcode_svg.svg'
    >>> fp = BytesIO()
    >>> generate('EAN13', '5901234123457', writer=ImageWriter(), output=fp)
    >>>

You can check the generated files (e.g.: ``ean13_barcode.png``) by opening them with
any graphical app (e.g.: Firefox).

Command Line usage
~~~~~~~~~~~~~~~~~~

.. versionadded:: 0.7beta4

This library also includes a cli app for quickly generating barcodes from the command
line or from shell scripts:

.. code:: console

    $ # Save a barcode to outfile.svg:
    $ python-barcode create "123456789000" outfile -b ean --text "text to appear under barcode"
    $ # Generate a PNG (Require Pillow):
    $ python-barcode create -t png "My Text" outfile
    $ python-barcode --help
    usage: python-barcode [-h] [-v] {create,list} ...

    Create standard barcodes via cli.

    optional arguments:
      -h, --help     show this help message and exit
      -v, --version  show program's version number and exit

    Actions:
      {create,list}
        create       Create a barcode with the given options.
        list         List available image and code types.

    Image output enabled, use --type option to give image format (png, jpeg, ...).
    $

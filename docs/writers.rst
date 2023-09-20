Writers
=======

Common Writer Options
---------------------

All writer take the following options (specified as keyword arguments to
``Barcode.save(filename, options)`` or set via ``Writer.set_options(options)``, where
``options`` is a dictionary where keys are option names and values are option values to
be set).

.. note::
   See the documentation of the specific writer for special options,
   only available for this writer.

:module_width:
    The width of one barcode module in mm as *float*.
    Defaults to **0.2**.

:module_height:
    The height of the barcode modules in mm as *float*.
    Defaults to **15.0**.

:quiet_zone:
    Distance on the left and on the right from the border to the first
    (last) barcode module in mm as *float*.
    Defaults to **6.5**.

:font_path:
    Path to the font file to be used. Defaults to **DejaVuSansMono** (which
    is bundled with this package).

:font_size:
    Font size of the text under the barcode in pt as *integer*.
    Font size zero suppresses text.
    Defaults to **10**.

:text_distance:
    Distance between the barcode and the text under it in mm as *float*.
    Defaults to **5.0**.

:background:
    The background color of the created barcode as *string*.
    Defaults to **white**.

:foreground:
    The foreground and text color of the created barcode as *string*.
    Defaults to **black**.

:center_text:
    If true (the default) the text is centered under the barcode else
    left aligned.

    .. versionadded:: 0.6

.. note::
   Some barcode classes change the above defaults to fit in some kind
   of specification.

BaseWriter
----------

Both ``ImageWriter`` and ``SVGWriter`` are subclasses of ``BaseWriter``:

.. autoclass:: barcode.writer.BaseWriter
   :members:

SVGWriter
---------

Renders barcodes as [optionally, compressed] SVG objects.

In addition to the common writer options you can give the following
special option.

:compress:
    Boolean value to output a compressed SVG object (.svgz).
    Defaults to ``False``

ImageWriter
-----------

.. versionadded:: 0.4b1

Renders barcodes as image. Supports all the image formats supported by Pillow.

In addition to the common writer options you can give the following special options:

:format:
    The image file format as ``str``. All formats supported by Pillow are
    valid (e.g. PNG, JPEG, BMP, ...).  Defaults to ``PNG``.

:dpi:
    DPI as ``int`` to calculate the image size in pixel. This value is
    used for all mm to px calculations.
    Defaults to ``300``

Custom writers
--------------

It's possible to create your own writer by inheriting from ``barcode.writer.BaseWriter``.

In your ``__init__`` method call BaseWriter's ``__init__`` and give your callbacks for:

 - ``initialize(raw_code)``
 - ``paint_module(xpos, ypos, width, color)``
 - ``paint_text(xpos, ypos)``
 - ``finish()``

Now instantiate a new barcode and give an instance of your new writer as argument. If
you now call ``render`` on the barcode instance your callbacks get called.

Creating compressed SVGs
------------------------

Saving a compressed SVG (SVGZ):

.. code:: pycon

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

Now you have ``ean13.svg`` and the compressed ``ean13.svgz`` in your current
working directory. Open it and see the result.

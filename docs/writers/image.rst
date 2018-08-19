pyBarcode ImageWriter
=====================

.. versionadded:: 0.4b1

Creates barcodes as image. All imagetypes supported by Pillow are availble.

Special Options
---------------

In addition to the common writer options you can give the following
special options.

Special Options:
~~~~~~~~~~~~~~~~

:format:
    The image file format as *string*. All formats supported by Pillow are
    valid (e.g. PNG, JPEG, BMP, ...).
    Defaults to **PNG**.

:dpi:
    DPI as *integer* to calculate the image size in pixel. This value is
    used for all mm to px calculations.
    Defaults to **300**.


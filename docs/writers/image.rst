pyBarcode ImageWriter
=====================

Creates barcodes as image. All imagetypes supported by PIL are availble.

Special Options
---------------

In addition to the common writer options you can give the following
special options.

Special Options:
~~~~~~~~~~~~~~~~

:format:
    The image file format as *string*. All formats supported by PIL are
    valid (e.g. PNG, JPG, BMP, ...).
    Defaults to **PNG**.

:dpi:
    DPI as *integer* to calculate the image size in pixel. This value is
    used for all mm to px calculations.
    Defaults to **300**.


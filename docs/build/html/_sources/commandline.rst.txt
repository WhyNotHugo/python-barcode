Create barcodes from the commandline
====================================

.. versionadded:: 0.7beta4

PyBarcode ships with a little commandline script to generate barcodes
without knowing Python. The install script detects your Python version and
adds the major version number to the executable script. On Python 2 it is
called `pybarcode2` and on Python 3 `pybarcode3`. When installing in a
systemwide direction, you can have pyBarcode installed in Python 2 and 3 at
the same time without trouble.

Usage::

    $ pybarcode{2,3} create "My Text" outfile
    New barcode saved as outfile.svg.
    $ pybarcode{2,3} create -t png "My Text" outfile
    New barcode saved as outfile.png.
    $ pybarcode{2,3} create -b ean8 -t jpeg "1234567" ean8_out
    New barcode saved as ean8_out.jpg.

See `pybarcode{2,3} -h` for more options.

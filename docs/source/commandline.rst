Create barcodes from the commandline
====================================

.. versionadded:: 0.7beta4

python-barcode ships with a little commandline script to generate barcodes
without knowing Python. The install script detects your Python version and
adds the major version number to the executable script.

Usage::

    $ python-barcode create "My Text" outfile
    New barcode saved as outfile.svg.
    $ python-barcode create -t png "My Text" outfile
    New barcode saved as outfile.png.
    $ python-barcode create -b ean8 -t jpeg "1234567" ean8_out
    New barcode saved as ean8_out.jpg.

See `python-barcode -h` for more options.

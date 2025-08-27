Changelog
---------

v0.16.1
~~~~~~~
* Switch from ``setup.py`` to ``pyproject.toml``. Only affects how installation
  from source is performed, and has no runtime impact.

v0.16.0
~~~~~~~

* **Breaking** Drop support for Python 3.7 and 3.8.
* Make image DPI configurable.
* Fixed inconsistent checksum calculation when calculating the checksum
  multiple times for EAN barcodes.
* Update the documentation with some barcodes that were not previously
  documented.
* Specifying ``None`` as a background for the ``SVGWriter``, no background is
  included resulting in a transparent background.
* Do not paint text if its size would be zero, to avoid an "invalid ppem value"
  error with newer versions of Pillow.

v0.15.1
~~~~~~~

* Add missing dependency to release script.

v0.15.0
~~~~~~~

* **Breaking** Dropped support for Python 3.6 and 3.7.
* Added support for Python 3.11.
* Fixed compatibility with Pillow 10.0.
* Updated ISBN to support newer allocated ranges.
* Improved type hints.

v0.14.0
~~~~~~~

* **Breaking**: The default dimensions have changed slightly. This is so that
  the results of generating a PNG and an SVG look more alike.
* Previous versions included an empty text element for SVGs with no comment.
  This is no longer the case.
* Some internals have been improved so as to allow better subclassing.
  Subclasses of ``Barcode`` can now override ``default_writer_options`` and
  ``default_writer()``.
* A ``guardbar`` parameter has been added to EAN barcodes. This renders
  barcodes with guardars (longer bars).
* Added support for Python 3.10.
* The documentation setup has been redone, hopefully squashing a lot of legacy
  quirks.
* Previous versions installed the `tests` module. This was not intentional and
  have been fixed.

v0.13.1
~~~~~~~

* Fix a crash when using the ``generate`` shortcut function.

v0.13.0
~~~~~~~

* Added support for transparent backgrounds. This is done by setting the ``mode`` option
  for a writer to ``RGBA``.
* Dropped support for Python 3.5.
* Added support for Python 3.9.

v0.12.0
~~~~~~~

* Removed ``writer_options`` from ``barcode.get``. This parameter was not used.
* Add a ``with_doctype`` flag to ``SVGWriter``. Set this to false to avoid including a
  ``DOCTYPE`` in the resulting SVG.
* Add support for ``Pillow>=8.0.0``.

v0.11.0
~~~~~~~

* Added basic support for multiline text.
* Dropped lots of older compat-only code and other cleanups.
* Fixed a bug in the API when combining certain barcodes and writers.
* Published documentation again and updated all project references.
* Fix python_barcode.get mixups between `options` as `writer_options`.
  Previously, some writer/barcode combinations worked fine, while others
  failed. Now all work consistently.
* The cli tool has been fixed and should now work as expected again.

v0.10.0
~~~~~~~

* Added support for GS1-128.

v0.9.1
~~~~~~

* Officially support Python 3.7
* Refer to Pillow in the docs, rather than PIL.

v0.9.0
~~~~~~

* Removed buggy ``Barcode.raw`` attribute.
* Various CLI errors ironed out.
* Make the default value for ``writer_options``` consistent across writers.

v0.8.3
~~~~~~

* Fix pushing of releases to GitHub.

v0.8.2
~~~~~~

* Fix crashes when attempting to use the CLI app.
* Properly include version numbers in SVG comments.

v0.8.1
~~~~~~
* Improve README rendering, and point to this fork's location (the outdated
  README on PyPI was causing some confusion).

v0.8.0
~~~~~~
* First release under the name ``python-barcode``.

Previous Changelog
------------------

This project is a fork of pyBarcode, which, apparently, is no longer
maintained. v0.8.0 is our first release, and is the latest ``master`` from that
parent project.

v0.8
~~~~
* Code 128 added.
* Data for charsets and bars moved to subpackage barcode.charsets.
* Merged in some improvements.

v0.7
~~~~
* Fixed some issues with fontsize and fontalignment.
* Added Python 3 support. It's not well tested yet, but the tests run without
  errors with Python 3.3. Commandline script added.

v0.6
~~~~
* Changed save and write methods to take the options as a dict not as keyword
  arguments (fix this in your code). Added option to left align the text under
  the barcode. Fixed bug with EAN13 generation.

v0.5.0
~~~~~~
* Added new generate function to do all generation in one step.
* Moved writer from a subpackage to a module (this breaks some existing code).
  UPC is now rendered as real UPC, not as EAN13 with the leading "0".

v0.4.3
~~~~~~
* Fixed bug in new write method (related to PIL) and updated docs.

v0.4.2
~~~~~~
* Added write method to support file like objects as target.

v0.4.1
~~~~~~
* Bugfix release. Removed redundancy in input validation.
* EAN8 was broken. It now works as expected.

v0.4
~~~~
* Removed \*\*options from writers __init__ method. These options never had
  effect. They were always overwritten by default_options.
* New config option available: text_distance (the distance between barcode and
  text).

v0.4b2
~~~~~~
* Basic documentation included. The barcode object now has a new attribute
  called `raw` to have the rendered output without saving to disk.

v0.4b1
~~~~~~
* Support for rendering barcodes as images is implemented.  PIL is required to
  use it.

v0.3
~~~~
* Compression for SVG output now works.

v0.3b1
~~~~~~
* Writer API has changed for simple adding new (own) writers.
* SVG output is now generated with xml.dom module instead of stringformatting
  (makes it more robust).

v0.2.1
~~~~~~
* API of render changed. Now render takes keyword arguments instead of a dict.

v0.2
~~~~
* More tests added.

v0.1
~~~~
* First release.

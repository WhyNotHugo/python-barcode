"""Module: barcode.isxn

:Provided barcodes: ISBN-13, ISBN-10, ISSN

This module provides some special codes, which are no standalone barcodes.
All codes where transformed to EAN-13 barcodes. In every case, the checksum
is new calculated.

Example::

    >>> from barcode import get_barcode
    >>> ISBN = get_barcode('isbn10')
    >>> isbn = ISBN('0132354187')
    >>> isbn
    '0132354187'
    >>> isbn.get_fullcode()
    '9780132354189'
    >>> # Test with wrong checksum
    >>> isbn = ISBN('0132354180')
    >>> isbn
    '0132354187'

"""

from __future__ import annotations

from barcode.ean import EuropeanArticleNumber13
from barcode.errors import BarcodeError
from barcode.errors import WrongCountryCodeError

__docformat__ = "restructuredtext en"


class InternationalStandardBookNumber13(EuropeanArticleNumber13):
    """Initializes new ISBN-13 barcode.

    :parameters:
        isbn : String
            The isbn number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "ISBN-13"

    def __init__(self, isbn, writer=None, no_checksum=False, guardbar=False) -> None:
        isbn = isbn.replace("-", "")
        self.isbn13 = isbn
        if isbn[:3] not in ("978", "979"):
            raise WrongCountryCodeError("ISBN must start with 978 or 979.")
        if isbn[:3] == "979" and isbn[3:4] not in ("1", "8"):
            raise BarcodeError("ISBN must start with 97910 or 97911.")
        super().__init__(isbn, writer, no_checksum, guardbar)


class InternationalStandardBookNumber10(InternationalStandardBookNumber13):
    """Initializes new ISBN-10 barcode. This code is rendered as EAN-13 by
    prefixing it with 978.

    :parameters:
        isbn : String
            The isbn number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "ISBN-10"

    isbn_digits = 9

    def __init__(self, isbn, writer=None) -> None:
        isbn = isbn.replace("-", "")[:self.isbn_digits]
        self.isbn10 = f"{isbn}{self._calculate_checksum(isbn)}"
        super().__init__("978" + isbn, writer)

    def _calculate_checksum(self, isbn):
        tmp = sum(x * int(y) for x, y in enumerate(isbn[:self.isbn_digits], start=1)) % 11
        if tmp == 10:
            return "X"

        return tmp

    def __str__(self) -> str:
        return self.isbn10


class InternationalStandardSerialNumber(EuropeanArticleNumber13):
    """Initializes new ISSN barcode. This code is rendered as EAN-13
    by prefixing it with 977 and adding 00 between code and checksum.

    :parameters:
        issn : String
            The issn number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "ISSN"

    issn_digits = 7

    def __init__(self, issn, writer=None) -> None:
        issn = issn.replace("-", "")[: self.issn_digits]
        self.issn = f"{issn}{self._calculate_checksum(issn)}"
        super().__init__(f"977{issn}00", writer) #checksum is overwritten by on .build


    def _calculate_checksum(self, issn):
        tmp = (
            11
            - sum(x * int(y) for x, y in enumerate(reversed(issn[:self.issn_digits]), start=2))
            % 11
        )
        if tmp == 10:
            return "X"

        return tmp

    def __str__(self) -> str:
        return self.issn


# Shortcuts
ISBN13 = InternationalStandardBookNumber13
ISBN10 = InternationalStandardBookNumber10
ISSN = InternationalStandardSerialNumber

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
from barcode.errors import WrongCountryCodeError

__docformat__ = "restructuredtext en"


class InternationalStandardBookNumber13(EuropeanArticleNumber13):
    """Initializes new ISBN-13 barcode.

    :parameters:
        isbn : String
            The isbn number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        addon : String
            Optional 2 or 5 digit addon (EAN-2 or EAN-5). Commonly used for
            prices (EAN-5).
    """

    name = "ISBN-13"

    def __init__(
        self, isbn, writer=None, no_checksum=False, guardbar=False, addon=None
    ) -> None:
        isbn = isbn.replace("-", "")
        self.isbn13 = isbn
        if isbn[:3] not in ("978", "979"):
            raise WrongCountryCodeError("ISBN must start with 978 or 979.")
        super().__init__(isbn, writer, no_checksum, guardbar, addon)


class InternationalStandardBookNumber10(InternationalStandardBookNumber13):
    """Initializes new ISBN-10 barcode. This code is rendered as EAN-13 by
    prefixing it with 978.

    :parameters:
        isbn : String
            The isbn number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        addon : String
            Optional 2 or 5 digit addon (EAN-2 or EAN-5). Commonly used for
            prices (EAN-5).
    """

    name = "ISBN-10"

    isbn10_digits = 9

    def __init__(self, isbn, writer=None, addon=None) -> None:
        isbn = isbn.replace("-", "")
        isbn = isbn[: self.isbn10_digits]
        super().__init__("978" + isbn, writer, addon=addon)
        self.isbn10 = isbn
        self.isbn10 = f"{isbn}{self._calculate_checksum()}"

    def _calculate_checksum(self):
        tmp = sum(x * int(y) for x, y in enumerate(self.isbn10[:9], start=1)) % 11
        if tmp == 10:
            return "X"

        return tmp

    def __str__(self) -> str:
        if self.addon:
            return f"{self.isbn10} {self.addon}"
        return self.isbn10


class InternationalStandardSerialNumber(EuropeanArticleNumber13):
    """Initializes new ISSN barcode. This code is rendered as EAN-13
    by prefixing it with 977.

    The ISSN can be provided in short form (7-8 digits) or full EAN-13 form
    (13 digits starting with 977). When provided in short form, digits 11-12
    default to "00". When provided in full form, digits 11-12 are preserved.

    :parameters:
        issn : String
            The issn number as string. Can be 7-8 digits (short form) or
            13 digits starting with 977 (full EAN-13 form).
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
        addon : String
            Optional 2 or 5 digit addon (EAN-2 or EAN-5). Commonly used for
            issue numbers (EAN-2) or prices (EAN-5).
    """

    name = "ISSN"

    issn_digits = 7

    def __init__(self, issn, writer=None, addon=None) -> None:
        issn = issn.replace("-", "")
        # Handle full EAN-13 form (13 digits starting with 977)
        if len(issn) >= 12 and issn.startswith("977"):
            self._sequence_digits = issn[10:12]
            issn = issn[3:10]
        else:
            self._sequence_digits = "00"
            issn = issn[: self.issn_digits]
        self.issn = issn
        self.issn = f"{issn}{self._calculate_checksum()}"
        super().__init__(self.make_ean(), writer, addon=addon)

    def _calculate_checksum(self):
        tmp = (
            11
            - sum(x * int(y) for x, y in enumerate(reversed(self.issn[:7]), start=2))
            % 11
        )
        if tmp == 10:
            return "X"

        return tmp

    def make_ean(self):
        # Return 12 digits: 977 + 7 ISSN digits + 2 sequence digits
        # EAN-13 will calculate and append the 13th digit (EAN checksum)
        return f"977{self.issn[:7]}{self._sequence_digits}"

    def __str__(self) -> str:
        if self.addon:
            return f"{self.issn} {self.addon}"
        return self.issn


# Shortcuts
ISBN13 = InternationalStandardBookNumber13
ISBN10 = InternationalStandardBookNumber10
ISSN = InternationalStandardSerialNumber

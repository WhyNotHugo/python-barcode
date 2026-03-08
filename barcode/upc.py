"""Module: barcode.upc

:Provided barcodes: UPC-A
"""

from __future__ import annotations

__docformat__ = "restructuredtext en"

from functools import reduce

from barcode import addon_utils
from barcode.base import Barcode
from barcode.charsets import upc as _upc
from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError


class UniversalProductCodeA(Barcode):
    """Universal Product Code (UPC) barcode.

    UPC-A consists of 12 numeric digits.
    """

    name = "UPC-A"

    digits = 11

    def __init__(
        self,
        upc: str,
        writer=None,
        make_ean: bool = False,
        addon: str | None = None,
    ) -> None:
        """Initializes new UPC-A barcode.

        :param str upc: The upc number as string.
        :param writer: barcode.writer instance. The writer to render the
            barcode (default: SVGWriter).
        :param bool make_ean: Indicates if a leading zero should be added to
            the barcode. This converts the UPC into a valid European Article
            Number (EAN).
        :param addon: Optional 2 or 5 digit addon (EAN-2 or EAN-5).
        """
        self.ean = make_ean
        upc = upc[: self.digits]
        if not upc.isdigit():
            raise IllegalCharacterError("UPC code can only contain numbers.")
        if len(upc) != self.digits:
            raise NumberOfDigitsError(
                f"UPC must have {self.digits} digits, not {len(upc)}."
            )
        self.upc = upc
        self.upc = f"{upc}{self.calculate_checksum()}"

        # Validate and store addon
        self.addon: str | None = None
        if addon is not None:
            addon = addon.strip()
            if addon:
                if not addon.isdigit():
                    raise IllegalCharacterError(
                        f"Addon can only contain numbers, got {addon}."
                    )
                if len(addon) not in (2, 5):
                    raise NumberOfDigitsError(
                        f"Addon must be 2 or 5 digits, received {len(addon)}."
                    )
                self.addon = addon

        self.writer = writer or self.default_writer()

    def __str__(self) -> str:
        base = "0" + self.upc if self.ean else self.upc
        if self.addon:
            return f"{base} {self.addon}"
        return base

    def get_fullcode(self):
        base = "0" + self.upc if self.ean else self.upc
        if self.addon:
            return f"{base} {self.addon}"
        return base

    def calculate_checksum(self):
        """Calculates the checksum for UPCA/UPC codes

        :return: The checksum for 'self.upc'
        :rtype: int
        """

        def sum_(x, y):
            return int(x) + int(y)

        upc = self.upc[0 : self.digits]
        oddsum = reduce(sum_, upc[::2])
        evensum = reduce(sum_, upc[1::2])
        check = (evensum + oddsum * 3) % 10
        if check == 0:
            return 0

        return 10 - check

    def build(self) -> list[str]:
        """Builds the barcode pattern from 'self.upc'

        :return: The pattern as string
        :rtype: List containing the string as a single element
        """
        code = _upc.EDGE[:]

        for number in self.upc[0:6]:
            code += _upc.CODES["L"][int(number)]

        code += _upc.MIDDLE

        for number in self.upc[6:]:
            code += _upc.CODES["R"][int(number)]

        code += _upc.EDGE

        # Add addon if present
        if self.addon:
            code += self._build_addon()

        return [code]

    def _build_addon(self) -> str:
        """Builds the addon barcode pattern (EAN-2 or EAN-5).

        :returns: The addon pattern as string (including quiet zone separator)
        """
        return addon_utils.build_addon(self.addon or "")

    def to_ascii(self) -> str:
        """Returns an ascii representation of the barcode.

        :rtype: str
        """

        code_list = self.build()
        if len(code_list) != 1:
            raise RuntimeError("Code list must contain a single element.")
        code = code_list[0]
        return code.replace("1", "|").replace("0", "_")

    def render(self, writer_options=None, text=None):
        options = {"module_width": 0.33}
        options.update(writer_options or {})
        return super().render(options, text)


UPCA = UniversalProductCodeA

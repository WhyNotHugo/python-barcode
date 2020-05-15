"""Module: barcode.upc

:Provided barcodes: UPC-A
"""
from functools import reduce
from typing import List, Union

from barcode.base import Barcode
from barcode.charsets import upc as _upc
from barcode.errors import IllegalCharacterError, NumberOfDigitsError
from barcode.writer import BaseWriter, Image


class UniversalProductCodeA(Barcode):
    """Universal Product Code (UPC) barcode.

    UPC-A consists of 12 numeric digits.
    """

    name = "UPC-A"
    digits = 11

    def __init__(self, upc: str, writer: BaseWriter = None, make_ean: bool = False):
        """Initializes new UPC-A barcode.

        :param upc: The upc number.
        :param writer: The writer to render the barcode (default: SVGWriter).
        :param make_ean: Indicates if a leading zero should be added to
            the barcode. This converts the UPC into a valid European Article
            Number (EAN).
        """
        self.ean = make_ean
        upc = upc[: self.digits]
        if not upc.isdigit():
            raise IllegalCharacterError("UPC code can only contain numbers.")
        if len(upc) != self.digits:
            raise NumberOfDigitsError(
                "UPC must have {0} digits, not " "{1}.".format(self.digits, len(upc))
            )
        self.upc = upc
        self.upc = "{}{}".format(upc, self.calculate_checksum())
        self.writer = writer or Barcode.default_writer()

    def __str__(self) -> str:
        return self.get_fullcode()

    def get_fullcode(self) -> str:
        if self.ean:
            return "0" + self.upc
        else:
            return self.upc

    def calculate_checksum(self) -> int:
        """Calculates the checksum for UPCA/UPC codes

        :return: The checksum for 'self.upc'
        :rtype: int
        """

        def sum_(x: str, y: str) -> int:
            return int(x) + int(y)

        upc = self.upc[0: self.digits]
        oddsum: int = reduce(sum_, upc[::2])  # type: ignore
        evensum: int = reduce(sum_, upc[1::2])  # type: ignore
        check = (evensum + oddsum * 3) % 10
        if check == 0:
            return 0
        else:
            return 10 - check

    def build(self) -> List[str]:
        """Builds the barcode pattern from `self.upc`.

        :return: The pattern as string.
        """
        code = _upc.EDGE[:]

        for _i, number in enumerate(self.upc[0:6]):
            code += _upc.CODES["L"][int(number)]

        code += _upc.MIDDLE

        for number in self.upc[6:]:
            code += _upc.CODES["R"][int(number)]

        code += _upc.EDGE

        return [code]

    def to_ascii(self) -> str:
        """Returns an ascii representation of the barcode."""

        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace("1", "|").replace("0", "_")
        return "\n".join(code)

    def render(self, writer_options=None, text=None) -> Union[bytes, Image]:
        options = {"module_width": 0.33}
        options.update(writer_options or {})
        return Barcode.render(self, options, text)


UPCA = UniversalProductCodeA

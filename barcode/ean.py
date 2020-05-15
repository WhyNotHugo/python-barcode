"""Module: barcode.ean

:Provided barcodes: EAN-14, EAN-13, EAN-8, JAN
"""
from functools import reduce
from typing import List, Union

from barcode.base import Barcode
from barcode.charsets import ean as _ean
from barcode.errors import (
    IllegalCharacterError,
    NumberOfDigitsError,
    WrongCountryCodeError,
)
from barcode.writer import BaseWriter, Image


# EAN13 Specs (all sizes in mm)
SIZES = {
    "SC0": 0.27,
    "SC1": 0.297,
    "SC2": 0.33,
    "SC3": 0.363,
    "SC4": 0.396,
    "SC5": 0.445,
    "SC6": 0.495,
    "SC7": 0.544,
    "SC8": 0.61,
    "SC9": 0.66,
}


class EuropeanArticleNumber13(Barcode):
    name = "EAN-13"
    digits = 12

    def __init__(self, ean: str, writer: BaseWriter = None, no_checksum: bool = False):
        """Initializes a EAN13 barcode object.

        :param ean: The ean number as string.
        :param writer: The writer to render the barcode (default: SVGWriter).
        """

        ean = ean[: self.digits]
        if not ean.isdigit():
            raise IllegalCharacterError("EAN code can only contain numbers.")
        if len(ean) != self.digits:
            raise NumberOfDigitsError(
                "EAN must have {0} digits, not {1}.".format(self.digits, len(ean),)
            )
        self.ean = ean
        # If no checksum
        if no_checksum:
            # Add a thirteen char if given in parameter,
            # otherwise pad with zero
            self.ean = "{0}{1}".format(
                ean, ean[self.digits] if len(ean) > self.digits else 0
            )
        else:
            self.ean = "{0}{1}".format(ean, self.calculate_checksum())
        self.writer = writer or Barcode.default_writer()

    def __str__(self) -> str:
        return self.ean

    def get_fullcode(self) -> str:
        return self.ean

    def calculate_checksum(self) -> int:
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """

        def sum_(x, y):
            return int(x) + int(y)

        evensum: int = reduce(sum_, self.ean[-2::-2])  # type: ignore
        oddsum: int = reduce(sum_, self.ean[-1::-2])  # type: ignore
        return (10 - ((evensum + oddsum * 3) % 10)) % 10

    def build(self) -> List[str]:
        """Builds and returns the barcode pattern as a string."""
        code = _ean.EDGE[:]
        pattern = _ean.LEFT_PATTERN[int(self.ean[0])]
        for i, number in enumerate(self.ean[1:7]):
            code += _ean.CODES[pattern[i]][int(number)]
        code += _ean.MIDDLE
        for number in self.ean[7:]:
            code += _ean.CODES["C"][int(number)]
        code += _ean.EDGE
        return [code]

    def to_ascii(self) -> str:
        """Returns an ascii representation of the barcode."""
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace("1", "|").replace("0", " ")
        return "\n".join(code)

    def render(self, writer_options=None, text=None) -> Union[bytes, Image]:
        options = {"module_width": SIZES["SC2"]}
        options.update(writer_options or {})
        return Barcode.render(self, options, text)


class JapanArticleNumber(EuropeanArticleNumber13):
    """Initializes JAN barcode. See EuropeanArticleNumber13 for details."""

    name = "JAN"
    valid_country_codes = list(range(450, 460)) + list(range(490, 500))

    def __init__(self, jan: str, writer: BaseWriter = None):
        if int(jan[:3]) not in JapanArticleNumber.valid_country_codes:
            raise WrongCountryCodeError(
                "Country code isn't between 450-460 or 490-500."
            )
        EuropeanArticleNumber13.__init__(self, jan, writer)


class EuropeanArticleNumber8(EuropeanArticleNumber13):
    """Represents an EAN-8 barcode. See EuropeanArticleNumber13 for details."""

    name = "EAN-8"
    digits = 7

    def __init__(self, ean: str, writer=None):
        EuropeanArticleNumber13.__init__(self, ean, writer)

    def build(self) -> List[str]:
        """Builds the barcode pattern from `self.ean`."""
        code = _ean.EDGE[:]
        for number in self.ean[:4]:
            code += _ean.CODES["A"][int(number)]
        code += _ean.MIDDLE
        for number in self.ean[4:]:
            code += _ean.CODES["C"][int(number)]
        code += _ean.EDGE
        return [code]


class EuropeanArticleNumber14(EuropeanArticleNumber13):
    """Represents an EAN-14 barcode. `EuropeanArticleNumber13` for details."""

    name = "EAN-14"
    digits = 13

    def calculate_checksum(self) -> int:
        """Calculates the checksum for EAN13-Code."""

        def sum_(x, y):
            return int(x) + int(y)

        evensum: int = reduce(sum_, self.ean[::2])  # type: ignore
        oddsum: int = reduce(sum_, self.ean[1::2])  # type: ignore
        return (10 - (((evensum * 3) + oddsum) % 10)) % 10


# Shortcuts
EAN14 = EuropeanArticleNumber14
EAN13 = EuropeanArticleNumber13
EAN8 = EuropeanArticleNumber8
JAN = JapanArticleNumber

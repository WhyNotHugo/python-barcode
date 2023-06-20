"""Module: barcode.ean

:Provided barcodes: EAN-14, EAN-13, EAN-8, JAN
"""
__docformat__ = "restructuredtext en"

from functools import reduce

from barcode.base import Barcode
from barcode.charsets import ean as _ean
from barcode.errors import IllegalCharacterError
from barcode.errors import NumberOfDigitsError
from barcode.errors import WrongCountryCodeError

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
    """Initializes EAN13 object.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "EAN-13"

    digits = 12

    def __init__(self, ean, writer=None, no_checksum=False, guardbar=False) -> None:
        ean = ean[: self.digits]
        if not ean.isdigit():
            raise IllegalCharacterError("EAN code can only contain numbers.")
        if len(ean) != self.digits:
            raise NumberOfDigitsError(
                "EAN must have {} digits, not {}.".format(
                    self.digits,
                    len(ean),
                )
            )
        self.ean = ean
        # If no checksum
        if no_checksum:
            # Add a thirteen char if given in parameter,
            # otherwise pad with zero
            self.ean = "{}{}".format(
                ean, ean[self.digits] if len(ean) > self.digits else 0
            )
        else:
            self.ean = f"{ean}{self.calculate_checksum()}"

        self.guardbar = guardbar
        if guardbar:
            self.EDGE = _ean.EDGE.replace("1", "G")
            self.MIDDLE = _ean.MIDDLE.replace("1", "G")
        else:
            self.EDGE = _ean.EDGE
            self.MIDDLE = _ean.MIDDLE
        self.writer = writer or self.default_writer()

    def __str__(self) -> str:
        return self.ean

    def get_fullcode(self):
        if self.guardbar:
            return self.ean[0] + " " + self.ean[1:7] + " " + self.ean[7:] + " >"
        return self.ean

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """

        def sum_(x, y):
            return int(x) + int(y)

        evensum = reduce(sum_, self.ean[-2::-2])
        oddsum = reduce(sum_, self.ean[-1::-2])
        return (10 - ((evensum + oddsum * 3) % 10)) % 10

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as string
        :rtype: String
        """
        code = self.EDGE[:]
        pattern = _ean.LEFT_PATTERN[int(self.ean[0])]
        for i, number in enumerate(self.ean[1:7]):
            code += _ean.CODES[pattern[i]][int(number)]
        code += self.MIDDLE
        for number in self.ean[7:]:
            code += _ean.CODES["C"][int(number)]
        code += self.EDGE
        return [code]

    def to_ascii(self):
        """Returns an ascii representation of the barcode.

        :rtype: String
        """
        code = self.build()
        for i, line in enumerate(code):
            code[i] = line.replace("G", "|").replace("1", "|").replace("0", " ")
        return "\n".join(code)

    def render(self, writer_options=None, text=None):
        options = {"module_width": SIZES["SC2"]}
        options.update(writer_options or {})
        return super().render(options, text)


class EuropeanArticleNumber13WithGuard(EuropeanArticleNumber13):
    name = "EAN-13 with guards"

    def __init__(self, ean, writer=None, no_checksum=False, guardbar=True) -> None:
        super().__init__(ean, writer, no_checksum, guardbar)


class JapanArticleNumber(EuropeanArticleNumber13):
    """Initializes JAN barcode.

    :parameters:
        jan : String
            The jan number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "JAN"

    valid_country_codes = list(range(450, 460)) + list(range(490, 500))

    def __init__(self, jan, *args, **kwargs) -> None:
        if int(jan[:3]) not in self.valid_country_codes:
            raise WrongCountryCodeError(
                "Country code isn't between 450-460 or 490-500."
            )
        super().__init__(jan, *args, **kwargs)


class EuropeanArticleNumber8(EuropeanArticleNumber13):
    """Represents an EAN-8 barcode. See EAN13's __init__ for details.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "EAN-8"

    digits = 7

    def build(self):
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as string
        :rtype: String
        """
        code = self.EDGE[:]
        for number in self.ean[:4]:
            code += _ean.CODES["A"][int(number)]
        code += self.MIDDLE
        for number in self.ean[4:]:
            code += _ean.CODES["C"][int(number)]
        code += self.EDGE
        return [code]

    def get_fullcode(self):
        if self.guardbar:
            return "< " + self.ean[:4] + " " + self.ean[4:] + " >"
        return self.ean


class EuropeanArticleNumber8WithGuard(EuropeanArticleNumber8):
    name = "EAN-8 with guards"

    def __init__(self, ean, writer=None, no_checksum=False, guardbar=True) -> None:
        super().__init__(ean, writer, no_checksum, guardbar)


class EuropeanArticleNumber14(EuropeanArticleNumber13):
    """Represents an EAN-14 barcode. See EAN13's __init__ for details.

    :parameters:
        ean : String
            The ean number as string.
        writer : barcode.writer Instance
            The writer to render the barcode (default: SVGWriter).
    """

    name = "EAN-14"
    digits = 13

    def calculate_checksum(self):
        """Calculates the checksum for EAN13-Code.

        :returns: The checksum for `self.ean`.
        :rtype: Integer
        """

        def sum_(x, y):
            return int(x) + int(y)

        evensum = reduce(sum_, self.ean[::2])
        oddsum = reduce(sum_, self.ean[1::2])
        return (10 - (((evensum * 3) + oddsum) % 10)) % 10


# Shortcuts
EAN14 = EuropeanArticleNumber14
EAN13 = EuropeanArticleNumber13
EAN13_GUARD = EuropeanArticleNumber13WithGuard
EAN8 = EuropeanArticleNumber8
EAN8_GUARD = EuropeanArticleNumber8WithGuard
JAN = JapanArticleNumber

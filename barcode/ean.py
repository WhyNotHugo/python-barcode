"""Module: barcode.ean

:Provided barcodes: EAN-14, EAN-13, EAN-8, JAN
"""

from __future__ import annotations

__docformat__ = "restructuredtext en"


from barcode import addon_utils
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

    :param ean: The ean number as string. If the value is too long, it is trimmed.
    :param writer: The writer to render the barcode (default: SVGWriter).
    :param no_checksum: Don't calculate the checksum. Use the provided input instead.
    :param guardbar: If True, use guard bar markers in the output.
    :param addon: Optional 2 or 5 digit addon (EAN-2 or EAN-5).
    """

    name = "EAN-13"

    digits = 12

    def __init__(
        self,
        ean: str,
        writer=None,
        no_checksum: bool = False,
        guardbar: bool = False,
        addon: str | None = None,
    ) -> None:
        if not ean[: self.digits].isdigit():
            raise IllegalCharacterError(f"EAN code can only contain numbers {ean}.")

        if len(ean) < self.digits:
            raise NumberOfDigitsError(
                f"EAN must have {self.digits} digits, received {len(ean)}."
            )

        base = ean[: self.digits]
        if no_checksum:
            # Use the thirteenth digit if given in parameter, otherwise pad with zero
            if len(ean) > self.digits and ean[self.digits].isdigit():
                last = int(ean[self.digits])
            else:
                last = 0
        else:
            last = self.calculate_checksum(base)

        self.ean = f"{base}{last}"

        # Validate and store addon
        self.addon = None
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

        self.guardbar = guardbar
        if guardbar:
            self.EDGE = _ean.EDGE.replace("1", "G")
            self.MIDDLE = _ean.MIDDLE.replace("1", "G")
        else:
            self.EDGE = _ean.EDGE
            self.MIDDLE = _ean.MIDDLE
        self.writer = writer or self.default_writer()

    def __str__(self) -> str:
        if self.addon:
            return f"{self.ean} {self.addon}"
        return self.ean

    def get_fullcode(self) -> str:
        addon = "" if not self.addon else f" {self.addon}"
        if self.guardbar:
            return self.ean[0] + " " + self.ean[1:7] + " " + self.ean[7:] + addon + " >"
        return f"{self.ean}{addon}"

    def calculate_checksum(self, value: str | None = None) -> int:
        """Calculates and returns the checksum for EAN13-Code.

        Calculates the checksum for the supplied `value` (if any) or for this barcode's
        internal ``self.ean`` property.
        """

        ean_without_checksum = value or self.ean[: self.digits]

        evensum = sum(int(x) for x in ean_without_checksum[-2::-2])
        oddsum = sum(int(x) for x in ean_without_checksum[-1::-2])
        return (10 - ((evensum + oddsum * 3) % 10)) % 10

    def build(self) -> list[str]:
        """Builds the barcode pattern from `self.ean`.

        :returns: The pattern as string
        :rtype: List containing the string as a single element
        """
        code = self.EDGE[:]
        pattern = _ean.LEFT_PATTERN[int(self.ean[0])]
        for i, number in enumerate(self.ean[1:7]):
            code += _ean.CODES[pattern[i]][int(number)]
        code += self.MIDDLE
        for number in self.ean[7:]:
            code += _ean.CODES["C"][int(number)]
        code += self.EDGE

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

        :rtype: String
        """
        code_list = self.build()
        if not len(code_list) == 1:
            raise RuntimeError("Code list must contain a single element.")
        code = code_list[0]
        return code.replace("G", "|").replace("1", "|").replace("0", " ")

    def render(self, writer_options: dict | None = None, text: str | None = None):
        options = {"module_width": SIZES["SC2"]}
        options.update(writer_options or {})
        return super().render(options, text)


class EuropeanArticleNumber13WithGuard(EuropeanArticleNumber13):
    """A shortcut to EAN-13 with ``guardbar=True``."""

    name = "EAN-13 with guards"

    def __init__(
        self, ean, writer=None, no_checksum=False, guardbar=True, addon=None
    ) -> None:
        super().__init__(ean, writer, no_checksum, guardbar, addon)


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

    :param ean: The ean number as string.
    :param writer: The writer to render the barcode (default: SVGWriter).
    :param addon: Optional 2 or 5 digit addon (EAN-2 or EAN-5).
    """

    name = "EAN-8"

    digits = 7

    def build(self) -> list[str]:
        """Builds the barcode pattern from `self.ean`.

        :returns: A list containing the string as a single element
        """
        code = self.EDGE[:]
        for number in self.ean[:4]:
            code += _ean.CODES["A"][int(number)]
        code += self.MIDDLE
        for number in self.ean[4:]:
            code += _ean.CODES["C"][int(number)]
        code += self.EDGE

        # Add addon if present
        if self.addon:
            code += self._build_addon()

        return [code]

    def get_fullcode(self):
        addon = "" if not self.addon else f" {self.addon}"
        if self.guardbar:
            return "< " + self.ean[:4] + " " + self.ean[4:] + addon + " >"
        return f"{self.ean}{addon}"


class EuropeanArticleNumber8WithGuard(EuropeanArticleNumber8):
    """A shortcut to EAN-8 with ``guardbar=True``."""

    name = "EAN-8 with guards"

    def __init__(
        self,
        ean: str,
        writer=None,
        no_checksum: bool = False,
        guardbar: bool = True,
        addon: str | None = None,
    ) -> None:
        super().__init__(ean, writer, no_checksum, guardbar, addon)


class EuropeanArticleNumber14(EuropeanArticleNumber13):
    """Represents an EAN-14 barcode. See EAN13's __init__ for details.

    :param ean: The ean number as string.
    :param writer: The writer to render the barcode (default: SVGWriter).
    :param no_checksum: Don't calculate the checksum. Use the provided input instead.
    """

    name = "EAN-14"
    digits = 13

    def calculate_checksum(self, value: str | None = None) -> int:
        """Calculates and returns the checksum for EAN14-Code.

        Calculates the checksum for the supplied `value` (if any) or for this barcode's
        internal ``self.ean`` property.
        """

        ean_without_checksum = value or self.ean[: self.digits]

        evensum = sum(int(x) for x in ean_without_checksum[::2])
        oddsum = sum(int(x) for x in ean_without_checksum[1::2])
        return (10 - (((evensum * 3) + oddsum) % 10)) % 10


# Shortcuts
EAN14 = EuropeanArticleNumber14
EAN13 = EuropeanArticleNumber13
EAN13_GUARD = EuropeanArticleNumber13WithGuard
EAN8 = EuropeanArticleNumber8
EAN8_GUARD = EuropeanArticleNumber8WithGuard
JAN = JapanArticleNumber

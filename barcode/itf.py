"""Module: barcode.itf

:Provided barcodes: Interleaved 2 of 5
"""

from __future__ import annotations

__docformat__ = "restructuredtext en"

from typing import TYPE_CHECKING

from barcode.base import Barcode
from barcode.charsets import itf
from barcode.errors import IllegalCharacterError

if TYPE_CHECKING:
    from PIL.Image import Image as T_Image

    from barcode.writer import BaseWriter

MIN_SIZE = 0.2
MIN_QUIET_ZONE = 6.4


class ITF(Barcode):
    """Initializes a new ITF instance.

    :param code: ITF (Interleaved 2 of 5) numeric string
    :param writer: The writer to render the barcode (default: SVGWriter).
    :param narrow: Width of the narrow elements (default: 2)
    :param wide: Width of the wide elements (default: 5).
        wide/narrow must be in the range 2..3
    """

    name = "ITF"

    def __init__(
        self,
        code: str,
        writer: BaseWriter | None = None,
        narrow: int = 2,
        wide: int = 5,
    ) -> None:
        if not code.isdigit():
            raise IllegalCharacterError("ITF code can only contain numbers.")
        # Length must be even, prepend 0 if necessary
        if len(code) % 2 != 0:
            code = "0" + code
        self.code = code
        self.writer = writer or self.default_writer()
        self.narrow = narrow
        self.wide = wide

    def __str__(self) -> str:
        return self.code

    def get_fullcode(self) -> str:
        return self.code

    def build(self) -> list[str]:
        data = itf.START
        for i in range(0, len(self.code), 2):
            bars_digit = int(self.code[i])
            spaces_digit = int(self.code[i + 1])
            for j in range(5):
                data += itf.CODES[bars_digit][j].upper()
                data += itf.CODES[spaces_digit][j].lower()
        data += itf.STOP
        raw = ""
        for e in data:
            if e == "W":
                raw += "1" * self.wide
            if e == "w":
                raw += "0" * self.wide
            if e == "N":
                raw += "1" * self.narrow
            if e == "n":
                raw += "0" * self.narrow
        return [raw]

    def render(
        self,
        writer_options: dict | None = None,
        text: str | None = None,
    ) -> bytes | T_Image:
        options = {
            "module_width": MIN_SIZE / self.narrow,
            "quiet_zone": MIN_QUIET_ZONE,
        }
        options.update(writer_options or {})
        return super().render(options, text)

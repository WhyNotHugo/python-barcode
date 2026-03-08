from __future__ import annotations

from barcode.charsets.addons import ADDON2_PARITY
from barcode.charsets.addons import ADDON5_PARITY
from barcode.charsets.addons import ADDON_QUIET_ZONE
from barcode.charsets.addons import ADDON_SEPARATOR
from barcode.charsets.addons import ADDON_START

# Note: Addon codes are defined in barcode.charsets.addons, but they use the
# same A/B digit encodings as CODES["A"] and CODES["B"] defined below.
EDGE = "101"
MIDDLE = "01010"
CODES = {
    "A": (
        "0001101",
        "0011001",
        "0010011",
        "0111101",
        "0100011",
        "0110001",
        "0101111",
        "0111011",
        "0110111",
        "0001011",
    ),
    "B": (
        "0100111",
        "0110011",
        "0011011",
        "0100001",
        "0011101",
        "0111001",
        "0000101",
        "0010001",
        "0001001",
        "0010111",
    ),
    "C": (
        "1110010",
        "1100110",
        "1101100",
        "1000010",
        "1011100",
        "1001110",
        "1010000",
        "1000100",
        "1001000",
        "1110100",
    ),
}
LEFT_PATTERN = (
    "AAAAAA",
    "AABABB",
    "AABBAB",
    "AABBBA",
    "ABAABB",
    "ABBAAB",
    "ABBBAA",
    "ABABAB",
    "ABABBA",
    "ABBABA",
)

# Re-export addon constants for backwards compatibility
__all__ = [
    "ADDON2_PARITY",
    "ADDON5_PARITY",
    "ADDON_QUIET_ZONE",
    "ADDON_SEPARATOR",
    "ADDON_START",
    "CODES",
    "EDGE",
    "LEFT_PATTERN",
    "MIDDLE",
]

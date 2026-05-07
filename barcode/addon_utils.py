"""Utility functions for building EAN-2 and EAN-5 addon barcodes.

This module provides shared functionality for addon barcode generation
used by EAN and UPC barcode classes.
"""

from __future__ import annotations

from barcode.charsets.addons import ADDON2_PARITY
from barcode.charsets.addons import ADDON5_PARITY
from barcode.charsets.addons import ADDON_CODES
from barcode.charsets.addons import ADDON_QUIET_ZONE
from barcode.charsets.addons import ADDON_SEPARATOR
from barcode.charsets.addons import ADDON_START


def build_addon(addon: str) -> str:
    """Build the complete addon barcode pattern (EAN-2 or EAN-5).

    :param addon: The addon digits (2 or 5 digits)
    :returns: The addon pattern as string (including quiet zone separator)
    """
    if not addon:
        return ""

    # Add quiet zone (9 modules) before addon per GS1 specification
    code = ADDON_QUIET_ZONE

    if len(addon) == 2:
        code += build_addon2(addon)
    else:
        code += build_addon5(addon)

    return code


def build_addon2(addon: str) -> str:
    """Build EAN-2 addon pattern.

    Parity is determined by the 2-digit value mod 4.

    :param addon: The 2-digit addon string
    :returns: The EAN-2 addon pattern (using 'A' for addon bars)
    """
    value = int(addon)
    parity = ADDON2_PARITY[value % 4]

    code = ADDON_START
    for i, digit in enumerate(addon):
        if i > 0:
            code += ADDON_SEPARATOR
        code += ADDON_CODES[parity[i]][int(digit)]

    # Replace '1' with 'A' to mark addon bars for special rendering
    return code.replace("1", "A")


def build_addon5(addon: str) -> str:
    """Build EAN-5 addon pattern.

    Parity is determined by a checksum calculation.

    :param addon: The 5-digit addon string
    :returns: The EAN-5 addon pattern (using 'A' for addon bars)
    """
    # Calculate checksum for parity pattern
    checksum = 0
    for i, digit in enumerate(addon):
        weight = 3 if i % 2 == 0 else 9
        checksum += int(digit) * weight
    checksum %= 10
    parity = ADDON5_PARITY[checksum]

    code = ADDON_START
    for i, digit in enumerate(addon):
        if i > 0:
            code += ADDON_SEPARATOR
        code += ADDON_CODES[parity[i]][int(digit)]

    # Replace '1' with 'A' to mark addon bars for special rendering
    return code.replace("1", "A")

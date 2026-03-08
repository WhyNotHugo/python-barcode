"""Common addon patterns for EAN-2 and EAN-5 supplemental barcodes.

These patterns are shared by EAN-13, EAN-8, UPC-A, and related barcode types.
Based on GS1/ISO standard.
"""

from __future__ import annotations

# Addon guard patterns
# 9-module separator between main code and addon (GS1 spec)
ADDON_QUIET_ZONE = "000000000"
ADDON_START = "1011"  # Start guard for addon
ADDON_SEPARATOR = "01"  # Separator between addon digits

# Addon digit encoding (uses A and B parity patterns)
ADDON_CODES = {
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
}

# EAN-2 parity patterns: determined by value mod 4
ADDON2_PARITY = (
    "AA",  # 0
    "AB",  # 1
    "BA",  # 2
    "BB",  # 3
)

# EAN-5 parity patterns: determined by checksum
ADDON5_PARITY = (
    "BBAAA",  # 0
    "BABAA",  # 1
    "BAABA",  # 2
    "BAAAB",  # 3
    "ABBAA",  # 4
    "AABBA",  # 5
    "AAABB",  # 6
    "ABABA",  # 7
    "ABAAB",  # 8
    "AABAB",  # 9
)

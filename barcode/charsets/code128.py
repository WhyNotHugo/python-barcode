import string

# Charsets for code 128

_common = (
    (
        " ",
        "!",
        '"',
        "#",
        "$",
        "%",
        "&",
        "'",
        "(",
        ")",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
    )
    + tuple(string.digits)
    + (
        ":",
        ";",
        "<",
        "=",
        ">",
        "?",
        "@",
    )
    + tuple(string.ascii_uppercase)
    + (
        "[",
        "\\",
        "]",
        "^",
        "_",
    )
)

_charset_a = _common + (
    "\x00",
    "\x01",
    "\x02",
    "\x03",
    "\x04",
    "\x05",
    "\x06",
    "\x07",
    "\x08",
    "\x09",
    "\x0a",
    "\x0b",
    "\x0c",
    "\x0d",
    "\x0e",
    "\x0f",
    "\x10",
    "\x11",
    "\x12",
    "\x13",
    "\x14",
    "\x15",
    "\x16",
    "\x17",
    "\x18",
    "\x19",
    "\x1a",
    "\x1b",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x1f",
    "\xf3",
    "\xf2",
    "SHIFT",
    "TO_C",
    "TO_B",
    "\xf4",
    "\xf1",
)

_charset_b = (
    _common
    + ("`",)
    + tuple(string.ascii_lowercase)
    + (
        "{",
        "|",
        "}",
        "~",
        "\x7f",
        "\xf3",
        "\xf2",
        "SHIFT",
        "TO_C",
        "\xf4",
        "TO_A",
        "\xf1",
    )
)

ISO_8859_1 = {bytes([i]).decode('latin1'): i - 128 for i in range(160, 256)}

ALL = set(_common + _charset_a + _charset_b + tuple(ISO_8859_1.keys()))

A = {c: i for i, c in enumerate(_charset_a)}
B = {c: i for i, c in enumerate(_charset_b)}
C = {"TO_B": 100, "TO_A": 101, "\xf1": 102}

CODES = (
    "11011001100",
    "11001101100",
    "11001100110",
    "10010011000",
    "10010001100",
    "10001001100",
    "10011001000",
    "10011000100",
    "10001100100",
    "11001001000",
    "11001000100",
    "11000100100",
    "10110011100",
    "10011011100",
    "10011001110",
    "10111001100",
    "10011101100",
    "10011100110",
    "11001110010",
    "11001011100",
    "11001001110",
    "11011100100",
    "11001110100",
    "11101101110",
    "11101001100",
    "11100101100",
    "11100100110",
    "11101100100",
    "11100110100",
    "11100110010",
    "11011011000",
    "11011000110",
    "11000110110",
    "10100011000",
    "10001011000",
    "10001000110",
    "10110001000",
    "10001101000",
    "10001100010",
    "11010001000",
    "11000101000",
    "11000100010",
    "10110111000",
    "10110001110",
    "10001101110",
    "10111011000",
    "10111000110",
    "10001110110",
    "11101110110",
    "11010001110",
    "11000101110",
    "11011101000",
    "11011100010",
    "11011101110",
    "11101011000",
    "11101000110",
    "11100010110",
    "11101101000",
    "11101100010",
    "11100011010",
    "11101111010",
    "11001000010",
    "11110001010",
    "10100110000",
    "10100001100",
    "10010110000",
    "10010000110",
    "10000101100",
    "10000100110",
    "10110010000",
    "10110000100",
    "10011010000",
    "10011000010",
    "10000110100",
    "10000110010",
    "11000010010",
    "11001010000",
    "11110111010",
    "11000010100",
    "10001111010",
    "10100111100",
    "10010111100",
    "10010011110",
    "10111100100",
    "10011110100",
    "10011110010",
    "11110100100",
    "11110010100",
    "11110010010",
    "11011011110",
    "11011110110",
    "11110110110",
    "10101111000",
    "10100011110",
    "10001011110",
    "10111101000",
    "10111100010",
    "11110101000",
    "11110100010",
    "10111011110",
    "10111101110",
    "11101011110",
    "11110101110",
    "11010000100",
    "11010010000",
    "11010011100",
)

STOP = "11000111010"

START_CODES = {"A": 103, "B": 104, "C": 105}
TO = {101: START_CODES["A"], 100: START_CODES["B"], 99: START_CODES["C"]}

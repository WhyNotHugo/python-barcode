import os
from io import BytesIO

import pytest

import barcode
from barcode.writer import SVGWriter

PATH = os.path.dirname(os.path.abspath(__file__))
TESTPATH = os.path.join(PATH, "test_outputs")


def test_generate_without_output():
    with pytest.raises(TypeError, match="'output' cannot be None"):
        barcode.generate("ean13", "123455559121112")


def test_generate_with_file():
    with open(os.path.join(TESTPATH, "generate_with_file.jpeg"), "wb") as f:
        barcode.generate("ean13", "123455559121112", output=f)


def test_generate_with_filepath():
    # FIXME: extension is added to the filepath even if you include it.
    rv = barcode.generate(
        "ean13",
        "123455559121112",
        output=os.path.join(TESTPATH, "generate_with_filepath"),
    )
    assert rv == os.path.abspath(os.path.join(TESTPATH, "generate_with_filepath.svg"))


def test_generate_with_file_and_writer():
    with open(os.path.join(TESTPATH, "generate_with_file_and_writer.jpeg"), "wb") as f:
        barcode.generate("ean13", "123455559121112", output=f, writer=SVGWriter())


def test_generate_with_bytesio():
    bio = BytesIO()
    barcode.generate("ean13", "123455559121112", output=bio)
    # XXX: File is not 100% deterministic; needs to be addressed at some point.
    # assert len(bio.getvalue()) == 6127

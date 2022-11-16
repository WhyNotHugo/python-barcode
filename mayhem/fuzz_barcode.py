#!/usr/bin/env python3
import atheris

with atheris.instrument_imports():
    import sys
    from io import BytesIO

    import barcode
    from barcode.errors import BarcodeError
    from barcode.writer import SVGWriter


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    result = fdp.ConsumeInt(12)
    strResult = str(result)
    if len(strResult) != 12:
        return
    try:
        EAN13 = barcode.get_barcode_class("ean13")
        EAN8 = barcode.get_barcode_class("ean8")
        JAN = barcode.get_barcode_class("jan")

        ean13 = EAN13(strResult)
        ean8 = EAN8(strResult)
        jan = JAN(strResult)

        fullname = ean13.save("ean13")
        fullname = ean8.save("ean8")
        fullname = jan.save("jan")

    except BarcodeError as be:
        print(be)
        None


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

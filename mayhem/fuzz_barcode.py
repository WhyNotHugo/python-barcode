import sys
import atheris
import os
from io import BytesIO
import barcode

@atheris.instrument_func
def TestOneInput(input_bytes):
  barray=bytearray(data)
  fdp=atheris.FuzzedDataProvider(data)
  try:
    rv = BytesIO()
    EAN = barcode.get_barcode_class('ean13')
    EAN(fdp.ConsumeInt(len(data)), writer=SVGWriter()).write(rv)
  except barcode.errors.IllegalCharacterError:
    None


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

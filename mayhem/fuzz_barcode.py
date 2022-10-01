import sys
import atheris
import os
from io import BytesIO
import barcode
from barcode import EAN13
#from barcode.writer import SVGWriter
@atheris.instrument_func
def TestOneInput(data):
  barray=bytearray(data)
  fdp=atheris.FuzzedDataProvider(data)
  try:
    EAN = barcode.get_barcode_class('ean13')
    my_ean = EAN(fdp.ConsumeString(data))
    fullname = my_ean.save('test_barcode')
  except Exception:
    None



def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

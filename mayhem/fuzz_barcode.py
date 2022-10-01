import sys
import atheris
import os
from io import BytesIO
import barcode
from barcode.writer import SVGWriter
from barcode.errors import BarcodeError

@atheris.instrument_func
def TestOneInput(data):

    if len(data) < 1:
      return
    
    barray=bytearray(data)
    fdp=atheris.FuzzedDataProvider(data)
    result = fdp.ConsumeInt(len(data))
    try:
      EAN = barcode.get_barcode_class('ean13')
      my_ean = EAN(str(result))
      fullname = my_ean.save('test_barcode')
    except BarcodeError:
      None  
    
    
  

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

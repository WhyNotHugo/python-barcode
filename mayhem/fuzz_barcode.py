import sys
import atheris
import os
from io import BytesIO
import barcode
from barcode.writer import SVGWriter

@atheris.instrument_func
def TestOneInput(data):

    if len(data) < 1:
      return
    
    barray=bytearray(data)
    fdp=atheris.FuzzedDataProvider(data)
    result = fdp.ConsumeInt(len(data)) + 1100001000011
  
    EAN = barcode.get_barcode_class('ean13')
    try:
      my_ean = EAN(str(result))
      fullname = my_ean.save('test_barcode')
      with open("somefile.svg", "wb") as f:
        EAN(str(result), writer=SVGWriter()).write(f)
    except Exception:
      None
    
  

def main():
  #atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

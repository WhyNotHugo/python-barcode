import atheris


with atheris.instrument_imports():
  import sys
  from io import BytesIO
  import barcode
  from barcode.writer import SVGWriter
  from barcode.errors import BarcodeError

@atheris.instrument_func
def TestOneInput(input_bytes):

    if len(input_bytes) <= 1 or len(input_bytes) > 12:
     return
    
    fdp=atheris.FuzzedDataProvider(input_bytes)
    result = fdp.ConsumeInt(len(input_bytes))
    strResult = str(result)
    
    try:
      CODE128 = barcode.get_barcode_class('code128')
      CODE39 = barcode.get_barcode_class('code39')
      EAN13 = barcode.get_barcode_class('ean13')
      EAN8 = barcode.get_barcode_class('ean8')
      JAN = barcode.get_barcode_class('jan')
      
      EAN14 = barcode.get_barcode_class('ean14')
      GS1 = barcode.get_barcode_class('gs1')
      GS1_128 = barcode.get_barcode_class('gs1_128')
      GTIN = barcode.get_barcode_class('gtin')
      ISBN = barcode.get_barcode_class('isbn')
      ITF = barcode.get_barcode_class('itf')
      ISSN = barcode.get_barcode_class('issn')
      ISBN10 = barcode.get_barcode_class('isbn10')
      ISBN13 = barcode.get_barcode_class('isbn13')
      PZN = barcode.get_barcode_class('pzn')
      UPC = barcode.get_barcode_class('upc')
      UPCA = barcode.get_barcode_class('upca')
      
      code128 = CODE128(strResult)
      code39 = CODE39(strResult)
      ean13 = EAN13(strResult)
      ean8 = EAN8(strResult)
      jan = JAN(strResult)
      ean14 = EAN14(strResult)
      gs1 = GS1(strResult)
      gs1_128 = GS1_128(strResult)
      gtin = GTIN(strResult)
      isbn = ISBN(strResult)
      itf = ITF(strResult)
      issn = ISSN(strResult)
      isbn10 = ISBN10(strResult)
      isbn13 = ISBN13(strResult)
      pzn = PZN(strResult)
      upc = UPC(strResult)
      upca = UPCA(strResult)
      
      
      fullname = code128.save('code128')
      fullname = code39.save('code39')
      fullname = ean13.save('ean13')
      fullname = ean8.save('ean8')
      fullname = jan.save('jan')
      fullname = ean14.save('ean14')
      fullname = gs1.save('gs1')
      fullname = gs1_128.save('gs1_128')
      fullname = gtin.save('gtin')
      fullname = isbn.save('isbn')
      fullname = itf.save('itf')
      fullname = issn.save('issn')
      fullname = isbn10.save('isbn10')
      fullname = isbn13.save('isbn13')
      fullname = pzn.save('pzn')
      fullname = upc.save('upc')
      fullname = upca.save('upca')
      
      # Or to an actual file:
      with open("checkjpeg.jpeg", "wb") as f:
        EAN13(strResult, writer=ImageWriter()).write(f)
      
      
    except BarcodeError:
      None      
    
    
  

def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

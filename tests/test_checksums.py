from barcode import get_barcode


def test_code39_checksum():
    code39 = get_barcode("code39", "Code39")
    assert "CODE39W" == code39.get_fullcode()


def test_pzn_checksum():
    pzn = get_barcode("pzn", "103940")
    assert "PZN-1039406" == pzn.get_fullcode()


def test_ean13_checksum():
    ean = get_barcode("ean13", "400614457735")
    assert "4006144577350" == ean.get_fullcode()


def test_ean8_checksum():
    ean = get_barcode("ean8", "6032299")
    assert "60322999" == ean.get_fullcode()


def test_jan_checksum():
    jan = get_barcode("jan", "491400614457")
    assert "4914006144575" == jan.get_fullcode()


def test_ean14_checksum():
    ean = get_barcode("ean14", "1234567891258")
    assert "12345678912589" == ean.get_fullcode()


def test_isbn10_checksum():
    isbn = get_barcode("isbn10", "376926085")
    assert "3769260856" == isbn.isbn10


def test_isbn13_checksum():
    isbn = get_barcode("isbn13", "978376926085")
    assert "9783769260854" == isbn.get_fullcode()


def test_gs1_128_checksum():
    gs1_128 = get_barcode("gs1_128", "00376401856400470087")
    assert "00376401856400470087" == gs1_128.get_fullcode()

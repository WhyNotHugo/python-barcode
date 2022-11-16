#FROM gcr.io/oss-fuzz-base/base-builder-python
FROM fuzzers/atheris:2.0.7-python3.9
ADD ./mayhem/fuzz_barcode.py /fuzz_barcode.py
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install python-barcode
RUN chmod +x /fuzz_barcode.py



CMD ["/fuzz_barcode.py"]

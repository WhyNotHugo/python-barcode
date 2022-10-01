FROM gcr.io/oss-fuzz-base/base-builder-python
ADD ./mayhem/fuzz_barcode.py /fuzz_barcode.py
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install python-barcode



CMD ["/fuzz_barcode.py"]

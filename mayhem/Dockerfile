FROM gcr.io/oss-fuzz-base/base-builder-python
COPY . python-barcode
RUN rm -rf pip/mayhem
WORKDIR $SRC/python-barcode
COPY mayhem/build.sh $SRC/
COPY mayhem/fuzz_* $SRC/

ENV FUZZING_LANGUAGE=python SANITIZER=address FUZZING_ENGINE=libfuzzer
RUN compile
RUN chmod +x /out/fuzz_requirements.pkg

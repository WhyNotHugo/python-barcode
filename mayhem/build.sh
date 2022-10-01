cd $SRC/python-barcode
pip3 install .
python3 setup.py install

cd $SRC/python-barcode

# Build fuzzers
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
	  compile_python_fuzzer $fuzzer
done


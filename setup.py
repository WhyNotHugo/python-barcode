# -*- coding: utf-8 -*-

import sys
from os.path import join, dirname

import barcode as pkg

from setuptools import setup, find_packages


# Avoid name clashes if the user has Python 2 and 3 installed
console_script = 'pybarcode{0}'.format(sys.version_info[0])
try:
    import argparse  # lint:ok
    required = []
except ImportError:
    required = ['argparse']

with open(join(dirname(__file__), 'README.rst')) as fp:
    long_desc = fp.read()


setup(
    name=pkg.__project__,
    version=pkg.__release__,
    packages=find_packages(),
    url=pkg.__url__,
    license=pkg.__license__,
    author=pkg.__author__,
    author_email=pkg.__author_email__,
    description=pkg.__description__,
    long_description=long_desc,
    classifiers=pkg.__classifiers__,
    entry_points={
        'console_scripts':
            ['{0} = barcode.pybarcode:main'.format(console_script)],
        },
    install_requires=required,
    include_package_data=True,
)

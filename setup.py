# -*- coding: utf-8 -*-

import barcode

from inspect import getdoc
from distutils.core import setup


setup(
    name=barcode.__project__,
    version=barcode.__version__,
    packages=['barcode', 'barcode.writer'],
    package_data={'barcode': ['writer/*.ttf']},
    url='http://bitbucket.org/whitie/pybarcode/',
    #download_url=('http://bitbucket.org/whitie/pybarcode/'
    #              'downloads/pyBarcode-0.4b1.tar.gz'),
    license=barcode.__license__,
    author='Thorsten Weimann',
    author_email='thorsten.weimann@gmx.net',
    description=('Create standard barcodes with Python and save them as SVG. '
                 'No external modules needed.'),
    long_description=getdoc(barcode),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Multimedia :: Graphics',
    ],
)

# -*- coding: utf-8 -*-

import barcode

from inspect import getdoc
from distutils.core import setup


setup(
    name='pyBarcode',
    version='0.2.1',
    packages=['barcode', 'barcode.writer'],
    url='http://trac-hg.assembla.com/pybarcode',
    download_url='http://www.dieweimanns.de/whitie/pyBarcode-0.2.1.tar.gz',
    license='BSD',
    author='Thorsten Weimann',
    author_email='thorsten.weimann@gmx.net',
    description=('Create standard barcodes with Python and save them as SVG. '
                 'No external modules needed.'),
    long_description=getdoc(barcode),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Multimedia :: Graphics',
    ],
)

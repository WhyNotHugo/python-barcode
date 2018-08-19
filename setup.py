# -*- coding: utf-8 -*-

from pathlib import Path
from setuptools import find_packages, setup


setup(
    name='python-barcode',
    packages=find_packages(),
    url="https://github.com/WhyNotHugo/python-barcode",
    license='MIT',
    author='Thorsten Weimann et al',
    author_email='weimann.th@yahoo.com',
    description=(
        'Create standard barcodes with Python. No external modules needed. '
        '(optional Pillow support included).'
    ),
    long_description=Path('README.rst').read_text(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Multimedia :: Graphics',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    entry_points={
        'console_scripts': [
            'python-barcode = barcode.pybarcode:main',
        ],
    },
    use_scm_version={
        'version_scheme': 'post-release',
        'write_to': 'barcode/version.py',
    },
    setup_requires=['setuptools_scm'],
    extras_require={
        'images': ['pillow']
    },
    include_package_data=True,
)

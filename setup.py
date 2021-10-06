from pathlib import Path

from setuptools import find_packages
from setuptools import setup

setup(
    name="python-barcode",
    packages=find_packages(),
    url="https://github.com/WhyNotHugo/python-barcode",
    license="MIT",
    author="Hugo Osvaldo Barrera et al",
    author_email="hugo@barrera.io",
    description=(
        "Create standard barcodes with Python. No external modules needed. "
        "(optional Pillow support included)."
    ),
    long_description=Path("README.rst").read_text(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Multimedia :: Graphics",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    entry_points={"console_scripts": ["python-barcode = barcode.pybarcode:main"]},
    use_scm_version={
        "version_scheme": "post-release",
        "write_to": "barcode/version.py",
    },
    setup_requires=["setuptools_scm"],
    extras_require={"images": ["pillow"]},
    include_package_data=True,
)

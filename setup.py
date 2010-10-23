# -*- coding: utf-8 -*-

import barcode as pkg

from inspect import getdoc
from distutils.core import setup


setup(
    name=pkg.__project__,
    version=pkg.__release__,
    packages=['barcode'],
    package_data={'barcode': ['*.ttf']},
    url=pkg.__url__,
    license=pkg.__license__,
    author=pkg.__author__,
    author_email=pkg.__author_email__,
    description=pkg.__description__,
    long_description=getdoc(pkg),
    classifiers=pkg.__classifiers__,
)

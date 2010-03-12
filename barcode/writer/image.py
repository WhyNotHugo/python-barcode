# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

"""barcode.writer.image

Needs PIL (Python Imaging Library) to be installed.

"""
__docformat__ = 'restructuredtext en'

try:
    from PIL import Image
except ImportError:
    Image = None
    print('PIL not found. Image support disabled.')



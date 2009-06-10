# -*- coding: utf-8 -*-

"""barcode.writer.writerbase

"""
__docformat__ = 'restructuredtext en'


class BaseWriter(object):

    def set_options(self, **options):
        for key, val in options.items():
            key = key.lstrip('_')
            if hasattr(self, key):
                setattr(self, key, val)

    def render(self, code):
        raise NotImplementedError

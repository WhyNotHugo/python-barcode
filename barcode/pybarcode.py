# -*- coding: utf-8 -*-

from __future__ import print_function

import os

import barcode

from argparse import ArgumentParser

from barcode.writer import ImageWriter, SVGWriter

# Optional PyQt4 GUI
try:
    from PyQt4 import QtCore
except ImportError:
    QtCore = None  # lint:ok

# No GUI available yet
QtCore = None
IMG_FORMATS = ('BMP', 'GIF', 'JPEG', 'MSP', 'PCX', 'PNG', 'TIFF', 'XBM')


def open_gui(args, parser=None):
    pass


def list_types(args, parser=None):
    print('\npyBarcode available barcode formats:')
    print(', '.join(barcode.PROVIDED_BARCODES))
    print('\n')
    print('Available image formats')
    print('Standard: svg')
    if ImageWriter is not None:
        print('PIL:', ', '.join(IMG_FORMATS))
    else:
        print('PIL: disabled')
    print('\n')


def create_barcode(args, parser):
    args.type = args.type.upper()
    if args.type != 'SVG' and args.type not in IMG_FORMATS:
        parser.error(
            'Unknown type {type}. Try list action for available '
            'types.'.format(type=args.type)
        )
    args.barcode = args.barcode.lower()
    if args.barcode not in barcode.PROVIDED_BARCODES:
        parser.error(
            'Unknown barcode {bc}. Try list action for available '
            'barcodes.'.format(bc=args.barcode)
        )
    if args.type != 'SVG':
        opts = dict(format=args.type)
        writer = ImageWriter()
    else:
        opts = dict(compress=args.compress)
        writer = SVGWriter()
    out = os.path.normpath(os.path.abspath(args.output))
    name = barcode.generate(args.barcode, args.code, writer, out, opts,
                            args.text)
    print('New barcode saved as {0}.'.format(name))


def main():
    msg = []
    if ImageWriter is None:
        msg.append(
            'Image output disabled (PIL not found), --type option disabled.'
        )
    else:
        msg.append(
            'Image output enabled, use --type option to give image '
            'format (png, jpeg, ...).'
        )
    if QtCore is None:
        msg.append('PyQt not found, gui action disabled.')
    else:
        msg.append('PyQt found. Use gui action to get a simple GUI.')
    parser = ArgumentParser(
        description=barcode.__description__, epilog=' '.join(msg)
    )
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + barcode.__release__)
    subparsers = parser.add_subparsers(title='Actions')
    create_parser = subparsers.add_parser('create', help='Create a barcode '
                                          'with the given options.')
    create_parser.add_argument('code', help='Code to render as barcode.')
    create_parser.add_argument('output', help='Filename for output '
                               'without extension, e. g. mybarcode.')
    create_parser.add_argument(
        '-c', '--compress', action='store_true',
        help='Compress output, only recognized if type is svg.'
    )
    create_parser.add_argument('-b', '--barcode', help='Barcode to use '
                               '[default: %(default)s].')
    create_parser.add_argument('--text', help='Text to show under the '
                               'barcode.')
    if ImageWriter is not None:
        create_parser.add_argument('-t', '--type', help='Type of output '
                                   '[default: %(default)s].')
    list_parser = subparsers.add_parser('list', help='List available '
                                        'image and code types.')
    list_parser.set_defaults(func=list_types)
    if QtCore is not None:
        gui_parser = subparsers.add_parser('gui', help='Opens a simple '
                                           'PyQt GUI to create barcodes.')
        gui_parser.set_defaults(func=open_gui)
    create_parser.set_defaults(type='svg', compress=False, func=create_barcode,
                               barcode='code39', text=None)
    args = parser.parse_args()
    args.func(args, parser)


if __name__ == '__main__':
    main()

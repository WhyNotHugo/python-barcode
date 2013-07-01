Create your own writer
======================

To create your own writer, inherit from `barcode.writer.BaseWriter`.
In your __init__ method call BaseWriter's __init__ and give your callbacks for
`initialize(raw_code)`, `paint_module(xpos, ypos, width, color)`,
`paint_text(xpos, ypos)` and `finish()`.

Now instatiate a new barcode and give an instance of your new writer as
argument. If you now call `render` on the barcode instance your callbacks
get called.

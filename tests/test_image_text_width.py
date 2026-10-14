from __future__ import annotations

import math

import pytest

from barcode import Gs1_128
from barcode.writer import ImageWriter
from barcode.writer import mm2px
from barcode.writer import pt2mm

if ImageWriter is not None:
    from PIL import Image
    from PIL import ImageChops
    from PIL import ImageDraw
    from PIL import ImageFont

    @pytest.mark.parametrize("dpi", [150, 300])
    @pytest.mark.parametrize("center_text", [True, False])
    @pytest.mark.parametrize(
        "caption", ["", "A much longer caption\nAnd a second line"]
    )
    def test_image_contains_complete_caption(
        dpi: int, center_text: bool, caption: str
    ) -> None:
        assert ImageWriter is not None
        writer = ImageWriter(dpi=dpi)
        barcode = Gs1_128("00376401856400470087", writer=writer)
        image = barcode.render({"center_text": center_text}, text=caption or None)
        assert isinstance(image, Image.Image)
        font = ImageFont.truetype(
            writer.font_path, int(mm2px(pt2mm(writer.font_size), dpi))
        )
        text = caption or barcode.get_fullcode()
        width, _ = writer.calculate_size(len(barcode.build()[0]), 1)
        xpos = width / 2 if center_text else writer.quiet_zone
        ypos = writer.margin_top + writer.module_height + writer.text_distance
        expected = Image.new("RGB", (image.width + 2048, image.height), "white")
        draw = ImageDraw.Draw(expected)
        for line in text.split("\n"):
            draw.text(
                (mm2px(xpos, dpi) + 1024, mm2px(ypos, dpi)),
                line,
                font=font,
                fill="black",
                anchor="md",
            )
            ypos += pt2mm(writer.font_size) / 2 + writer.text_line_distance
        text_top = math.ceil(mm2px(writer.margin_top + writer.module_height, dpi)) + 1
        actual = image.crop((0, text_top, image.width, image.height))
        reference = expected.crop((0, text_top, expected.width, expected.height))
        actual_box = ImageChops.difference(
            actual, Image.new("RGB", actual.size, "white")
        ).getbbox()
        reference_box = ImageChops.difference(
            reference, Image.new("RGB", reference.size, "white")
        ).getbbox()
        assert actual_box is not None
        assert reference_box is not None
        assert actual.crop(actual_box).size == reference.crop(reference_box).size
        assert (
            actual.crop(actual_box).tobytes() == reference.crop(reference_box).tobytes()
        )

    def test_expanding_caption_preserves_barcode_and_resets_between_images() -> None:
        assert ImageWriter is not None
        writer = ImageWriter()
        barcode = Gs1_128("00376401856400470087", writer=writer)
        plain = barcode.render({"write_text": False})
        labelled = barcode.render()
        assert isinstance(plain, Image.Image)
        assert isinstance(labelled, Image.Image)
        assert labelled.width > plain.width
        top = math.ceil(mm2px(writer.margin_top + writer.module_height, writer.dpi)) + 1
        plain_bars = plain.crop((0, 0, plain.width, top))
        labelled_bars = labelled.crop((0, 0, labelled.width, top))
        plain_box = ImageChops.difference(
            plain_bars, Image.new("RGB", plain_bars.size, "white")
        ).getbbox()
        labelled_box = ImageChops.difference(
            labelled_bars, Image.new("RGB", labelled_bars.size, "white")
        ).getbbox()
        assert plain_box is not None
        assert labelled_box is not None
        assert plain_bars.crop(plain_box).size == labelled_bars.crop(labelled_box).size
        assert (
            plain_bars.crop(plain_box).tobytes()
            == labelled_bars.crop(labelled_box).tobytes()
        )
        plain_again = barcode.render({"write_text": False})
        labelled_again = barcode.render()
        assert isinstance(plain_again, Image.Image)
        assert isinstance(labelled_again, Image.Image)
        assert plain_again.tobytes() == plain.tobytes()
        assert labelled_again.tobytes() == labelled.tobytes()

    def test_human_caption_expansion_preserves_transparent_background() -> None:
        assert ImageWriter is not None
        writer = ImageWriter(mode="RGBA")
        barcode = Gs1_128("00376401856400470087", writer=writer)
        caption = "A long custom human-readable caption"
        options = {
            "background": (0, 0, 0, 0),
            "human": caption,
        }
        image = barcode.render(options)
        assert isinstance(image, Image.Image)
        assert image.mode == "RGBA"
        assert image.getpixel((0, 0)) == (0, 0, 0, 0)
        assert image.getpixel((image.width - 1, 0)) == (0, 0, 0, 0)
        reference = Gs1_128(
            "00376401856400470087", writer=ImageWriter(mode="RGBA")
        ).render({"background": (0, 0, 0, 0)}, text=caption)
        assert isinstance(reference, Image.Image)
        assert image.size == reference.size
        assert image.tobytes() == reference.tobytes()

    def test_guarded_text_blocks_keep_their_relative_positions() -> None:
        from barcode import EAN13

        assert ImageWriter is not None
        image = EAN13("590123412345", writer=ImageWriter(), guardbar=True).render(
            {"font_size": 36}
        )
        # A wider quiet zone is an independent reference where no block is clipped.
        reference = EAN13("590123412345", writer=ImageWriter(), guardbar=True).render(
            {"font_size": 36, "quiet_zone": 6.5 + 500 * 25.4 / 300}
        )
        assert isinstance(image, Image.Image)
        assert isinstance(reference, Image.Image)
        actual_box = ImageChops.difference(
            image, Image.new("RGB", image.size, "white")
        ).getbbox()
        reference_box = ImageChops.difference(
            reference, Image.new("RGB", reference.size, "white")
        ).getbbox()
        assert actual_box is not None
        assert reference_box is not None
        assert image.crop(actual_box).size == reference.crop(reference_box).size
        assert (
            image.crop(actual_box).tobytes() == reference.crop(reference_box).tobytes()
        )

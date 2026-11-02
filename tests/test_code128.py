from __future__ import annotations

import pytest

from barcode.codex import Code128
from barcode.errors import BarcodeError


def test_build_is_stable_across_repeated_calls() -> None:
    """Calling build() repeatedly on the same instance must be deterministic.

    Regression test for #143: ``_build`` mutated ``_charset`` and
    ``_digit_buffer`` without resetting them, so a second call started from
    stale state and produced a different bit string.
    """
    code = Code128("12A")
    first = code.build()
    assert code.build() == first
    assert code.build() == first


def test_encoded_is_stable_across_repeated_calls() -> None:
    """The ``encoded`` property must also be deterministic across calls."""
    code = Code128("12A")
    first = code.encoded
    assert code.encoded == first
    assert code.encoded == first


def test_reused_instance_matches_fresh_instance() -> None:
    """A reused instance must encode identically to a freshly built one."""
    reused = Code128("123ABC456")
    reused.build()  # dirties the internal charset/buffer state
    assert reused.build() == Code128("123ABC456").build()


def test_empty_code_raises_barcode_error() -> None:
    """Empty data must fail with a clear error at construction time.

    Code128("") was accepted by __init__ and then crashed with IndexError
    inside _try_to_optimize, because the encoded list holds only the start
    code. Fail fast with the library's own error type instead.
    """
    with pytest.raises(BarcodeError):
        Code128("")

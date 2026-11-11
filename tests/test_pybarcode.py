from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from barcode import pybarcode

if TYPE_CHECKING:
    from pathlib import Path


def test_create_invalid_code_is_clean_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["pybarcode", "create", "123", "out", "--barcode", "ean8"]
    )
    with pytest.raises(SystemExit) as excinfo:
        pybarcode.main()
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "7 digits" in err


def test_create_valid_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["pybarcode", "create", "1234567", "out", "--barcode", "ean8"]
    )
    pybarcode.main()  # must not raise
    assert tmp_path.joinpath("out.svg").exists()
    assert "New barcode saved as" in capsys.readouterr().out

"""Tests for OVALParser stub."""
from pathlib import Path

import pytest

from app.parsers.oval_parser import OVALParser


def test_oval_parser_raises_not_implemented(tmp_path):
    parser = OVALParser()
    dummy = tmp_path / "dummy.xml"
    dummy.write_text("<oval/>", encoding="utf-8")
    with pytest.raises(NotImplementedError, match="not yet implemented"):
        parser.parse(dummy)

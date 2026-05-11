"""OVAL results parser — stub placeholder.

Full implementation is deferred to a future release.
See README.md roadmap: 'Standalone OVAL Results Parsing'.
"""
from __future__ import annotations

from pathlib import Path

from app.parsers.base import BaseParser


class OVALParser(BaseParser):
    """Parses standalone OVAL results files (OpenSCAP .oval.xml output).

    Not yet implemented. Raises NotImplementedError on use.
    """

    def parse(self, path: Path) -> None:  # type: ignore[override]
        raise NotImplementedError(
            "OVAL results parsing is not yet implemented. "
            "See README.md for roadmap details."
        )

"""Filter findings to actionable statuses only.

The matcher already discards non-actionable statuses during merge.
This module provides an explicit filter step for pipeline clarity and
to support filtering an already-merged list (e.g. after re-import).
"""
from __future__ import annotations

from app.parsers.base import Finding

_KEEP_STATUSES = frozenset({"Open", "Not Reviewed", "Error", "Unknown"})


def filter_findings(findings: list[Finding]) -> list[Finding]:
    """Return only findings whose status is actionable.

    Passes: Open, Not Reviewed, Error, Unknown.
    Discards anything else (should not occur after matcher, but defensive).
    """
    return [f for f in findings if f.status in _KEEP_STATUSES]

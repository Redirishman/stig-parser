"""Upload allow-list — the single definition, shared by every entry point.

Both the Flask app (``app/web.py``) and the Lambda API handler
(``app/lambdas/api.py``) gate uploads on this. It is a security control: a
second, drifting copy is how one entry point ends up accepting a file type the
other rejects.
"""
from __future__ import annotations

from pathlib import Path

# Results accept XCCDF (.xml), CKLB checklists (.cklb), and Nessus compliance
# scans (.nessus); benchmarks accept .xml and DISA .zip bundles.
ALLOWED_UPLOAD_EXT = {".xml", ".zip", ".cklb", ".nessus"}
MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # per file

_ALLOWED_DISPLAY = ", ".join(sorted(ALLOWED_UPLOAD_EXT))


def is_safe_name(name: str) -> bool:
    """True if ``name`` is a bare filename safe to join onto a path.

    Upload filenames are operator-supplied and become S3 keys and local paths;
    separators, ``..`` and absolute paths must never make it that far.
    """
    return (
        bool(name)
        and "/" not in name
        and "\\" not in name
        and ".." not in name
        and not Path(name).is_absolute()
    )


def reject_filename(name: str) -> str | None:
    """Return a user-safe rejection message for a bad filename, else None."""
    if not is_safe_name(name):
        return f"Invalid filename: {name!r}"
    if Path(name).suffix.lower() not in ALLOWED_UPLOAD_EXT:
        return f"Unsupported file type: {name!r} (allowed: {_ALLOWED_DISPLAY})"
    return None


def reject_size(name: str, size: int) -> str | None:
    """Return a user-safe rejection message for an oversized file, else None."""
    if size > MAX_UPLOAD_BYTES:
        return f"File too large: {name!r} (max 200 MB each)"
    return None

"""Extract XCCDF benchmark XML files from DISA STIG distribution ZIPs.

DISA distributes STIGs as ZIP files (e.g. U_MS_Windows_Server_2022_V2R8_STIG.zip)
containing a folder with the XCCDF benchmark XML, supplementary docs, and
sometimes nested ZIPs (the "wrapper" pattern). This module unwraps those.
"""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

# Filenames matching this suffix (case-insensitive) are treated as XCCDF benchmarks
_XCCDF_SUFFIX = "xccdf.xml"

# Decompressed-size cap per archive member and nested-ZIP recursion limit.
# Without these, a crafted ZIP (high compression ratio, or self-nesting)
# exhausts disk/stack — a classic zip bomb DoS on untrusted uploads.
_MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
_MAX_ZIP_DEPTH = 2
_CHUNK = 65536


def _bounded_extract(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path
) -> bool:
    """Stream one archive member to *target*, aborting past the size cap.

    Returns True on success; False if the limit was exceeded (partial file
    removed). The decompressed size is measured as data is written, so a
    member that lies about its declared size is still caught.
    """
    written = 0
    with zf.open(info) as src, target.open("wb") as dst:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > _MAX_EXTRACTED_BYTES:
                dst.close()
                target.unlink(missing_ok=True)
                log.warning(
                    "Skipping %s — exceeds %d-byte decompressed limit "
                    "(possible zip bomb)",
                    info.filename,
                    _MAX_EXTRACTED_BYTES,
                )
                return False
            dst.write(chunk)
    return True


def _unique_path(path: Path) -> Path:
    """Return *path* if it does not exist, otherwise append a numeric suffix."""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for i in range(1, 1000):
        candidate = parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find a unique path for {path}")


def extract_xccdf_from_zip(
    zip_path: Path, dest_dir: Path, _depth: int = 0
) -> list[Path]:
    """Extract every XCCDF benchmark XML from *zip_path* into *dest_dir*.

    Recurses one level into any nested ZIPs (DISA's wrapper-zip pattern).
    Returns a flat list of extracted .xml file paths. The list is empty if the
    archive contains no XCCDF benchmark.
    """
    extracted: list[Path] = []
    dest_dir.mkdir(parents=True, exist_ok=True)

    if _depth > _MAX_ZIP_DEPTH:
        log.warning(
            "Skipping %s — nested ZIP depth exceeds %d (possible zip bomb)",
            zip_path.name,
            _MAX_ZIP_DEPTH,
        )
        return extracted

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        log.warning("Skipping %s — not a valid ZIP: %s", zip_path.name, exc)
        return extracted

    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            inner_name = Path(info.filename).name  # strip any folder structure
            if not inner_name:
                continue
            lower = inner_name.lower()

            if lower.endswith(_XCCDF_SUFFIX):
                target = _unique_path(dest_dir / inner_name)
                if _bounded_extract(zf, info, target):
                    extracted.append(target)
                continue

            if lower.endswith(".zip"):
                # Wrapper-zip pattern: extract nested zip, recurse, then discard it
                inner_zip = _unique_path(dest_dir / inner_name)
                if _bounded_extract(zf, info, inner_zip):
                    extracted.extend(
                        extract_xccdf_from_zip(inner_zip, dest_dir, _depth + 1)
                    )
                inner_zip.unlink(missing_ok=True)

    return extracted


def expand_benchmark_paths(
    paths: list[Path], extract_dir: Path
) -> tuple[list[Path], list[str]]:
    """Replace any .zip entries in *paths* with their extracted XCCDF XMLs.

    Non-zip paths pass through unchanged. Returns (resolved_paths, warnings)
    where warnings name any zip whose contents had no XCCDF benchmark XML.
    """
    resolved: list[Path] = []
    warnings: list[str] = []

    for p in paths:
        if p.suffix.lower() != ".zip":
            resolved.append(p)
            continue

        extracted = extract_xccdf_from_zip(p, extract_dir)
        if extracted:
            resolved.extend(extracted)
            log.info("Extracted %d XCCDF file(s) from %s", len(extracted), p.name)
        else:
            warnings.append(
                f"No XCCDF benchmark XML found in {p.name} "
                f"(expected a *xccdf.xml file inside the zip)"
            )

    return resolved, warnings

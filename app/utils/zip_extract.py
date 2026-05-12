"""Extract XCCDF benchmark XML files from DISA STIG distribution ZIPs.

DISA distributes STIGs as ZIP files (e.g. U_MS_Windows_Server_2022_V2R8_STIG.zip)
containing a folder with the XCCDF benchmark XML, supplementary docs, and
sometimes nested ZIPs (the "wrapper" pattern). This module unwraps those.
"""
from __future__ import annotations

import logging
import shutil
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

# Filenames matching this suffix (case-insensitive) are treated as XCCDF benchmarks
_XCCDF_SUFFIX = "xccdf.xml"


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


def extract_xccdf_from_zip(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Extract every XCCDF benchmark XML from *zip_path* into *dest_dir*.

    Recurses one level into any nested ZIPs (DISA's wrapper-zip pattern).
    Returns a flat list of extracted .xml file paths. The list is empty if the
    archive contains no XCCDF benchmark.
    """
    extracted: list[Path] = []
    dest_dir.mkdir(parents=True, exist_ok=True)

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
                with zf.open(info) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.append(target)
                continue

            if lower.endswith(".zip"):
                # Wrapper-zip pattern: extract nested zip, recurse, then discard it
                inner_zip = _unique_path(dest_dir / inner_name)
                with zf.open(info) as src, inner_zip.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.extend(extract_xccdf_from_zip(inner_zip, dest_dir))
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

# Backend Async Re-Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose the synchronous parse→export monolith into discrete, artifact-based stages behind storage and job-state abstractions, so the pipeline can later run as async Lambda stages — while keeping the Flask app and CLI working through the same shared core.

**Architecture:** Extract the duplicated pipeline (currently copy-pasted in `app/web.py` and `app/cli.py`) into a pure `app/core/pipeline.py`. Add a JSON serialization layer for `Finding` objects so stages can hand off via S3. Introduce two abstractions — `ArtifactStore` (blob I/O) and `JobStore` (job status) — each with a local implementation (used by Flask/CLI/tests) and an AWS implementation (`S3ArtifactStore`, `DynamoJobStore`) tested with `moto`. Compose these into async stage entrypoints (`run_parse_stage`, `run_export_stage`) that operate purely through the abstractions.

**Tech Stack:** Python 3.11+, Flask, lxml, openpyxl (existing); boto3 + moto (added, dev/runtime for AWS store impls); pytest.

**Scope boundary:** This plan does NOT add Lambda `handler(event, context)` entrypoints or the Step Functions wiring — those depend on infra event shapes defined in sub-project #2 (Terraform). This plan delivers the AWS-agnostic core + AWS-backed stores, all unit-tested without any real AWS resources.

**Non-negotiable invariants to preserve:**
- CLI behavior and exit codes unchanged (existing `tests/test_cli.py` must stay green).
- Flask endpoints and job lifecycle unchanged (existing `tests/test_web.py` must stay green).
- The two distinct "no actionable findings" error messages are preserved verbatim in meaning.
- Core pipeline never imports boto3. AWS lives only in the store implementations.

---

### Task 1: Scaffold `app/core` package and add dev dependencies

**Files:**
- Create: `app/core/__init__.py`
- Modify: `pyproject.toml` (dependencies + optional dev deps)
- Test: `tests/test_core_import.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_core_import.py
"""Smoke test: the core package and its AWS deps are importable."""


def test_core_package_imports():
    import app.core  # noqa: F401


def test_boto3_available():
    import boto3  # noqa: F401


def test_moto_available():
    import moto  # noqa: F401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_core_import.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core'` (and/or moto not installed).

- [ ] **Step 3: Create the package and add dependencies**

Create `app/core/__init__.py`:

```python
"""Core pipeline, serialization, and storage/job abstractions.

This package is AWS-agnostic except for the concrete ``S3ArtifactStore`` and
``DynamoJobStore`` implementations, which are the only modules permitted to
import boto3.
"""
```

In `pyproject.toml`, change the `dependencies` list to add boto3 (needed at runtime by the AWS store impls in Lambda):

```toml
dependencies = [
    "flask>=3.0",
    "lxml>=5.0",
    "openpyxl>=3.1",
    "boto3>=1.34",
]
```

And change the `[project.optional-dependencies]` `dev` list to add moto:

```toml
dev = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "moto[s3,dynamodb]>=5.0",
]
```

- [ ] **Step 4: Install and run the test to verify it passes**

Run: `pip install -e ".[dev]" && python -m pytest tests/test_core_import.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/__init__.py pyproject.toml tests/test_core_import.py
git commit -m "chore: scaffold app.core package and add boto3/moto deps"
```

---

### Task 2: Extract the parse→export pipeline into `app/core/pipeline.py`

**Files:**
- Create: `app/core/pipeline.py`
- Test: `tests/test_pipeline.py`

The pipeline currently lives twice: `app/web.py:247-349` (`_run_job`) and `app/cli.py:118-182`. This task extracts a single source of truth. Behavior — including warning collection and the two "empty" error messages — is preserved.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline.py
"""Tests for the shared parse→export pipeline."""
from pathlib import Path

import pytest

from app.core.pipeline import (
    ParseResult,
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)
from app.parsers.base import Finding


def _finding(severity="CAT II", server="host1"):
    return Finding(
        stig_title="Test STIG",
        vuln_id="V-1",
        rule_id="SV-1r1_rule",
        severity=severity,
        status="Open",
        server=server,
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )


def test_compute_summary_counts_by_severity_and_host():
    findings = [
        _finding("CAT I", "a"),
        _finding("CAT II", "a"),
        _finding("CAT III", "b"),
    ]
    summary = compute_summary(findings, source_file_count=2)
    assert summary == {
        "files": 2,
        "hosts": 2,
        "findings": 3,
        "cat1": 1,
        "cat2": 1,
        "cat3": 1,
    }


def test_default_output_name_is_timestamped_xlsx():
    name = default_output_name()
    assert name.startswith("stig_findings_")
    assert name.endswith(".xlsx")


def test_parse_stage_raises_pipelineerror_when_no_results_parse(tmp_path):
    # A file that is not valid XCCDF results -> no scan_results parsed.
    bad = tmp_path / "not_xccdf.xml"
    bad.write_text("<html><body>nope</body></html>", encoding="utf-8")
    with pytest.raises(PipelineError) as exc:
        parse_stage(
            results_paths=[bad],
            benchmark_paths=[],
            extract_dir=tmp_path / "extract",
        )
    assert "results" in str(exc.value).lower()


def test_export_stage_writes_xlsx(tmp_path):
    out = tmp_path / "report.xlsx"
    export_stage([_finding()], out)
    assert out.exists() and out.stat().st_size > 0


def test_parse_stage_cancel_check_is_invoked(tmp_path):
    bad = tmp_path / "x.xml"
    bad.write_text("<x/>", encoding="utf-8")
    calls = []

    def cancel():
        calls.append(1)

    with pytest.raises(PipelineError):
        parse_stage([bad], [], tmp_path / "e", cancel_check=cancel)
    assert calls, "cancel_check should be invoked at least once"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_pipeline.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.pipeline'`.

- [ ] **Step 3: Write the implementation**

Create `app/core/pipeline.py`:

```python
"""Shared parse→export pipeline used by the CLI, the Flask app, and the
async stage entrypoints. Single source of truth for the processing steps.

This module is AWS-agnostic and must not import boto3.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.exporters.excel_exporter import ExcelExporter
from app.parsers.base import Finding
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
from app.utils.zip_extract import expand_benchmark_paths


class PipelineError(Exception):
    """Raised when the pipeline cannot produce actionable findings.

    The message is user-safe and intended for display in the UI / CLI.
    """


@dataclass
class ParseResult:
    """Output of :func:`parse_stage`."""
    findings: list[Finding]
    warnings: list[str]
    source_file_count: int


def parse_stage(
    results_paths: list[Path],
    benchmark_paths: list[Path],
    extract_dir: Path,
    *,
    cancel_check: Callable[[], None] | None = None,
) -> ParseResult:
    """Parse results + benchmarks, match, and filter to actionable findings.

    ``cancel_check`` is an optional zero-arg callable invoked between units of
    work; it may raise to abort (the Flask worker uses this for cancellation).
    Raises :class:`PipelineError` (user-safe message) when no actionable
    findings can be produced.
    """

    def _check() -> None:
        if cancel_check is not None:
            cancel_check()

    warnings: list[str] = []

    # When no benchmark files were supplied, SCC result files embed the full
    # benchmark definitions — use the results files for both sides.
    if not benchmark_paths:
        benchmark_paths = list(results_paths)

    _check()
    benchmark_paths, zip_warnings = expand_benchmark_paths(benchmark_paths, extract_dir)
    warnings.extend(zip_warnings)

    benchmark_parser = BenchmarkParser()
    benchmarks = []
    for path in benchmark_paths:
        _check()
        bm = benchmark_parser.parse(path)
        if bm:
            benchmarks.append(bm)
        else:
            warnings.append(f"Could not parse benchmark: {path.name}")

    results_parser = XCCDFResultsParser()
    scan_results = []
    for path in results_paths:
        _check()
        sr = results_parser.parse(path)
        if sr:
            scan_results.append(sr)
        else:
            warnings.append(f"Could not parse results file: {path.name}")

    if not scan_results:
        raise PipelineError("No valid results files could be parsed.")

    _check()
    findings = match_results_to_benchmarks(scan_results, benchmarks)
    findings = filter_findings(findings)

    if not findings:
        total_rules = sum(len(s.rule_results) for s in scan_results)
        if total_rules == 0:
            msg = (
                f"No <rule-result> elements were found in any of the "
                f"{len(scan_results)} results file(s). The files may not be "
                f"XCCDF scan results, or may use an unrecognised structure. "
                f"Check the warnings for details."
            )
        else:
            msg = (
                f"Parsed {total_rules} rule-result(s) across "
                f"{len(scan_results)} file(s), but none had an actionable "
                f"status (Open / Not Reviewed / Error / Unknown). Either "
                f"every rule passed, or the results were not matched to the "
                f"supplied STIG benchmarks. Check the warnings."
            )
        raise PipelineError(msg)

    return ParseResult(
        findings=findings,
        warnings=warnings,
        source_file_count=len(scan_results),
    )


def compute_summary(findings: list[Finding], source_file_count: int) -> dict:
    """Build the summary dict shown in the UI after a successful run."""
    severity_counts = {"CAT I": 0, "CAT II": 0, "CAT III": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    return {
        "files": source_file_count,
        "hosts": len({f.server for f in findings if f.server}),
        "findings": len(findings),
        "cat1": severity_counts["CAT I"],
        "cat2": severity_counts["CAT II"],
        "cat3": severity_counts["CAT III"],
    }


def export_stage(findings: list[Finding], output_path: Path) -> None:
    """Write findings to an Excel workbook at ``output_path``."""
    ExcelExporter().export(findings, output_path)


def default_output_name() -> str:
    """Timestamped default output filename."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"stig_findings_{ts}.xlsx"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_pipeline.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/pipeline.py tests/test_pipeline.py
git commit -m "feat: extract shared parse/export pipeline into app.core.pipeline"
```

---

### Task 3: Refactor `app/cli.py` onto the shared pipeline

**Files:**
- Modify: `app/cli.py:117-184` (the `try/finally` processing block)
- Test: `tests/test_cli.py` (existing — must stay green)

- [ ] **Step 1: Run the existing CLI tests to establish the green baseline**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS (record the count; it must not drop after refactor).

- [ ] **Step 2: Replace the inline pipeline with a call to `parse_stage`/`export_stage`**

In `app/cli.py`, replace the block from `extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))` through the end of the `finally:` (currently lines 118-184) with:

```python
    extract_dir = Path(tempfile.mkdtemp(prefix="stig_zip_"))
    try:
        try:
            result = parse_stage(results_paths, benchmark_paths, extract_dir)
        except PipelineError as exc:
            log.error("%s", exc)
            return 1

        for w in result.warnings:
            log.warning(w)

        log.info("Actionable findings: %d", len(result.findings))

        if args.output:
            output_path = Path(args.output)
        else:
            output_path = Path(default_output_name())

        log.info("Exporting to %s…", output_path)
        try:
            export_stage(result.findings, output_path)
        except Exception as exc:
            log.error("Export failed: %s", exc)
            return 1

        print(f"Report written: {output_path.resolve()}")
        return 0
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
```

Then update the imports near the top of `app/cli.py`. Remove the now-unused pipeline imports and add the core import. Delete these lines:

```python
from app.exporters.excel_exporter import ExcelExporter
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
from app.utils.zip_extract import expand_benchmark_paths
```

Add in their place:

```python
from app.core.pipeline import (
    PipelineError,
    default_output_name,
    export_stage,
    parse_stage,
)
```

Note: the `datetime` import in `app/cli.py` is now only used elsewhere — if `python -m pyflakes app/cli.py` reports it unused, remove `from datetime import datetime, timezone`.

- [ ] **Step 3: Run the CLI tests to verify still green**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS — same count as Step 1.

- [ ] **Step 4: Commit**

```bash
git add app/cli.py
git commit -m "refactor: CLI uses shared app.core.pipeline (DRY)"
```

---

### Task 4: Refactor `app/web.py:_run_job` onto the shared pipeline

**Files:**
- Modify: `app/web.py:247-349` (`_run_job`) and imports at `app/web.py:25-30`
- Test: `tests/test_web.py` (existing — must stay green)

- [ ] **Step 1: Run the existing web tests to establish the green baseline**

Run: `python -m pytest tests/test_web.py -v`
Expected: PASS (record the count).

- [ ] **Step 2: Replace the body of `_run_job` with pipeline calls**

In `app/web.py`, replace the entire body of `_run_job` (the code inside `try:` through the `summary = {...}` / final `_set_job(..., status="complete", ...)`, i.e. lines 252-349) with the version below. The `except _JobCancelled`, `except Exception`, and `finally` clauses (lines 351-359) stay unchanged.

```python
    try:
        def _cancel_check() -> None:
            _raise_if_cancelled(job_id)

        _set_job(job_id, progress="Parsing files…")
        try:
            result = parse_stage(
                results_paths,
                benchmark_paths,
                _job_dir(job_id) / "benchmarks_extracted",
                cancel_check=_cancel_check,
            )
        except PipelineError as exc:
            _set_job(
                job_id,
                status="error",
                error=str(exc),
                warnings=list(warnings),
            )
            return

        warnings.extend(result.warnings)

        _raise_if_cancelled(job_id)
        _set_job(job_id, progress="Generating Excel workbook…", warnings=list(warnings))
        output_path = _job_dir(job_id) / default_output_name()
        export_stage(result.findings, output_path)

        summary = compute_summary(result.findings, result.source_file_count)

        _set_job(
            job_id,
            status="complete",
            progress=f"Done — {len(result.findings)} findings exported.",
            output_path=str(output_path),
            warnings=list(warnings),
            summary=summary,
        )
```

- [ ] **Step 3: Update imports in `app/web.py`**

Delete these lines (25-30):

```python
from app.exporters.excel_exporter import ExcelExporter
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
from app.utils.zip_extract import expand_benchmark_paths
```

Add in their place:

```python
from app.core.pipeline import (
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)
```

If `python -m pyflakes app/web.py` reports `datetime`/`timezone` unused after this change, remove `from datetime import datetime, timezone`.

- [ ] **Step 4: Run the web tests to verify still green**

Run: `python -m pytest tests/test_web.py -v`
Expected: PASS — same count as Step 1.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -v`
Expected: PASS — all pre-existing tests plus the new `tests/test_pipeline.py` and `tests/test_core_import.py`.

- [ ] **Step 6: Commit**

```bash
git add app/web.py
git commit -m "refactor: Flask worker uses shared app.core.pipeline (DRY)"
```

---

### Task 5: Add `Finding` JSON serialization in `app/core/findings_io.py`

**Files:**
- Create: `app/core/findings_io.py`
- Test: `tests/test_findings_io.py`

Async stages hand findings off through S3 as JSON between parse and export.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_findings_io.py
from app.core.findings_io import findings_from_json, findings_to_json
from app.parsers.base import Finding


def _finding(**over):
    base = dict(
        stig_title="T",
        vuln_id="V-1",
        rule_id="SV-1r1_rule",
        severity="CAT II",
        status="Open",
        server="host1",
        ip_address="10.0.0.1",
        check_text="check",
        fix_text="fix",
    )
    base.update(over)
    return Finding(**base)


def test_roundtrip_preserves_all_fields():
    original = [_finding(), _finding(vuln_id="V-2", severity="CAT I")]
    restored = findings_from_json(findings_to_json(original))
    assert restored == original


def test_to_json_is_a_string():
    assert isinstance(findings_to_json([_finding()]), str)


def test_empty_list_roundtrips():
    assert findings_from_json(findings_to_json([])) == []


def test_from_json_ignores_unknown_keys():
    # Forward-compatibility: extra keys in stored JSON must not crash load.
    payload = '[{"stig_title":"T","vuln_id":"V-1","rule_id":"r","severity":"CAT II",' \
              '"status":"Open","server":"h","ip_address":"1.1.1.1","check_text":"c",' \
              '"fix_text":"f","future_field":"x"}]'
    restored = findings_from_json(payload)
    assert restored[0].vuln_id == "V-1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_findings_io.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.findings_io'`.

- [ ] **Step 3: Write the implementation**

Create `app/core/findings_io.py`:

```python
"""JSON serialization for :class:`Finding` objects.

Used to hand findings between async pipeline stages via blob storage.
AWS-agnostic.
"""
from __future__ import annotations

import json
from dataclasses import asdict, fields

from app.parsers.base import Finding

_FIELD_NAMES = {f.name for f in fields(Finding)}


def findings_to_json(findings: list[Finding]) -> str:
    """Serialize a list of findings to a JSON string."""
    return json.dumps([asdict(f) for f in findings])


def findings_from_json(data: str) -> list[Finding]:
    """Deserialize findings from a JSON string.

    Unknown keys are ignored so that older stored payloads and newer code (or
    vice versa) remain compatible.
    """
    raw = json.loads(data)
    result: list[Finding] = []
    for item in raw:
        kwargs = {k: v for k, v in item.items() if k in _FIELD_NAMES}
        result.append(Finding(**kwargs))
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_findings_io.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/findings_io.py tests/test_findings_io.py
git commit -m "feat: add Finding JSON serialization for stage handoff"
```

---

### Task 6: Define `ArtifactStore` protocol and `LocalArtifactStore`

**Files:**
- Create: `app/core/artifact_store.py`
- Test: `tests/test_artifact_store_local.py`

`ArtifactStore` is the blob-I/O boundary. The local impl backs Flask/CLI/tests; the S3 impl (Task 7) backs Lambda. Presigned URLs are an S3-only capability, so the protocol exposes `presign_get`/`presign_put` which `LocalArtifactStore` implements as `file://` paths (usable in tests, never surfaced to users).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_artifact_store_local.py
from app.core.artifact_store import LocalArtifactStore


def test_put_then_get_bytes_roundtrip(tmp_path):
    store = LocalArtifactStore(tmp_path)
    store.put_bytes("jobs/1/findings.json", b'{"a":1}')
    assert store.get_bytes("jobs/1/findings.json") == b'{"a":1}'


def test_exists(tmp_path):
    store = LocalArtifactStore(tmp_path)
    assert store.exists("missing/key") is False
    store.put_bytes("present/key", b"x")
    assert store.exists("present/key") is True


def test_download_to_and_upload_from(tmp_path):
    store = LocalArtifactStore(tmp_path)
    src = tmp_path / "src.bin"
    src.write_bytes(b"payload")
    store.upload_from("k/obj.bin", src)
    dst = tmp_path / "out" / "obj.bin"
    store.download_to("k/obj.bin", dst)
    assert dst.read_bytes() == b"payload"


def test_presign_get_returns_file_uri(tmp_path):
    store = LocalArtifactStore(tmp_path)
    store.put_bytes("k/o", b"z")
    url = store.presign_get("k/o")
    assert url.startswith("file://")


def test_keys_are_sandboxed_within_root(tmp_path):
    store = LocalArtifactStore(tmp_path)
    # Path-traversal keys must not escape the root.
    import pytest
    with pytest.raises(ValueError):
        store.put_bytes("../escape.txt", b"nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_artifact_store_local.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.artifact_store'`.

- [ ] **Step 3: Write the implementation**

Create `app/core/artifact_store.py`:

```python
"""Blob-storage boundary for pipeline artifacts.

``ArtifactStore`` is the interface; ``LocalArtifactStore`` (filesystem) is used
by the Flask app, the CLI, and tests. ``S3ArtifactStore`` (added separately) is
the only module here permitted to import boto3.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ArtifactStore(Protocol):
    """Key→bytes blob store used to hand artifacts between pipeline stages."""

    def put_bytes(self, key: str, data: bytes) -> None: ...
    def get_bytes(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...
    def upload_from(self, key: str, path: Path) -> None: ...
    def download_to(self, key: str, path: Path) -> None: ...
    def presign_get(self, key: str, expires: int = 900) -> str: ...
    def presign_put(self, key: str, expires: int = 900) -> str: ...


class LocalArtifactStore:
    """Filesystem-backed :class:`ArtifactStore` rooted at a directory."""

    def __init__(self, root: Path):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        # Reject keys that would escape the root (path traversal).
        target = (self._root / key).resolve()
        root = self._root.resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"key escapes store root: {key!r}")
        return target

    def put_bytes(self, key: str, data: bytes) -> None:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def get_bytes(self, key: str) -> bytes:
        return self._resolve(key).read_bytes()

    def exists(self, key: str) -> bool:
        try:
            return self._resolve(key).is_file()
        except ValueError:
            return False

    def upload_from(self, key: str, path: Path) -> None:
        self.put_bytes(key, Path(path).read_bytes())

    def download_to(self, key: str, path: Path) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(self.get_bytes(key))

    def presign_get(self, key: str, expires: int = 900) -> str:
        return self._resolve(key).as_uri()

    def presign_put(self, key: str, expires: int = 900) -> str:
        return self._resolve(key).as_uri()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_artifact_store_local.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/artifact_store.py tests/test_artifact_store_local.py
git commit -m "feat: add ArtifactStore protocol and LocalArtifactStore"
```

---

### Task 7: Add `S3ArtifactStore` (boto3) with moto tests

**Files:**
- Modify: `app/core/artifact_store.py` (append `S3ArtifactStore`)
- Test: `tests/test_artifact_store_s3.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_artifact_store_s3.py
import boto3
import pytest
from moto import mock_aws

from app.core.artifact_store import S3ArtifactStore

BUCKET = "test-artifacts"


@pytest.fixture
def s3_bucket():
    with mock_aws():
        client = boto3.client("s3", region_name="us-gov-west-1")
        client.create_bucket(
            Bucket=BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "us-gov-west-1"},
        )
        yield client


def test_put_then_get_bytes_roundtrip(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    store.put_bytes("jobs/1/findings.json", b'{"a":1}')
    assert store.get_bytes("jobs/1/findings.json") == b'{"a":1}'


def test_exists(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    assert store.exists("nope") is False
    store.put_bytes("yes", b"x")
    assert store.exists("yes") is True


def test_upload_from_and_download_to(s3_bucket, tmp_path):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    store.upload_from("k/o.bin", src)
    dst = tmp_path / "d" / "o.bin"
    store.download_to("k/o.bin", dst)
    assert dst.read_bytes() == b"payload"


def test_presign_get_returns_https_url(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    store.put_bytes("k/o", b"z")
    url = store.presign_get("k/o")
    assert url.startswith("https://")
    assert "k/o" in url
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_artifact_store_s3.py -v`
Expected: FAIL — `ImportError: cannot import name 'S3ArtifactStore'`.

- [ ] **Step 3: Append the implementation to `app/core/artifact_store.py`**

Add these imports at the top of `app/core/artifact_store.py` (below the existing imports):

```python
import boto3
```

Append this class to the end of `app/core/artifact_store.py`:

```python
class S3ArtifactStore:
    """S3-backed :class:`ArtifactStore`.

    The only module member permitted to touch boto3. In GovCloud the client
    reaches S3 through the VPC gateway endpoint; presigned URLs are generated
    for the interface-endpoint host.
    """

    def __init__(self, bucket: str, region: str, client=None):
        self._bucket = bucket
        self._client = client or boto3.client("s3", region_name=region)

    def put_bytes(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def get_bytes(self, key: str) -> bytes:
        resp = self._client.get_object(Bucket=self._bucket, Key=key)
        return resp["Body"].read()

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def upload_from(self, key: str, path: Path) -> None:
        self._client.upload_file(str(path), self._bucket, key)

    def download_to(self, key: str, path: Path) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._client.download_file(self._bucket, key, str(dst))

    def presign_get(self, key: str, expires: int = 900) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )

    def presign_put(self, key: str, expires: int = 900) -> str:
        return self._client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_artifact_store_s3.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/artifact_store.py tests/test_artifact_store_s3.py
git commit -m "feat: add S3ArtifactStore with moto coverage"
```

---

### Task 8: Define `JobStore` protocol and `MemoryJobStore`

**Files:**
- Create: `app/core/job_store.py`
- Test: `tests/test_job_store_memory.py`

`JobStore` is the job-status boundary. `MemoryJobStore` reproduces the current in-memory dict semantics (thread-safe) for Flask/local; `DynamoJobStore` (Task 9) backs Lambda.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_job_store_memory.py
from app.core.job_store import MemoryJobStore


def test_create_then_get():
    store = MemoryJobStore()
    store.create("job1", status="running", progress="Starting…")
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Starting…"


def test_update_merges_fields():
    store = MemoryJobStore()
    store.create("job1", status="running")
    store.update("job1", progress="Parsing…", warnings=["w1"])
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Parsing…"
    assert job["warnings"] == ["w1"]


def test_get_missing_returns_empty_dict():
    assert MemoryJobStore().get("nope") == {}


def test_delete_removes_job():
    store = MemoryJobStore()
    store.create("job1", status="running")
    store.delete("job1")
    assert store.get("job1") == {}


def test_get_returns_a_copy():
    store = MemoryJobStore()
    store.create("job1", status="running")
    job = store.get("job1")
    job["status"] = "mutated"
    assert store.get("job1")["status"] == "running"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_job_store_memory.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.job_store'`.

- [ ] **Step 3: Write the implementation**

Create `app/core/job_store.py`:

```python
"""Job-status boundary.

``JobStore`` is the interface; ``MemoryJobStore`` (thread-safe dict) backs the
Flask app / CLI / tests. ``DynamoJobStore`` (added separately) backs Lambda and
is the only member permitted to import boto3.
"""
from __future__ import annotations

import threading
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class JobStore(Protocol):
    """Stores per-job status records keyed by job id."""

    def create(self, job_id: str, **fields: Any) -> None: ...
    def update(self, job_id: str, **fields: Any) -> None: ...
    def get(self, job_id: str) -> dict: ...
    def delete(self, job_id: str) -> None: ...


class MemoryJobStore:
    """In-process, thread-safe :class:`JobStore`."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            self._jobs[job_id] = dict(fields)

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            self._jobs.setdefault(job_id, {}).update(fields)

    def get(self, job_id: str) -> dict:
        with self._lock:
            return dict(self._jobs.get(job_id, {}))

    def delete(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_job_store_memory.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/job_store.py tests/test_job_store_memory.py
git commit -m "feat: add JobStore protocol and MemoryJobStore"
```

---

### Task 9: Add `DynamoJobStore` (boto3) with moto tests

**Files:**
- Modify: `app/core/job_store.py` (append `DynamoJobStore`)
- Test: `tests/test_job_store_dynamo.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_job_store_dynamo.py
import boto3
import pytest
from moto import mock_aws

from app.core.job_store import DynamoJobStore

TABLE = "stig-jobs"


@pytest.fixture
def jobs_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-gov-west-1")
        client.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "job_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield


def test_create_then_get(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running", progress="Starting…")
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Starting…"


def test_update_merges_fields(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running")
    store.update("job1", progress="Parsing…", warnings=["w1"])
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Parsing…"
    assert job["warnings"] == ["w1"]


def test_get_missing_returns_empty_dict(jobs_table):
    assert DynamoJobStore(TABLE, region="us-gov-west-1").get("nope") == {}


def test_delete_removes_job(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running")
    store.delete("job1")
    assert store.get("job1") == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_job_store_dynamo.py -v`
Expected: FAIL — `ImportError: cannot import name 'DynamoJobStore'`.

- [ ] **Step 3: Append the implementation to `app/core/job_store.py`**

Add this import at the top of `app/core/job_store.py` (below the existing imports):

```python
import json

import boto3
```

Append this class to the end of `app/core/job_store.py`:

```python
class DynamoJobStore:
    """DynamoDB-backed :class:`JobStore`.

    The job record is stored as a single item keyed by ``job_id``. Field values
    are JSON-encoded into a ``data`` attribute so arbitrary nested structures
    (warnings lists, summary dicts) round-trip without per-field typing. The
    only member here permitted to touch boto3.
    """

    def __init__(self, table_name: str, region: str, client=None):
        self._table = table_name
        self._client = client or boto3.client("dynamodb", region_name=region)

    def create(self, job_id: str, **fields: Any) -> None:
        self._put(job_id, dict(fields))

    def update(self, job_id: str, **fields: Any) -> None:
        record = self.get(job_id)
        record.update(fields)
        self._put(job_id, record)

    def get(self, job_id: str) -> dict:
        resp = self._client.get_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
        )
        item = resp.get("Item")
        if not item:
            return {}
        return json.loads(item["data"]["S"])

    def delete(self, job_id: str) -> None:
        self._client.delete_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
        )

    def _put(self, job_id: str, record: dict) -> None:
        self._client.put_item(
            TableName=self._table,
            Item={
                "job_id": {"S": job_id},
                "data": {"S": json.dumps(record)},
            },
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_job_store_dynamo.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add app/core/job_store.py tests/test_job_store_dynamo.py
git commit -m "feat: add DynamoJobStore with moto coverage"
```

---

### Task 10: Compose async stage entrypoints in `app/core/stages.py`

**Files:**
- Create: `app/core/stages.py`
- Test: `tests/test_stages.py`

These functions are what the future Lambda handlers (sub-project #2) will call. They operate purely through `ArtifactStore` + `JobStore`, so they are testable end-to-end with the local implementations and no AWS. `run_parse_stage` reads uploaded scan files from the store, runs `parse_stage`, and writes `findings.json` back to the store. `run_export_stage` reads `findings.json`, exports to `.xlsx`, and writes it back. Job status is updated throughout.

Storage key layout (fixed contract, reused by infra):
- Uploaded inputs: `jobs/{job_id}/input/{filename}`
- Findings handoff: `jobs/{job_id}/findings.json`
- Final report: `jobs/{job_id}/report.xlsx`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_stages.py
from pathlib import Path

import pytest

from app.core.artifact_store import LocalArtifactStore
from app.core.findings_io import findings_from_json
from app.core.job_store import MemoryJobStore
from app.core.stages import (
    INPUT_PREFIX,
    FINDINGS_KEY,
    REPORT_KEY,
    run_export_stage,
    run_parse_stage,
)

# Minimal SCC-style self-contained XCCDF sample is large; instead use a real
# fixture already present in the tests suite.
FIXTURE = Path(__file__).parent / "fixtures"


def _seed_input(store, job_id, filename, data: bytes):
    store.put_bytes(f"{INPUT_PREFIX.format(job_id=job_id)}/{filename}", data)


def test_run_parse_stage_errors_on_garbage_input(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "job1"
    jobs.create(job_id, status="running")
    _seed_input(store, job_id, "bad.xml", b"<html></html>")

    result = run_parse_stage(
        job_id, ["bad.xml"], store, jobs, work_dir=tmp_path / "w"
    )
    assert result is False
    assert jobs.get(job_id)["status"] == "error"
    assert jobs.get(job_id)["error"]


def test_run_export_stage_reads_findings_and_writes_report(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "job2"
    jobs.create(job_id, status="running")

    # Seed a findings.json directly (bypassing parse) to test export in isolation.
    findings_json = (
        '[{"stig_title":"T","vuln_id":"V-1","rule_id":"r","severity":"CAT II",'
        '"status":"Open","server":"h","ip_address":"1.1.1.1","check_text":"c",'
        '"fix_text":"f"}]'
    )
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())

    ok = run_export_stage(job_id, store, jobs, work_dir=tmp_path / "w")
    assert ok is True
    assert store.exists(REPORT_KEY.format(job_id=job_id))
    job = jobs.get(job_id)
    assert job["status"] == "complete"
    assert job["summary"]["findings"] == 1


def test_findings_key_roundtrips_through_store(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    job_id = "job3"
    findings_json = "[]"
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())
    loaded = findings_from_json(
        store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode()
    )
    assert loaded == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_stages.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.stages'`.

- [ ] **Step 3: Write the implementation**

Create `app/core/stages.py`:

```python
"""Async stage entrypoints composed over the storage and job-state boundaries.

The future Lambda handlers (sub-project #2) call these. Each function is
AWS-agnostic: it takes an ``ArtifactStore`` and a ``JobStore`` and returns a
bool indicating success, updating job status as it goes. Errors are captured
into the job record (never raised out) so the orchestrator can branch on
status rather than on exceptions.
"""
from __future__ import annotations

import logging
from pathlib import Path

from app.core.artifact_store import ArtifactStore
from app.core.findings_io import findings_from_json, findings_to_json
from app.core.job_store import JobStore
from app.core.pipeline import (
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)

log = logging.getLogger(__name__)

INPUT_PREFIX = "jobs/{job_id}/input"
FINDINGS_KEY = "jobs/{job_id}/findings.json"
REPORT_KEY = "jobs/{job_id}/report.xlsx"


def run_parse_stage(
    job_id: str,
    input_filenames: list[str],
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
) -> bool:
    """Download inputs, parse+match+filter, upload ``findings.json``.

    Returns True on success. On failure sets job status to ``error`` with a
    user-safe message and returns False.
    """
    work_dir = Path(work_dir)
    input_dir = work_dir / "input"
    extract_dir = work_dir / "extract"
    input_dir.mkdir(parents=True, exist_ok=True)

    jobs.update(job_id, status="running", progress="Parsing files…")

    local_inputs: list[Path] = []
    prefix = INPUT_PREFIX.format(job_id=job_id)
    for name in input_filenames:
        dest = input_dir / name
        store.download_to(f"{prefix}/{name}", dest)
        local_inputs.append(dest)

    try:
        result = parse_stage(local_inputs, [], extract_dir)
    except PipelineError as exc:
        jobs.update(job_id, status="error", error=str(exc))
        return False
    except Exception as exc:  # unexpected — capture, don't leak a stack trace
        log.exception("parse stage failed for job %s", job_id)
        jobs.update(job_id, status="error", error=f"Parsing failed: {exc}")
        return False

    store.put_bytes(
        FINDINGS_KEY.format(job_id=job_id),
        findings_to_json(result.findings).encode("utf-8"),
    )
    jobs.update(
        job_id,
        progress="Parsed.",
        warnings=result.warnings,
        source_file_count=result.source_file_count,
    )
    return True


def run_export_stage(
    job_id: str,
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
) -> bool:
    """Read ``findings.json``, export to xlsx, upload ``report.xlsx``.

    Returns True on success. On failure sets job status to ``error`` and
    returns False.
    """
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    jobs.update(job_id, progress="Generating Excel workbook…")

    try:
        raw = store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode("utf-8")
        findings = findings_from_json(raw)
        out_path = work_dir / default_output_name()
        export_stage(findings, out_path)
        store.upload_from(REPORT_KEY.format(job_id=job_id), out_path)
    except Exception as exc:
        log.exception("export stage failed for job %s", job_id)
        jobs.update(job_id, status="error", error=f"Export failed: {exc}")
        return False

    source_file_count = jobs.get(job_id).get("source_file_count", 0)
    summary = compute_summary(findings, source_file_count)
    jobs.update(
        job_id,
        status="complete",
        progress=f"Done — {len(findings)} findings exported.",
        summary=summary,
    )
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_stages.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -v`
Expected: PASS — all existing tests plus every new test file.

- [ ] **Step 6: Commit**

```bash
git add app/core/stages.py tests/test_stages.py
git commit -m "feat: compose async parse/export stage entrypoints over storage+job stores"
```

---

## Self-Review

**Spec coverage (against §5 Backend Re-Architecture of the master design):**
- "Introduce a job-orchestration boundary: pure functions that parse / optionally enrich / export, taking/returning S3-addressable artifacts" → Tasks 2, 5, 10 (`parse_stage`, `export_stage`, `run_parse_stage`, `run_export_stage` over `ArtifactStore`). *Enrich stage intentionally deferred to sub-project #4 — the `run_parse_stage`→`run_export_stage` seam is where the `Choice`/enrich node slots in.*
- "Provide Lambda handlers wrapping those functions" → **deferred to sub-project #2** (event shapes come from the infra/Step Functions work). Explicitly noted in the scope boundary. The stage entrypoints they will wrap are delivered here.
- "Preserve the synchronous Flask path and the CLI; they call the same core" → Tasks 3, 4, with existing `tests/test_cli.py` / `tests/test_web.py` as the green gate.
- Storage + job-state abstractions with local + AWS impls (needed by infra #2 and referenced by DynamoDB/S3 in the master design) → Tasks 6–9.

**Placeholder scan:** No "TBD"/"handle edge cases"/"similar to Task N". All code blocks are complete. Deferrals (Lambda handlers, enrich stage) are explicit scope statements tied to named sub-projects, not gaps.

**Type consistency:** `parse_stage` returns `ParseResult(findings, warnings, source_file_count)` (Task 2), consumed with those exact attributes in Tasks 3, 4, 10. `compute_summary(findings, source_file_count)` signature consistent across Tasks 2, 4, 10. `findings_to_json`/`findings_from_json` (Task 5) used in Tasks 10. `ArtifactStore` methods (`put_bytes`/`get_bytes`/`exists`/`upload_from`/`download_to`/`presign_get`/`presign_put`) identical across Local (6), S3 (7), and callers (10). `JobStore` methods (`create`/`update`/`get`/`delete`) identical across Memory (8), Dynamo (9), callers (10). Key constants `INPUT_PREFIX`/`FINDINGS_KEY`/`REPORT_KEY` defined once (Task 10) and used by its tests.

**Note for executor:** Task 10's test imports `INPUT_PREFIX.format(job_id=...)` then appends `/{filename}` — matches how `run_parse_stage` builds input keys. If `tests/fixtures/` is used by other suites, do not rely on specific fixture files in `test_stages.py` (the provided tests seed inputs inline and do not read fixture files).

# Security Residuals — stig-parser

Critical surface CLOSED + committed in `038267d` (XXE x3, Excel formula injection,
zip-bomb, secure_filename, debug=False, SECRET_KEY warn, job_id session scope,
rate limit, CLI temp cleanup). Items below are MED/LOW hardening only.

**STATUS: all 5 applied.** #1 `895ff51`; #2–5 on branch `hardening/residuals-2-5`
(upload allow-list + size cap, security headers + strict CSP with inline JS moved
to `static/app.js`, cookie hardening, dep upper-bounds + pip-audit CI gate).
240 tests pass. App is Python Flask/lxml.

## 1. MED — Error-detail leak (`app/web.py`) — ✅ RESOLVED in `895ff51`
`except Exception as exc:` handler ships `str(exc)` to client via `/api/status`.
Keep `log.exception(...)` at :295. Change the `_set_job` call:

```python
except Exception:
    log.exception("Job %s failed with unhandled exception", job_id)
    _set_job(job_id, status="error",
             error="Processing failed — see server logs.",
             warnings=list(warnings))
```
Do NOT touch the curated `error=msg` calls at :250 and :277 (intentional user text).

## 2. MED — Upload type/size validation (`app/web.py`, `process()`) — ✅ RESOLVED
Applied with allow-list `{.xml, .zip, .cklb, .nessus}` (extended from the original
`{.xml, .zip}` to cover the CKLB + Nessus parsers added since this was written).
Add module constants near rate-limit block (~line 45):
```python
_ALLOWED_UPLOAD_EXT = {".xml", ".zip"}
_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # per file
```
Add helper:
```python
def _reject_upload(fs) -> str | None:
    if Path(fs.filename).suffix.lower() not in _ALLOWED_UPLOAD_EXT:
        return f"Unsupported file type: {fs.filename!r} (allowed: .xml, .zip)"
    fs.stream.seek(0, os.SEEK_END)
    size = fs.stream.tell()
    fs.stream.seek(0)
    if size > _MAX_UPLOAD_BYTES:
        return f"File too large: {fs.filename!r} (max 200 MB each)"
    return None
```
In `process()`: AFTER the empty-results check, BEFORE `job_id`/`mkdir`, loop all
non-blank `results_files` + `benchmark_files`; on first `_reject_upload` truthy
return `jsonify({"error": msg}), 400`. (Validate before mkdir = no orphan dir.)

## 3. MED — Security headers (`app/web.py`, inside `create_app`) — ✅ RESOLVED
Took option (b): inline `<script>` moved to `app/static/app.js`, job_id passed via
`<body data-job-id>`; CSS was already external. Strict CSP shipped —
`script-src 'self'; style-src 'self'`, no `'unsafe-inline'`.

```python
@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "base-uri 'self'"
        # if (a): add  " ; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    )
    return resp
```

## 4. LOW-MED — CSRF / cookie hardening (`app/web.py`, in `create_app` after secret) — ✅ RESOLVED
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)
# SESSION_COOKIE_SECURE left False: tool runs over local http.
# Full CSRF token skipped — localhost single-user tool; SameSite=Strict
# blocks cross-site cookie send. Revisit if deployed multi-user.
```

## 5. LOW — Dependency pinning + audit — ✅ RESOLVED (also pinned boto3/moto added since)
`pyproject.toml`: add upper bounds —
`flask>=3.0,<4.0`, `lxml>=5.0,<6.0`, `openpyxl>=3.1,<4.0`,
`pytest>=8.0,<9.0`, `pytest-cov>=4.0,<6.0`; add `"pip-audit>=2.7"` to `dev`.
`.github/workflows/ci.yml`: add step after "Install dependencies":
```yaml
      - name: Security audit (dependencies)
        run: pip-audit
```

## Done criteria
`pytest tests/ -v` green (was 146/146), then commit all changed files with a
message describing the hardening pass.

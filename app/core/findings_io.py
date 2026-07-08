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

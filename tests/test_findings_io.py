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

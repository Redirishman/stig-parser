"""Every kind of input problem the run reports, with the exact lines the operator must see.

Shared by the web, CLI and pipeline tests: each problem is reported once, by the run's own
warning, which says why. A case is one or more files next to a good scan, the archive limits
lowered for it where it needs them, the file its lines are about (its subject), and those
lines, exactly. Not collected by pytest (the name does not start with ``test_``).
"""
from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from app.parsers.benchmark_parser import _safe_xml_parse
from app.reference.normalize import error_text

FIXTURES = Path(__file__).parent / "fixtures"
GOOD = FIXTURES / "scc_embedded_results.xml"
MISSING = "any scan results or STIG references among them are missing from this report"
# A minimal results file with a host: a member that is read and named only by its own name.
SCAN = b'<TestResult><target>H</target><target-address>10.0.0.9</target-address>' \
       b'<rule-result idref="SV-1r1_rule"><result>fail</result></rule-result></TestResult>'


def xml_error(payload: bytes) -> str:
    """What the hardened parser says about *payload*, as the operator reads it."""
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        probe = Path(folder) / "probe.xml"
        probe.write_bytes(payload)
        try:
            _safe_xml_parse(probe)
        except etree.XMLSyntaxError as exc:
            return error_text(exc)
    raise AssertionError("the payload parsed")


def json_error(payload: bytes) -> str:
    try:
        json.loads(payload.decode("utf-8"))
    except ValueError as exc:
        return error_text(exc)
    raise AssertionError("the payload parsed")


def zip_bytes(members: dict[str, bytes], *, encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)
    data = bytearray(buf.getvalue())
    if encrypted:       # general-purpose flag bit 0 on every header, as a password-protected ZIP has
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            at = data.find(signature)
            while at != -1:
                data[at + offset] |= 0x01
                at = data.find(signature, at + 4)
    return bytes(data)


def bad_crc_zip() -> bytes:
    marker = b"MARKER-" + bytes(range(256))
    data = bytearray(zip_bytes({"damaged.xml": b"<TestResult><!--" + marker + b"--></TestResult>"}))
    data[data.find(marker) + 100] ^= 0xFF
    return bytes(data)


def nested(levels: int, innermost: dict[str, bytes]) -> bytes:
    """*innermost* inside *levels* ZIPs, the inner ones named l1.zip, l2.zip, …"""
    data = zip_bytes(innermost)
    for level in range(levels - 1, 0, -1):
        data = zip_bytes({f"l{level}.zip": data})
    return data


def checklist(stigs: list, **target) -> bytes:
    doc = {"stigs": stigs}
    if target:
        doc["target_data"] = target
    return json.dumps(doc).encode()


RULE = {"rule_id": "SV-254239r958472_rule", "group_id": "V-254239", "rule_version": "WN22-00-000010",
        "severity": "high", "status": "open", "check_content": "Check it.", "fix_text": "Fix it."}


@dataclass
class ProblemCase:
    id: str
    files: list[tuple[str, str, bytes]]     # (zone: "results" or "references", name, bytes)
    subject: str                            # the file the lines are about
    expected: list[str]                     # every run warning that names the subject, in order
    patches: dict[str, int] = field(default_factory=dict)   # app.utils.zip_extract limits for this case
    # Detail log lines that name the subject and that the run does not report (web and CLI show
    # them before the run's warnings): never a restatement of an expected line.
    detail: list[str] = field(default_factory=list)

    @property
    def shown(self) -> list[str]:
        """What the web card and the CLI show about the subject, in order."""
        return [*self.detail, *self.expected]


def problem_cases() -> list[ProblemCase]:
    bare = (b'<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="t"><target>h3</target>'
            b'<target-address>10.0.0.3</target-address></TestResult>')
    vuln = (b'<NessusClientData_v2><Report name="r"><ReportHost name="h2"><HostProperties/>'
            b'<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="1" pluginName="x" '
            b'pluginFamily="General"/></ReportHost></Report></NessusClientData_v2>')
    server = {"stig_id": "MS_Windows_Server_2022_STIG", "display_name": "Microsoft Windows Server 2022 STIG"}
    return [
        ProblemCase("invalid-xml", [("results", "broken.xml", b"<a><b></a>")], "broken.xml",
                    ["Could not parse results file: broken.xml — invalid XML: " + xml_error(b"<a><b></a>")]),
        ProblemCase("legacy-ckl", [("results", "old.ckl.xml",
                                    b'<?xml version="1.0"?><CHECKLIST><ASSET/></CHECKLIST>')], "old.ckl.xml",
                    ["old.ckl.xml: STIG Viewer .ckl checklists are not supported — save it as .cklb in "
                     "STIG Viewer 3 and upload that"]),
        ProblemCase("no-rule-results", [("results", "bare.xml", bare)], "bare.xml",
                    ["bare.xml: 0 rule results — not counted as a scan; if this file is a benchmark, "
                     "pass it as a reference"],
                    detail=["Could not identify scanner for bare.xml — defaulting to Unknown"]),
        ProblemCase("cklb-not-json", [("results", "broken.cklb", b"{not json")], "broken.cklb",
                    ["Could not parse results file: broken.cklb — not valid JSON: " + json_error(b"{not json")]),
        ProblemCase("cklb-no-stigs", [("results", "nostigs.cklb", b'{"hello": 1}')], "nostigs.cklb",
                    ["Could not parse results file: nostigs.cklb — not a CKLB checklist (no 'stigs' array)"]),
        ProblemCase("cklb-no-rules", [("results", "empty.cklb", checklist(
                        [{"stig_id": "S", "rules": []}], host_name="h1", ip_address="10.0.0.9"))], "empty.cklb",
                    ["empty.cklb: 0 rule results — not counted as a scan; the checklist has no rules"]),
        ProblemCase("cklb-non-text-reference-pass-only", [("results", "idnum.cklb", checklist(
                        [{**server, "stig_id": 7, "rules": [RULE]}], host_name="h4", ip_address="10.0.0.4"))],
                    "idnum.cklb",
                    ["idnum.cklb: at least 1 non-text value(s) in the checklist were ignored"]),
        ProblemCase("cklb-non-text-both-passes", [("results", "textnum.cklb", checklist(
                        [{**server, "rules": [{**RULE, "check_content": 5}]}], host_name="h5",
                        ip_address="10.0.0.5"))], "textnum.cklb",
                    ["textnum.cklb: 1 non-text value(s) in the checklist were ignored"]),
        ProblemCase("nessus-invalid-xml", [("results", "broken.nessus", b"<NessusClientData_v2><Report>")],
                    "broken.nessus",
                    ["Could not parse results file: broken.nessus — invalid XML: "
                     + xml_error(b"<NessusClientData_v2><Report>")]),
        ProblemCase("nessus-wrong-root", [("results", "notes.nessus", b"<foo/>")], "notes.nessus",
                    ["Could not parse results file: notes.nessus — not a Nessus export "
                     "(root element is <foo>, expected <NessusClientData_v2>)"]),
        ProblemCase("nessus-no-compliance", [("results", "vuln.nessus", vuln)], "vuln.nessus",
                    ["vuln.nessus: 0 rule results — not counted as a scan; no Policy Compliance items "
                     "(a vulnerability scan is not a compliance scan)"]),
        ProblemCase("benchmark-invalid-xml", [("references", "broken_ref.xml", b"<Benchmark><unclosed>")],
                    "broken_ref.xml",
                    ["Could not parse benchmark: broken_ref.xml — invalid XML: "
                     + xml_error(b"<Benchmark><unclosed>")]),
        ProblemCase("benchmark-no-rules", [("references", "empty_bench.xml",
                                            b'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="b"/>')],
                    "empty_bench.xml", ["empty_bench.xml: reference contains 0 rules — ignored"]),
        ProblemCase("benchmark-none", [("references", "report.xml", b"<report><row/></report>")], "report.xml",
                    ["Could not parse benchmark: report.xml — no Benchmark element"]),
        ProblemCase("reference-cklb-not-json", [("references", "broken_ref.cklb", b"[1,2")], "broken_ref.cklb",
                    ["Could not parse reference checklist: broken_ref.cklb — not valid JSON: "
                     + json_error(b"[1,2")]),
        ProblemCase("reference-cklb-non-text", [("references", "ref.cklb", checklist(
                        [{**server, "rules": [{**RULE, "check_content": 123}]}]))], "ref.cklb",
                    ["ref.cklb: 1 non-text value(s) in the checklist were ignored",
                     "ref.cklb: 0 of 1 rules carry check text"]),
        ProblemCase("reference-cklb-entry-without-rules", [("references", "noentry.cklb", checklist(
                        [{**server, "rules": [RULE]}, {"display_name": "Broken STIG"}]))], "noentry.cklb",
                    ["noentry.cklb: 1 malformed checklist entry was skipped"]),
        ProblemCase("zip-not-a-zip", [("references", "bad.zip", b"PK not really")], "bad.zip",
                    ["bad.zip: not a readable ZIP — not read"]),
        ProblemCase("zip-password", [("results", "locked.zip", zip_bytes({"s.xml": SCAN}, encrypted=True))],
                    "locked.zip", ["locked.zip: password-protected — not read"]),
        ProblemCase("zip-too-many-entries", [("results", "many.zip",
                                              zip_bytes({f"m{i}.xml": SCAN for i in range(5)}))],
                    "many.zip", ["many.zip: more than 3 entries — not read"], {"_MAX_ENTRIES": 3}),
        ProblemCase("zip-entry-list-too-large", [("results", "long.zip",
                                                  zip_bytes({"a" * 60 + ".xml": SCAN, "b" * 60 + ".xml": SCAN}))],
                    "long.zip", ["long.zip: entry list over 200 bytes — not read"],
                    {"_MAX_ENTRIES": 5, "_DIRECTORY_BYTES_PER_ENTRY": 40}),
        ProblemCase("member-unreadable", [("results", "crc.zip", bad_crc_zip())], "crc.zip",
                    ["crc.zip: could not read damaged.xml: Bad CRC-32 for file 'damaged.xml' — skipped"]),
        ProblemCase("member-too-large", [("results", "big.zip", zip_bytes(
                        {"big.xml": b"<TestResult><!--" + b"p" * 2000 + b"--></TestResult>", "s1.xml": SCAN}))],
                    "big.zip", ["big.zip: big.xml is larger than the 1000-byte limit — skipped"],
                    {"_MAX_EXTRACTED_BYTES": 1000}),
        ProblemCase("member-not-a-zip", [("references", "refs.zip", zip_bytes({"inner.zip": b"PK no"}))],
                    "refs.zip", ["refs.zip: inner.zip is not a readable ZIP — skipped"]),
        ProblemCase("member-password", [("results", "wrap.zip", zip_bytes(
                        {"inner.zip": zip_bytes({"s.xml": SCAN}, encrypted=True), "s2.xml": SCAN}))],
                    "wrap.zip", ["wrap.zip: inner.zip is password-protected — skipped"]),
        ProblemCase("member-too-many-entries", [("results", "outer.zip", zip_bytes(
                        {"inner.zip": zip_bytes({f"m{i}.xml": SCAN for i in range(5)}), "s3.xml": SCAN}))],
                    "outer.zip", ["outer.zip: inner.zip has more than 3 entries — skipped"], {"_MAX_ENTRIES": 3}),
        ProblemCase("member-nested-too-deep", [("results", "deep.zip", nested(3, {"l3.zip": b"", "s4.xml": SCAN}))],
                    "deep.zip", ["deep.zip: l3.zip is nested more than 2 ZIPs deep — skipped"]),
        ProblemCase("members-nested-too-deep-flood", [("results", "flood.zip", nested(
                        3, {**{f"x{n}.zip": b"" for n in range(1, 8)}, "s5.xml": SCAN}))], "flood.zip",
                    [f"flood.zip: x{n}.zip is nested more than 2 ZIPs deep — skipped" for n in range(1, 6)]
                    + ["flood.zip: … and 2 more skipped"]),
        ProblemCase("archive-member-limit", [("results", "count.zip",
                                              zip_bytes({"c1.xml": SCAN, "c2.xml": SCAN, "c3.xml": SCAN}))],
                    "count.zip", [f"count.zip: member limit reached — 1 more file(s) not checked; {MISSING}"],
                    {"_MAX_MEMBERS": 2}),
        ProblemCase("archive-size-limit", [("results", "size.zip", zip_bytes({"z1.xml": SCAN, "z2.xml": SCAN}))],
                    "size.zip", [f"size.zip: size limit reached — 1 more file(s) not checked; {MISSING}"],
                    {"_MAX_ARCHIVE_BYTES": len(SCAN) + 10}),
        ProblemCase("run-limit", [("results", "one.zip", zip_bytes({"r1.xml": SCAN})),
                                  ("results", "two.zip", zip_bytes({"r2.xml": SCAN}))],
                    "two.zip", ["two.zip: not read — the limit for one run was reached"], {"_MAX_RUN_MEMBERS": 1}),
    ]

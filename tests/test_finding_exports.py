from __future__ import annotations

import json

from argus.reporting.exports import findings_json, findings_sarif

from tests.control.helpers import make_finding, make_project, make_scan


def test_json_and_sarif_exports_are_deterministic_canonical_finding_views() -> None:
    finding = make_finding(make_scan(make_project()))

    json_first = findings_json([finding])
    sarif_first = findings_sarif([finding])

    assert findings_json([finding]) == json_first
    assert findings_sarif([finding]) == sarif_first
    exported_json = json.loads(json_first)
    exported_sarif = json.loads(sarif_first)
    assert exported_json[0]["fingerprint"] == finding.fingerprint
    result = exported_sarif["runs"][0]["results"][0]
    assert result["fingerprints"]["argus/v2"] == finding.fingerprint
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

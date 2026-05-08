from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "audit-output.schema.json"
SEVERITIES = {"low", "medium", "high", "critical"}
RULE_PATTERN = re.compile(r"^MCP-[0-9]{3}$")


def fail(message: str) -> None:
    raise AssertionError(message)


def validate_schema_file() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    required = schema.get("required", [])
    if required != ["risk_score", "findings"]:
        fail("audit output schema must require risk_score and findings")
    finding_schema = schema["properties"]["findings"]["items"]
    for field in ("severity", "rule_id", "server", "message", "recommendation", "evidence"):
        if field not in finding_schema["required"]:
            fail(f"audit output schema must require finding field: {field}")


def validate_report(path: Path) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    if sorted(report.keys()) != ["findings", "risk_score"]:
        fail("audit JSON output must contain only findings and risk_score")
    if not isinstance(report["risk_score"], int) or not 0 <= report["risk_score"] <= 100:
        fail("risk_score must be an integer from 0 to 100")
    if not isinstance(report["findings"], list):
        fail("findings must be a list")

    for finding in report["findings"]:
        if sorted(finding.keys()) != ["evidence", "message", "recommendation", "rule_id", "server", "severity"]:
            fail("finding has unexpected fields")
        if finding["severity"] not in SEVERITIES:
            fail(f"invalid severity: {finding['severity']}")
        if not RULE_PATTERN.match(finding["rule_id"]):
            fail(f"invalid rule id: {finding['rule_id']}")
        for field in ("server", "message", "recommendation"):
            if not isinstance(finding[field], str) or not finding[field]:
                fail(f"finding.{field} must be a non-empty string")
        if not isinstance(finding["evidence"], str):
            fail("finding.evidence must be a string")


def main(argv: list[str]) -> int:
    validate_schema_file()
    if len(argv) > 1:
        for raw_path in argv[1:]:
            validate_report(Path(raw_path))
    print("JSON output contract validation passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except AssertionError as exc:
        print(f"JSON output contract validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_agent_security_kit.audit import (  # noqa: E402
    compare_allowed_tool_drift,
    load_config,
    render_allowed_tool_drift_json,
    render_allowed_tool_drift_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare allowed MCP tools between a baseline and current config.")
    parser.add_argument("baseline", type=Path, help="Approved baseline MCP JSON configuration.")
    parser.add_argument("current", type=Path, help="Current MCP JSON configuration.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format.")
    parser.add_argument("--output", type=Path, help="Optional output report path.")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="Exit with status 1 when drift at or above this severity exists.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    drift = compare_allowed_tool_drift(load_config(args.baseline), load_config(args.current))
    report = render_allowed_tool_drift_json(drift) if args.format == "json" else render_allowed_tool_drift_markdown(drift)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)

    if args.fail_on == "none":
        return 0

    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = order[args.fail_on]
    return 1 if any(order[item.severity] >= threshold for item in drift) else 0


if __name__ == "__main__":
    raise SystemExit(main())


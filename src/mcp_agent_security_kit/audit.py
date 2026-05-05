from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"low": 3, "medium": 10, "high": 20, "critical": 35}

SECRET_NAME_PATTERN = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|credential|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
DANGEROUS_ARG_PATTERN = re.compile(
    r"(--privileged|--net=host|--network=host|--unsafe|--allow-all|--dangerously|--no-sandbox|--disable-sandbox)",
    re.IGNORECASE,
)
SHELL_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "python", "python3", "node", "ruby", "perl"}
PACKAGE_RUNNERS = {"npx", "pnpm", "npm", "bunx", "uvx", "pipx"}
FILESYSTEM_WORDS = ("filesystem", "file", "fs", "directory", "path")


@dataclass(frozen=True)
class Finding:
    severity: str
    rule_id: str
    server: str
    message: str
    recommendation: str
    evidence: str = ""


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("MCP configuration must be a JSON object.")
    return loaded


def extract_servers(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(config.get("mcpServers"), dict):
        return _dict_servers(config["mcpServers"])
    if isinstance(config.get("servers"), dict):
        return _dict_servers(config["servers"])
    if all(isinstance(value, dict) for value in config.values()):
        return _dict_servers(config)
    if "command" in config or "url" in config:
        return {"default": config}
    return {}


def _dict_servers(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(name): server for name, server in value.items() if isinstance(server, dict)}


def audit_config(config: dict[str, Any]) -> list[Finding]:
    servers = extract_servers(config)
    findings: list[Finding] = []
    if not servers:
        findings.append(
            Finding(
                severity="medium",
                rule_id="MCP-000",
                server="configuration",
                message="No MCP servers were found in the configuration.",
                recommendation="Use an MCP configuration shape with mcpServers, servers, or a server object.",
            )
        )
        return findings

    for server_name, server in servers.items():
        findings.extend(audit_server(server_name, server))
    return sorted(findings, key=lambda item: (-SEVERITY_ORDER[item.severity], item.server, item.rule_id))


def audit_server(name: str, server: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    command = _command_name(server.get("command"))
    args = _string_list(server.get("args"))
    env = server.get("env") if isinstance(server.get("env"), dict) else {}
    headers = server.get("headers") if isinstance(server.get("headers"), dict) else {}
    url = str(server.get("url", "") or server.get("endpoint", "") or "")
    text_blob = " ".join([command, url, *args]).lower()

    if url.startswith("http://"):
        findings.append(
            Finding(
                "critical",
                "MCP-001",
                name,
                "Remote MCP server uses unencrypted HTTP.",
                "Use HTTPS with certificate validation for remote MCP traffic.",
                url,
            )
        )

    if url.startswith(("http://", "https://")) and not _has_auth_signal(headers, env, server):
        findings.append(
            Finding(
                "high",
                "MCP-002",
                name,
                "Remote MCP server has no clear authentication signal.",
                "Require user or service authentication and pass tokens through a controlled client path.",
                url,
            )
        )

    for key, value in env.items():
        if SECRET_NAME_PATTERN.search(str(key)) and value:
            findings.append(
                Finding(
                    "high",
                    "MCP-003",
                    name,
                    "Secret-like environment variable is configured inline.",
                    "Load secrets from a secret manager or local protected environment, not committed configuration.",
                    str(key),
                )
            )

    if command in PACKAGE_RUNNERS and _runner_package_unpinned(command, args):
        findings.append(
            Finding(
                "medium",
                "MCP-004",
                name,
                "Package runner is used without an obvious package version pin.",
                "Pin package versions or use a reviewed local wrapper to reduce supply-chain drift.",
                " ".join([command, *args]),
            )
        )

    if command in SHELL_COMMANDS and _looks_like_evaluator(command, args):
        findings.append(
            Finding(
                "critical",
                "MCP-005",
                name,
                "Shell or evaluator command can execute arbitrary code.",
                "Avoid shell evaluators in MCP configs. Use a narrow wrapper with fixed behavior and limited inputs.",
                " ".join([command, *args]),
            )
        )

    dangerous_args = [arg for arg in args if DANGEROUS_ARG_PATTERN.search(arg)]
    if dangerous_args:
        findings.append(
            Finding(
                "critical",
                "MCP-006",
                name,
                "Dangerous execution flags are present.",
                "Remove privileged, host-network, unsafe, or sandbox-disabling flags unless formally approved.",
                " ".join(dangerous_args),
            )
        )

    broad_paths = [arg for arg in args if _is_broad_path(arg)]
    if broad_paths:
        findings.append(
            Finding(
                "high",
                "MCP-007",
                name,
                "Broad filesystem access is granted.",
                "Scope filesystem access to a narrow project directory and prefer read-only access.",
                ", ".join(broad_paths),
            )
        )

    if command == "docker" and any(arg in {"--privileged", "--net=host", "--network=host", "-v", "--volume"} for arg in args):
        findings.append(
            Finding(
                "high",
                "MCP-008",
                name,
                "Docker-based MCP server uses privileged, host network, or host volume access.",
                "Use a restricted container profile, narrow mounts, read-only filesystems, and no host networking.",
                " ".join(args),
            )
        )

    if not any(key in server for key in ("owner", "riskOwner", "risk_owner", "maintainer")):
        findings.append(
            Finding(
                "low",
                "MCP-009",
                name,
                "Server has no visible owner or risk owner metadata.",
                "Record the technical owner and risk owner for each MCP server.",
            )
        )

    if any(word in name.lower() or word in text_blob for word in FILESYSTEM_WORDS) and "readonly" not in text_blob and "read-only" not in text_blob:
        findings.append(
            Finding(
                "medium",
                "MCP-010",
                name,
                "Filesystem-like tool lacks a read-only signal.",
                "Use read-only mode where possible and document any write access requirement.",
                " ".join([command, *args]),
            )
        )

    return findings


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_SCORE[item.severity] for item in findings))


def render_markdown(findings: list[Finding]) -> str:
    lines = [
        "# MCP Agent Security Audit",
        "",
        f"Risk score: {risk_score(findings)} / 100",
        "",
    ]
    if not findings:
        lines.extend(["No findings detected.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Server | Finding | Recommendation | Evidence |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        lines.append(
            "| {severity} | {rule_id} | {server} | {message} | {recommendation} | {evidence} |".format(
                severity=finding.severity,
                rule_id=finding.rule_id,
                server=_escape_cell(finding.server),
                message=_escape_cell(finding.message),
                recommendation=_escape_cell(finding.recommendation),
                evidence=_escape_cell(finding.evidence),
            )
        )
    lines.append("")
    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "risk_score": risk_score(findings),
            "findings": [asdict(item) for item in findings],
        },
        indent=2,
    )


def write_output(text: str, output_path: Path | None) -> None:
    if output_path is None:
        print(text)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def should_fail(findings: list[Finding], threshold: str) -> bool:
    if threshold == "none":
        return False
    required = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[item.severity] >= required for item in findings)


def _command_name(value: Any) -> str:
    if not value:
        return ""
    command = str(value).strip().strip('"').strip("'")
    return os.path.basename(command).lower()


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _has_auth_signal(headers: dict[str, Any], env: dict[str, Any], server: dict[str, Any]) -> bool:
    header_names = {str(key).lower() for key in headers}
    if "authorization" in header_names or "x-api-key" in header_names:
        return True
    if any(SECRET_NAME_PATTERN.search(str(key)) for key in env):
        return True
    return any(str(key).lower() in {"auth", "oauth", "token", "credential", "credentials"} for key in server)


def _runner_package_unpinned(command: str, args: list[str]) -> bool:
    package = _first_package_arg(args)
    if not package:
        return True
    if command == "uvx":
        return not any(marker in package for marker in ("==", "@", "git+", "file:"))
    if package.startswith("@") and "/" in package:
        _, _, rest = package.partition("/")
        return "@" not in rest
    return "@" not in package and "git+" not in package and "file:" not in package


def _first_package_arg(args: list[str]) -> str:
    skip_next = False
    for index, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in {"-y", "--yes", "--quiet"}:
            continue
        if arg in {"--package", "-p"}:
            if index + 1 < len(args):
                return args[index + 1]
            return ""
        if arg.startswith("-"):
            continue
        return arg
    return ""


def _looks_like_evaluator(command: str, args: list[str]) -> bool:
    if command in {"python", "python3", "node", "ruby", "perl"}:
        return any(arg in {"-c", "-e"} for arg in args)
    return command in {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}


def _is_broad_path(value: str) -> bool:
    normalized = value.strip().strip('"').strip("'")
    lowered = normalized.lower()
    if normalized in {"/", "\\", ".", "..", "~"}:
        return True
    if re.fullmatch(r"[a-zA-Z]:\\?", normalized):
        return True
    return lowered in {"/users", "/home", "/var", "/etc", "c:\\users", "c:\\", "c:/", "/tmp"}


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit MCP server configuration for common agentic AI security risks.")
    parser.add_argument("config", type=Path, help="Path to an MCP JSON configuration file.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format.")
    parser.add_argument("--output", type=Path, help="Optional output report path.")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit with status 1 when findings at or above this severity exist.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    findings = audit_config(config)
    report = render_json(findings) if args.format == "json" else render_markdown(findings)
    write_output(report, args.output)
    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())

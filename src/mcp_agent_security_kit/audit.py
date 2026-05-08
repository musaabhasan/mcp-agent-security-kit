from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"low": 3, "medium": 10, "high": 20, "critical": 35}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
SARIF_SECURITY_SEVERITY = {"low": "3.0", "medium": "5.0", "high": "7.5", "critical": "9.0"}

SECRET_NAME_PATTERN = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|credential|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
DANGEROUS_ARG_PATTERN = re.compile(
    r"(--privileged|--net=host|--network=host|--unsafe|--allow-all|--dangerously|--no-sandbox|--disable-sandbox)",
    re.IGNORECASE,
)
TLS_SKIP_ARG_PATTERN = re.compile(
    r"^(--insecure|-k|--skip-tls-verify|--skip-verify|--no-verify|--tls-skip-verify|--disable-tls-verification)$",
    re.IGNORECASE,
)
SHELL_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "python", "python3", "node", "ruby", "perl"}
PACKAGE_RUNNERS = {"npx", "pnpm", "npm", "bunx", "uvx", "pipx"}
FILESYSTEM_WORDS = ("filesystem", "file", "fs", "directory", "path")
DOCKER_SOCKET_MARKERS = (
    "/var/run/docker.sock",
    "docker.sock",
    "//./pipe/docker_engine",
    "npipe:////./pipe/docker_engine",
)
DOCKER_OPTIONS_WITH_VALUES = {
    "-e",
    "--env",
    "--env-file",
    "-h",
    "--hostname",
    "--add-host",
    "--dns",
    "--entrypoint",
    "-l",
    "--label",
    "-m",
    "--memory",
    "--mount",
    "--name",
    "--network",
    "-p",
    "--publish",
    "--platform",
    "-u",
    "--user",
    "-v",
    "--volume",
    "-w",
    "--workdir",
}
AUTO_APPROVAL_KEYS = {
    "alwaysallow",
    "alwaysallowed",
    "autoallow",
    "autoallowed",
    "autoapprove",
    "autoapproved",
    "allowwithoutconfirmation",
    "allowedtools",
    "allowed_tools",
}
AUTO_APPROVAL_WILDCARDS = {"*", "all", "any", ".*"}
EXTERNAL_ACTION_TOOL_PATTERN = re.compile(
    r"(^|[_:.-])("
    r"approve|commit|create|delete|deploy|email|grant|http|invite|merge|"
    r"message|payment|post|publish|push|refund|remove|request|send|submit|"
    r"ticket|transfer|update|upload|webhook|write"
    r")([_:.-]|$)",
    re.IGNORECASE,
)
TLS_VERIFY_FALSE_KEYS = {
    "rejectunauthorized",
    "reject_unauthorized",
    "sslverify",
    "ssl_verify",
    "tlsverify",
    "tls_verify",
    "verifyssl",
    "verify_ssl",
    "verifytls",
    "verify_tls",
    "verifycert",
    "verify_cert",
    "verifycertificate",
    "verify_certificate",
}
TLS_SKIP_TRUE_KEYS = {
    "allowinsecure",
    "allow_insecure",
    "insecure",
    "skiptlsverify",
    "skip_tls_verify",
    "skipverify",
    "skip_verify",
    "tlsinsecure",
    "tls_insecure",
}
BROAD_AUTH_SCOPE_KEYS = {
    "scope",
    "scopes",
    "oauthscope",
    "oauthscopes",
    "permission",
    "permissions",
    "authscope",
    "authscopes",
    "oauthpermissions",
}
BROAD_AUTH_SCOPE_PATTERN = re.compile(
    r"(^\*$|(^|[:/._-])(admin|administrator|root|owner|full[-_ ]?access|read[-_ ]?write|delete)(?:$|[:/._-])|[:.]\*$)",
    re.IGNORECASE,
)
SENSITIVE_CREDENTIAL_PATH_PATTERNS = (
    re.compile(r"(^|/|:|=|,|;|~)(\.ssh)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.aws)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.azure)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.kube)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.docker)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.gnupg)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;)(\.config/gcloud)(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;)(\.npmrc|\.pypirc|\.netrc|\.git-credentials)$", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$", re.IGNORECASE),
)
ENV_FILE_OPTIONS = {"--env-file", "--envfile", "--dotenv", "--dotenv-file", "--env-file-path"}
SAFE_ENV_FILE_SUFFIXES = (".example", ".sample", ".template", ".dist")
BROWSER_PROFILE_OPTIONS = {
    "--user-data-dir",
    "--profile-path",
    "--browser-profile",
    "--browser-profile-dir",
}
BROWSER_SESSION_OPTIONS = {
    "--auth-state",
    "--cookie-db",
    "--cookie-file",
    "--cookies",
    "--session-file",
    "--storage-state",
}
BROWSER_PROFILE_PATH_PATTERNS = (
    re.compile(r"(^|/|:|=|,|;|~)(\.config/(google-chrome|chromium|brave-browser|microsoft-edge))(/|:|$)", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;|~)(\.mozilla/firefox)(/|:|$)", re.IGNORECASE),
    re.compile(r"(library/application support/(google/chrome|chromium|brave[- ]browser|microsoft edge))", re.IGNORECASE),
    re.compile(r"(appdata/(local|roaming)/(google/chrome|chromium|bravesoftware|microsoft/edge|mozilla/firefox))", re.IGNORECASE),
    re.compile(r"(^|/|:|=|,|;)(cookies|cookies\.sqlite|logins\.json|key4\.db|local state)$", re.IGNORECASE),
)
CLOUD_METADATA_PATTERNS = (
    re.compile(r"169\.254\.169\.254", re.IGNORECASE),
    re.compile(r"100\.100\.100\.200", re.IGNORECASE),
    re.compile(r"fd00:ec2::254", re.IGNORECASE),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"metadata\.azure\.internal", re.IGNORECASE),
    re.compile(r"/latest/meta-data", re.IGNORECASE),
    re.compile(r"/computeMetadata/v1", re.IGNORECASE),
    re.compile(r"/metadata/instance", re.IGNORECASE),
    re.compile(r"/opc/v[12]/instance", re.IGNORECASE),
)
NETWORK_ALLOWLIST_KEYS = {
    "alloweddomains",
    "allowedhosts",
    "allowedurls",
    "alloweddestinations",
    "allowdomains",
    "allowhosts",
    "allowurls",
    "allowdestinations",
    "domainallowlist",
    "egressallowlist",
    "hostallowlist",
    "networkallowlist",
    "urlallowlist",
}
NETWORK_ALLOWLIST_WILDCARDS = {"*", "all", "any", "0.0.0.0/0", "::/0", "http://*", "https://*"}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule_id: str
    server: str
    message: str
    recommendation: str
    evidence: str = ""


@dataclass(frozen=True)
class AllowedToolDrift:
    severity: str
    server: str
    tool: str
    change: str
    message: str
    recommendation: str


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


def extract_allowed_tools(config: dict[str, Any]) -> dict[str, set[str]]:
    servers = extract_servers(config)
    return {
        server_name: tools
        for server_name, server in servers.items()
        if (tools := _allowed_tools_for_server(server))
    }


def compare_allowed_tool_drift(
    baseline_config: dict[str, Any], current_config: dict[str, Any]
) -> list[AllowedToolDrift]:
    baseline = extract_allowed_tools(baseline_config)
    current = extract_allowed_tools(current_config)
    drift: list[AllowedToolDrift] = []

    for server in sorted(set(baseline) | set(current)):
        baseline_tools = baseline.get(server, set())
        current_tools = current.get(server, set())

        for tool in sorted(current_tools - baseline_tools):
            severity = _allowed_tool_drift_severity(tool, "added")
            drift.append(
                AllowedToolDrift(
                    severity=severity,
                    server=server,
                    tool=tool,
                    change="added",
                    message="Allowed tool was added after the approved baseline.",
                    recommendation=_allowed_tool_recommendation(tool, severity),
                )
            )

        for tool in sorted(baseline_tools - current_tools):
            drift.append(
                AllowedToolDrift(
                    severity="low",
                    server=server,
                    tool=tool,
                    change="removed",
                    message="Allowed tool was removed from the approved baseline.",
                    recommendation="Confirm dependent workflows no longer require this tool and keep the removal in the change record.",
                )
            )

    return sorted(drift, key=lambda item: (-SEVERITY_ORDER[item.severity], item.server, item.change, item.tool))


def render_allowed_tool_drift_markdown(drift: list[AllowedToolDrift]) -> str:
    lines = ["# MCP Allowed Tool Drift", ""]
    if not drift:
        lines.extend(["No allowed-tool drift detected.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Server | Tool | Change | Finding | Recommendation |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in drift:
        lines.append(
            "| {severity} | {server} | {tool} | {change} | {message} | {recommendation} |".format(
                severity=item.severity,
                server=_escape_cell(item.server),
                tool=_escape_cell(item.tool),
                change=item.change,
                message=_escape_cell(item.message),
                recommendation=_escape_cell(item.recommendation),
            )
        )
    lines.append("")
    return "\n".join(lines)


def render_allowed_tool_drift_json(drift: list[AllowedToolDrift]) -> str:
    return json.dumps({"drift": [asdict(item) for item in drift]}, indent=2)


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

    broad_auth_scopes = _broad_auth_scopes(server)
    if broad_auth_scopes:
        findings.append(
            Finding(
                "high",
                "MCP-019",
                name,
                "Authentication scopes or permissions look overbroad.",
                "Use the narrowest provider scopes needed by this MCP server and require owner approval for administrative, wildcard, delete, or full-access permissions.",
                ", ".join(broad_auth_scopes),
            )
        )

    tls_validation_disabled = _tls_validation_disabled(server, env, args)
    if tls_validation_disabled:
        findings.append(
            Finding(
                "high",
                "MCP-015",
                name,
                "TLS certificate validation is disabled.",
                "Keep certificate validation enabled for remote MCP traffic and fix trust-store or certificate-chain issues instead of bypassing verification.",
                ", ".join(tls_validation_disabled),
            )
        )

    url_secret_params = _inline_secret_query_params(url)
    if url_secret_params:
        findings.append(
            Finding(
                "high",
                "MCP-013",
                name,
                "Secret-like URL query parameter is configured inline.",
                "Move tokens and credentials out of MCP server URLs and inject them through a protected runtime secret path.",
                ", ".join(url_secret_params),
            )
        )

    url_userinfo_secrets = _inline_url_userinfo_secrets(url)
    if url_userinfo_secrets:
        findings.append(
            Finding(
                "high",
                "MCP-014",
                name,
                "Credential-like URL userinfo is configured inline.",
                "Move URL userinfo credentials into a protected runtime secret path and use header-based or client-managed authentication.",
                ", ".join(url_userinfo_secrets),
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

    for key, value in headers.items():
        header_name = str(key)
        if _is_secret_header(header_name) and _is_inline_secret_value(value):
            findings.append(
                Finding(
                    "high",
                    "MCP-011",
                    name,
                    "Secret-like HTTP header value is configured inline.",
                    "Inject authorization headers at runtime from a secret manager or protected environment variable.",
                    header_name,
                )
            )

    secret_args = _inline_secret_args(args)
    if secret_args:
        findings.append(
            Finding(
                "high",
                "MCP-012",
                name,
                "Secret-like command argument value is configured inline.",
                "Pass secrets through a protected environment reference, secret manager, or runtime credential broker instead of command arguments.",
                ", ".join(secret_args),
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

    sensitive_paths = _sensitive_credential_paths(args)
    if sensitive_paths:
        findings.append(
            Finding(
                "high",
                "MCP-020",
                name,
                "Credential-bearing local path is exposed to the MCP server.",
                "Do not grant agent-accessible tools direct access to SSH keys, cloud CLIs, Kubernetes config, Docker credentials, package registry tokens, or local credential stores. Use a brokered credential flow or a sanitized project directory instead.",
                ", ".join(sensitive_paths),
            )
        )

    env_files = _exposed_env_files(args)
    if env_files:
        findings.append(
            Finding(
                "high",
                "MCP-021",
                name,
                "Environment file is exposed to the MCP server.",
                "Do not pass .env or secret-bearing env files directly to agent-accessible MCP servers. Inject scoped runtime credentials from a protected environment, secret manager, or brokered credential flow instead.",
                ", ".join(env_files),
            )
        )

    browser_session_exposures = _browser_session_exposures(args)
    if browser_session_exposures:
        findings.append(
            Finding(
                "high",
                "MCP-022",
                name,
                "Browser session or profile data is exposed to the MCP server.",
                "Do not grant agent-accessible browser tools direct access to existing browser profiles, cookies, or storage-state files. Use a fresh isolated profile, short-lived test account, and explicit domain allowlist instead.",
                ", ".join(browser_session_exposures),
            )
        )

    cloud_metadata_exposures = _cloud_metadata_exposures(server)
    if cloud_metadata_exposures:
        findings.append(
            Finding(
                "high",
                "MCP-024",
                name,
                "Cloud metadata endpoint or wildcard network scope is reachable by the MCP server.",
                "Deny cloud metadata addresses such as 169.254.169.254 and use explicit egress allowlists for browser, fetch, request, and HTTP-capable MCP tools.",
                ", ".join(cloud_metadata_exposures),
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

    docker_socket_mounts = _docker_socket_mounts(args)
    if docker_socket_mounts:
        findings.append(
            Finding(
                "critical",
                "MCP-016",
                name,
                "Docker socket access is exposed to the MCP server.",
                "Do not mount the Docker socket into agent-accessible tools. Use a narrow broker, sandboxed build service, or read-only deployment API instead.",
                ", ".join(docker_socket_mounts),
            )
        )

    docker_unpinned_images = _docker_unpinned_images(command, args)
    if docker_unpinned_images:
        findings.append(
            Finding(
                "medium",
                "MCP-018",
                name,
                "Docker-based MCP server image is not pinned to an immutable digest.",
                "Pin containerized MCP server images with an approved sha256 digest and review image changes through change control.",
                ", ".join(docker_unpinned_images),
            )
        )

    auto_approval_wildcards = _auto_approval_wildcards(server)
    if auto_approval_wildcards:
        findings.append(
            Finding(
                "high",
                "MCP-017",
                name,
                "MCP tool auto-approval is configured with a wildcard.",
                "Replace wildcard auto-approval with explicit tool names and require confirmation for tools that write, delete, execute code, send data, or call external services.",
                ", ".join(auto_approval_wildcards),
            )
        )

    external_action_auto_approvals = _external_action_auto_approvals(server)
    if external_action_auto_approvals:
        findings.append(
            Finding(
                "high",
                "MCP-023",
                name,
                "External-action tools are configured for automatic approval.",
                "Require explicit confirmation, policy evaluation, and audit logging before tools can write, send, publish, deploy, merge, or call external services.",
                ", ".join(external_action_auto_approvals),
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


def render_owner_remediation_summary(config: dict[str, Any], findings: list[Finding]) -> str:
    servers = extract_servers(config)
    grouped: dict[str, list[Finding]] = {}

    for finding in findings:
        owner = _finding_owner(finding, servers)
        grouped.setdefault(owner, []).append(finding)

    lines = ["# Owner Remediation Summary", ""]
    if not findings:
        lines.extend(["No remediation items detected.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Owner | Critical | High | Medium | Low | Action |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for owner, owner_findings in sorted(
        grouped.items(), key=lambda item: (-_owner_max_severity(item[1]), item[0].lower())
    ):
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in owner_findings:
            counts[finding.severity] += 1
        lines.append(
            "| {owner} | {critical} | {high} | {medium} | {low} | {action} |".format(
                owner=_escape_cell(owner),
                critical=counts["critical"],
                high=counts["high"],
                medium=counts["medium"],
                low=counts["low"],
                action=_escape_cell(_owner_action(owner_findings)),
            )
        )

    lines.append("")
    for owner, owner_findings in sorted(
        grouped.items(), key=lambda item: (-_owner_max_severity(item[1]), item[0].lower())
    ):
        lines.extend(
            [
                f"## {owner}",
                "",
                "| Severity | Rule | Server | Finding | Recommendation |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in sorted(owner_findings, key=lambda item: (-SEVERITY_ORDER[item.severity], item.server, item.rule_id)):
            lines.append(
                "| {severity} | {rule_id} | {server} | {message} | {recommendation} |".format(
                    severity=finding.severity,
                    rule_id=finding.rule_id,
                    server=_escape_cell(finding.server),
                    message=_escape_cell(finding.message),
                    recommendation=_escape_cell(finding.recommendation),
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


def render_sarif(findings: list[Finding], config_path: Path | None = None) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    artifact_uri = config_path.as_posix() if config_path else "mcp-config.json"

    for finding in findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "fullDescription": {"text": finding.recommendation},
                "properties": {"security-severity": SARIF_SECURITY_SEVERITY[finding.severity]},
            }

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "server": finding.server,
                    "recommendation": finding.recommendation,
                    "evidence": finding.evidence,
                },
            }
        )

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-agent-security-kit",
                            "informationUri": "https://github.com/musaabhasan/mcp-agent-security-kit",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
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


def _finding_owner(finding: Finding, servers: dict[str, dict[str, Any]]) -> str:
    server = servers.get(finding.server, {})
    for key in ("riskOwner", "risk_owner", "owner", "maintainer"):
        value = server.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unassigned"


def _owner_max_severity(findings: list[Finding]) -> int:
    return max(SEVERITY_ORDER[finding.severity] for finding in findings)


def _owner_action(findings: list[Finding]) -> str:
    max_severity = _owner_max_severity(findings)
    if max_severity >= SEVERITY_ORDER["critical"]:
        return "Block release and remediate critical items before enabling the server."
    if max_severity >= SEVERITY_ORDER["high"]:
        return "Require owner remediation plan before production rollout."
    if max_severity >= SEVERITY_ORDER["medium"]:
        return "Track remediation in the next change window."
    return "Record ownership and monitor during routine review."


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _has_auth_signal(headers: dict[str, Any], env: dict[str, Any], server: dict[str, Any]) -> bool:
    if any(_is_secret_header(str(key)) and _has_nonempty_value(value) for key, value in headers.items()):
        return True
    if any(SECRET_NAME_PATTERN.search(str(key)) and _has_nonempty_value(value) for key, value in env.items()):
        return True
    return any(
        str(key).lower() in {"auth", "oauth", "token", "credential", "credentials"} and _has_nonempty_value(value)
        for key, value in server.items()
    )


def _is_secret_header(name: str) -> bool:
    normalized = name.lower()
    return normalized in {"authorization", "x-api-key", "api-key", "x-auth-token"} or SECRET_NAME_PATTERN.search(name) is not None


def _is_inline_secret_value(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    lowered = text.lower()
    placeholder_markers = ("${", "{{", "env:", "secret:", "vault:", "keyvault:", "op://")
    if any(marker in lowered for marker in placeholder_markers):
        return False
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", text):
        return False
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", text):
        return False
    if re.fullmatch(r"<[^>]+>", text):
        return False
    return True


def _has_nonempty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _inline_secret_args(args: list[str]) -> list[str]:
    findings: list[str] = []
    secret_option_pattern = re.compile(
        r"^(--?(?:api[_-]?key|token|auth[_-]?token|access[_-]?token|secret|password|passwd|client[_-]?secret))(?:=(.*))?$",
        re.IGNORECASE,
    )
    for index, arg in enumerate(args):
        match = secret_option_pattern.match(arg.strip())
        if match:
            option_name = match.group(1)
            inline_value = match.group(2)
            if inline_value is not None:
                if _is_inline_secret_value(inline_value):
                    findings.append(option_name)
                continue
            if index + 1 < len(args) and _is_inline_secret_value(args[index + 1]):
                findings.append(option_name)
            continue

        if re.search(r"\bbearer\s+\S+", arg, re.IGNORECASE) and _is_inline_secret_value(arg):
            findings.append("bearer-token")

    return sorted(set(findings))


def _inline_secret_query_params(url: str) -> list[str]:
    if not url:
        return []

    params: list[str] = []
    try:
        query = urlsplit(url).query
    except ValueError:
        return []

    for key, value in parse_qsl(query, keep_blank_values=True):
        if SECRET_NAME_PATTERN.search(key) and _is_inline_secret_value(value):
            params.append(key)

    return sorted(set(params))


def _inline_url_userinfo_secrets(url: str) -> list[str]:
    if not url:
        return []

    try:
        parsed = urlsplit(url)
    except ValueError:
        return []

    userinfo_parts: list[str] = []
    if parsed.username and _is_inline_secret_value(parsed.username):
        userinfo_parts.append("username")
    if parsed.password and _is_inline_secret_value(parsed.password):
        userinfo_parts.append("password")
    return userinfo_parts


def _tls_validation_disabled(server: dict[str, Any], env: dict[str, Any], args: list[str]) -> list[str]:
    evidence: list[str] = []

    for key, value in server.items():
        normalized = _normalize_key(str(key))
        if normalized in TLS_VERIFY_FALSE_KEYS and _is_explicit_false(value):
            evidence.append(str(key))
        if normalized in TLS_SKIP_TRUE_KEYS and _is_explicit_true(value):
            evidence.append(str(key))

    for key, value in env.items():
        normalized = str(key).strip().upper()
        if normalized == "NODE_TLS_REJECT_UNAUTHORIZED" and str(value).strip() == "0":
            evidence.append(str(key))
        if normalized == "PYTHONHTTPSVERIFY" and str(value).strip() == "0":
            evidence.append(str(key))

    evidence.extend(arg for arg in args if TLS_SKIP_ARG_PATTERN.match(arg.strip()))
    return sorted(set(evidence))


def _docker_socket_mounts(args: list[str]) -> list[str]:
    evidence: list[str] = []
    for index, arg in enumerate(args):
        lowered = arg.strip().lower().replace("\\", "/")
        if any(marker in lowered for marker in DOCKER_SOCKET_MARKERS):
            evidence.append(arg)
            continue
        if arg in {"-v", "--volume", "--mount"} and index + 1 < len(args):
            next_arg = args[index + 1]
            next_lowered = next_arg.strip().lower().replace("\\", "/")
            if any(marker in next_lowered for marker in DOCKER_SOCKET_MARKERS):
                evidence.append(next_arg)
    return sorted(set(evidence))


def _docker_unpinned_images(command: str, args: list[str]) -> list[str]:
    if command != "docker":
        return []
    image = _docker_primary_image(args)
    if not image:
        return []
    if re.search(r"@sha256:[a-fA-F0-9]{64}\b", image):
        return []
    return [image]


def _docker_primary_image(args: list[str]) -> str:
    start = _docker_run_or_create_start(args)
    if start is None:
        return ""

    index = start
    while index < len(args):
        arg = args[index]
        if not arg:
            index += 1
            continue
        if arg == "--":
            return args[index + 1] if index + 1 < len(args) else ""
        if arg.startswith("--") and "=" in arg:
            index += 1
            continue
        if arg in DOCKER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return ""


def _docker_run_or_create_start(args: list[str]) -> int | None:
    for index, arg in enumerate(args):
        if arg in {"run", "create"}:
            return index + 1
        if arg == "container" and index + 1 < len(args) and args[index + 1] in {"run", "create"}:
            return index + 2
    return None


def _auto_approval_wildcards(server: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for key, value in server.items():
        normalized = _normalize_key(str(key))
        if normalized not in AUTO_APPROVAL_KEYS:
            continue
        if _contains_wildcard_approval(value):
            evidence.append(str(key))
    return sorted(set(evidence))


def _broad_auth_scopes(value: Any, path: str = "") -> list[str]:
    evidence: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if _normalize_key(str(key)) in BROAD_AUTH_SCOPE_KEYS:
                evidence.extend(
                    f"{key_path}={scope}"
                    for scope in _scope_values(item)
                    if BROAD_AUTH_SCOPE_PATTERN.search(scope.strip())
                )
                continue
            evidence.extend(_broad_auth_scopes(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            evidence.extend(_broad_auth_scopes(item, f"{path}[{index}]"))
    return sorted(set(evidence))


def _scope_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [scope.strip() for scope in re.split(r"[\s,]+", value) if scope.strip()]
    if isinstance(value, list):
        scopes: list[str] = []
        for item in value:
            scopes.extend(_scope_values(item))
        return scopes
    if isinstance(value, dict):
        scopes = []
        for key, item in value.items():
            if isinstance(item, bool):
                if item:
                    scopes.append(str(key))
                continue
            scopes.extend(_scope_values(item))
        return scopes
    return []


def _allowed_tools_for_server(server: dict[str, Any]) -> set[str]:
    tools: set[str] = set()
    for key, value in server.items():
        if _normalize_key(str(key)) in AUTO_APPROVAL_KEYS:
            tools.update(_collect_tool_names(value))
    return {tool for tool in tools if tool}


def _collect_tool_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value.strip()} if value.strip() else set()
    if isinstance(value, list):
        tools: set[str] = set()
        for item in value:
            tools.update(_collect_tool_names(item))
        return tools
    if isinstance(value, dict):
        tools: set[str] = set()
        for key, item in value.items():
            if isinstance(item, bool):
                if item:
                    tools.add(str(key))
                continue
            nested = _collect_tool_names(item)
            if nested:
                tools.update(nested)
            elif item:
                tools.add(str(key))
        return tools
    return set()


def _allowed_tool_drift_severity(tool: str, change: str) -> str:
    if change != "added":
        return "low"
    if tool.strip().lower() in AUTO_APPROVAL_WILDCARDS:
        return "critical"
    if re.search(
        r"(write|delete|remove|exec|shell|command|run|deploy|publish|send|email|post|request|http|create|update|grant|token|secret|credential|upload|download|push|merge)",
        tool,
        re.IGNORECASE,
    ):
        return "high"
    return "medium"


def _external_action_auto_approvals(server: dict[str, Any]) -> list[str]:
    return sorted(
        tool
        for tool in _allowed_tools_for_server(server)
        if tool.strip().lower() not in AUTO_APPROVAL_WILDCARDS and EXTERNAL_ACTION_TOOL_PATTERN.search(tool)
    )


def _allowed_tool_recommendation(tool: str, severity: str) -> str:
    if severity == "critical":
        return "Do not approve wildcard tool access. Replace it with explicit low-impact tool names and require confirmation for write, execution, or external-action tools."
    if severity == "high":
        return f"Require change approval, owner sign-off, and runtime monitoring before allowing `{tool}` in production."
    return f"Confirm `{tool}` is required for the approved workflow and record the change owner."


def _contains_wildcard_approval(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in AUTO_APPROVAL_WILDCARDS
    if isinstance(value, list):
        return any(_contains_wildcard_approval(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_wildcard_approval(item) for item in value.values())
    return False


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _is_explicit_false(value: Any) -> bool:
    if isinstance(value, bool):
        return value is False
    if isinstance(value, (int, float)):
        return value == 0
    return str(value).strip().lower() in {"false", "0", "no", "off"}


def _is_explicit_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value is True
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


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


def _sensitive_credential_paths(args: list[str]) -> list[str]:
    evidence: list[str] = []
    for arg in args:
        normalized = arg.strip().strip('"').strip("'").replace("\\", "/")
        if not normalized:
            continue
        if any(pattern.search(normalized) for pattern in SENSITIVE_CREDENTIAL_PATH_PATTERNS):
            evidence.append(arg)
    return sorted(set(evidence))


def _exposed_env_files(args: list[str]) -> list[str]:
    evidence: list[str] = []
    for index, arg in enumerate(args):
        normalized = arg.strip().strip('"').strip("'")
        if not normalized:
            continue

        option, separator, value = normalized.partition("=")
        if option.lower() in ENV_FILE_OPTIONS and separator:
            if _looks_like_secret_env_file(value):
                evidence.append(arg)
            continue

        if normalized.lower() in ENV_FILE_OPTIONS and index + 1 < len(args):
            next_arg = args[index + 1].strip().strip('"').strip("'")
            if _looks_like_secret_env_file(next_arg):
                evidence.append(f"{arg} {args[index + 1]}")
            continue

        if _looks_like_secret_env_file(normalized):
            evidence.append(arg)

    return sorted(set(evidence))


def _looks_like_secret_env_file(value: str) -> bool:
    if not value:
        return False
    normalized = value.replace("\\", "/").rstrip("/")
    filename = normalized.rsplit("/", 1)[-1].lower()
    if not filename.endswith(".env") and not filename.startswith(".env"):
        return False
    if filename.startswith(".env") and any(filename.endswith(suffix) for suffix in SAFE_ENV_FILE_SUFFIXES):
        return False
    if filename in {"example.env", "sample.env", "template.env", "test.env"}:
        return False
    return (
        filename == ".env"
        or filename.startswith(".env.")
        or any(marker in filename for marker in ("secret", "credential", "token", "prod", "production"))
    )


def _browser_session_exposures(args: list[str]) -> list[str]:
    evidence: list[str] = []
    for index, arg in enumerate(args):
        normalized = arg.strip().strip('"').strip("'")
        if not normalized:
            continue

        option, separator, value = normalized.partition("=")
        lowered_option = option.lower()
        if lowered_option in BROWSER_PROFILE_OPTIONS and separator:
            if _looks_like_browser_profile_path(value):
                evidence.append(arg)
            continue

        if lowered_option in BROWSER_SESSION_OPTIONS and separator:
            if _is_inline_session_reference(value):
                evidence.append(arg)
            continue

        lowered_normalized = normalized.lower()
        if lowered_normalized in BROWSER_PROFILE_OPTIONS and index + 1 < len(args):
            next_arg = args[index + 1].strip().strip('"').strip("'")
            if _looks_like_browser_profile_path(next_arg):
                evidence.append(f"{arg} {args[index + 1]}")
            continue

        if lowered_normalized in BROWSER_SESSION_OPTIONS and index + 1 < len(args):
            next_arg = args[index + 1].strip().strip('"').strip("'")
            if _is_inline_session_reference(next_arg):
                evidence.append(f"{arg} {args[index + 1]}")
            continue

        if _looks_like_browser_profile_path(normalized):
            evidence.append(arg)

    return sorted(set(evidence))


def _looks_like_browser_profile_path(value: str) -> bool:
    if not value:
        return False
    normalized = value.strip().strip('"').strip("'").replace("\\", "/").rstrip("/")
    if _is_placeholder_reference(normalized):
        return False
    return any(pattern.search(normalized) for pattern in BROWSER_PROFILE_PATH_PATTERNS)


def _is_inline_session_reference(value: str) -> bool:
    if not value:
        return False
    normalized = value.strip().strip('"').strip("'")
    if _is_placeholder_reference(normalized):
        return False
    lowered = normalized.lower().replace("\\", "/")
    filename = lowered.rsplit("/", 1)[-1]
    return (
        _looks_like_browser_profile_path(normalized)
        or "cookie" in filename
        or "storage-state" in filename
        or "auth-state" in filename
        or filename in {"state.json", "session.json", "sessions.json"}
    )


def _cloud_metadata_exposures(value: Any, path: str = "") -> list[str]:
    evidence: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if _normalize_key(str(key)) in NETWORK_ALLOWLIST_KEYS:
                evidence.extend(
                    f"{key_path}={scope}"
                    for scope in _network_scope_values(item)
                    if _is_metadata_network_scope(scope)
                )
            evidence.extend(_cloud_metadata_exposures(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            evidence.extend(_cloud_metadata_exposures(item, f"{path}[{index}]"))
    elif isinstance(value, (str, int, float)):
        text = str(value).strip()
        if text and _metadata_reference(text):
            evidence.append(f"{path}={text}" if path else text)
    return sorted(set(evidence))


def _network_scope_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [scope.strip() for scope in re.split(r"[\s,]+", value) if scope.strip()]
    if isinstance(value, list):
        scopes: list[str] = []
        for item in value:
            scopes.extend(_network_scope_values(item))
        return scopes
    if isinstance(value, dict):
        scopes = []
        for key, item in value.items():
            if isinstance(item, bool):
                if item:
                    scopes.append(str(key))
                continue
            scopes.extend(_network_scope_values(item))
        return scopes
    return []


def _is_metadata_network_scope(value: str) -> bool:
    normalized = value.strip().strip('"').strip("'").lower()
    return normalized in NETWORK_ALLOWLIST_WILDCARDS or _metadata_reference(value)


def _metadata_reference(value: str) -> bool:
    if _is_placeholder_reference(value):
        return False
    normalized = value.strip().strip('"').strip("'").replace("\\", "/")
    return any(pattern.search(normalized) for pattern in CLOUD_METADATA_PATTERNS)


def _is_placeholder_reference(value: str) -> bool:
    lowered = value.strip().lower()
    if any(marker in lowered for marker in ("${", "{{", "env:", "secret:", "vault:", "keyvault:", "op://")):
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", value):
        return True
    return re.fullmatch(r"<[^>]+>", value) is not None


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit MCP server configuration for common agentic AI security risks.")
    parser.add_argument("config", type=Path, help="Path to an MCP JSON configuration file.")
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown", help="Output format.")
    parser.add_argument("--output", type=Path, help="Optional output report path.")
    parser.add_argument(
        "--append-owner-summary",
        action="store_true",
        help="Append a Markdown remediation summary grouped by risk owner or owner.",
    )
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
    if args.format == "json":
        report = render_json(findings)
    elif args.format == "sarif":
        report = render_sarif(findings, args.config)
    else:
        report = render_markdown(findings)
        if args.append_owner_summary:
            report = report.rstrip() + "\n\n" + render_owner_remediation_summary(config, findings)
    write_output(report, args.output)
    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())

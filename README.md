# MCP Agent Security Kit

Practical audit tools, threat models, and control templates for securing Model Context Protocol (MCP) servers and agentic AI tool access.

AI agents are moving from chat interfaces into systems that can read files, call APIs, query databases, trigger workflows, and act with user or service credentials. MCP makes that integration easier, but it also turns tool configuration into a security boundary. This project helps teams review that boundary before agents are connected to sensitive systems.

## What This Repository Provides

- A dependency-free Python CLI that audits MCP server configuration files.
- Detection rules for risky local commands, unpinned package runners, secret exposure, unencrypted remote servers, missing auth, broad filesystem access, and dangerous execution flags.
- Review guard for external-action tools that should not be automatically approved without confirmation, policy evaluation, and audit logging.
- Cloud metadata exposure detection for browser, fetch, request, and HTTP-capable MCP tools.
- Browser debugging interface exposure detection for DevTools, CDP, and remote debugging endpoints.
- Kubernetes service account exposure detection for in-cluster agent workloads.
- SSH agent socket exposure detection for Git, deployment, and server-authentication boundaries.
- Git credential helper exposure detection for source-control authority boundaries.
- Container runtime socket exposure detection for Podman, containerd, CRI-O, cri-dockerd, and BuildKit boundaries.
- Cloud CLI credential context detection for AWS, Google Cloud, Azure, and OCI authority boundaries.
- Database client credential context detection for DSNs, password variables, option files, and profile directories.
- Package registry credential context detection for dependency and publishing authority boundaries.
- Safe and risky MCP configuration examples for testing.
- GitHub Actions validation for unit tests, Python compilation, SARIF report generation, JSON contract validation, and safe-example audit gates.
- A published JSON output schema for downstream security dashboards, CI gates, and evidence repositories.
- Allowed-tool drift comparison between an approved baseline and the current MCP configuration.
- A threat model for MCP and agentic tool access.
- A threat scenario library for prompt-to-tool abuse, tool poisoning, approval bypass, and toxic tool flows.
- A control matrix aligned to agentic AI security, identity, logging, and governance concerns.
- A practical launch checklist for teams piloting AI agents.
- Runtime monitoring guidance for tool telemetry, drift detection, evidence handling, and incident triggers.
- Severity override policies for adapting default rule severities to local risk appetite without suppressing evidence.

## Why This Topic Matters Now

Agentic AI and MCP security are becoming high-priority security topics because agents can combine natural-language instructions with real system authority. Current guidance and research emphasize the same themes:

- OWASP published the Top 10 for Agentic Applications 2026, covering risks such as goal hijacking, tool misuse, unexpected code execution, insecure inter-agent communication, and agentic supply chain exposure.
- NIST continues to operationalize the AI Risk Management Framework and Generative AI Profile for real-world governance, testing, and monitoring.
- MCP adoption is expanding across AI tools, which increases the importance of secure tool configuration, authentication, and least privilege.
- Recent MCP security research highlights risks from prompt injection, tool poisoning, unsafe local execution, and over-privileged tool access.

## Quick Start

Install the repository locally:

```bash
python -m pip install -e .
```

Run the audit tool:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json
```

Write a Markdown report:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --output reports/mcp-audit.md
```

Append remediation guidance grouped by risk owner or owner:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --append-owner-summary
```

Write SARIF for GitHub code scanning or security dashboards:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --format sarif --output reports/mcp-audit.sarif
```

Write JSON and validate the published output contract:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --format json --output reports/mcp-audit.json
python scripts/validate_json_output.py reports/mcp-audit.json
```

Compare allowed-tool drift between an approved baseline and the current config:

```bash
python scripts/compare_allowed_tools.py examples/allowed-tools-baseline.json examples/allowed-tools-current.json
```

Fail a pipeline when high-risk findings exist:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --fail-on high
```

Apply reviewed local severity policy before rendering reports or enforcing gates:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --severity-overrides examples/severity-overrides.json --fail-on high
```

After installation:

```bash
mcp-agent-audit examples/mcp-config-risky.json --format json
```

## Supported Configuration Shapes

The auditor supports common MCP configuration layouts:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

It also handles top-level server maps and remote server entries with `url`, `headers`, and `env` fields.

## Detection Rules

| Rule | Risk |
| --- | --- |
| MCP-001 | Remote MCP server uses unencrypted HTTP |
| MCP-002 | Remote MCP server has no clear authentication signal |
| MCP-003 | Secret-like values are configured inline in environment variables |
| MCP-004 | Package runner is used without an obvious package version pin |
| MCP-005 | Shell or evaluator command can execute arbitrary code |
| MCP-006 | Dangerous execution flags are present |
| MCP-007 | Broad filesystem access is granted |
| MCP-008 | Docker configuration uses privileged or host-level access |
| MCP-009 | Server has no visible owner or risk owner metadata |
| MCP-010 | Filesystem-like tool lacks a read-only signal |
| MCP-011 | Secret-like HTTP header values are configured inline |
| MCP-012 | Secret-like command argument values are configured inline |
| MCP-013 | Secret-like URL query parameter values are configured inline |
| MCP-014 | Credential-like URL userinfo values are configured inline |
| MCP-015 | TLS certificate validation is disabled |
| MCP-016 | Docker socket access is exposed to the MCP server |
| MCP-017 | Tool auto-approval is configured with a wildcard |
| MCP-018 | Docker-based MCP server image is not pinned to an immutable digest |
| MCP-019 | Authentication scopes or permissions look overbroad |
| MCP-020 | Credential-bearing local path is exposed to the MCP server |
| MCP-021 | Environment file is exposed to the MCP server |
| MCP-022 | Browser session or profile data is exposed to the MCP server |
| MCP-023 | External-action tools are configured for automatic approval |
| MCP-024 | Cloud metadata endpoint or wildcard network scope is reachable by the MCP server |
| MCP-025 | Browser debugging interface is exposed to the MCP server |
| MCP-026 | Kubernetes service account access is exposed to the MCP server |
| MCP-027 | SSH agent socket access is exposed to the MCP server |
| MCP-028 | Git credential helper access is exposed to the MCP server |
| MCP-029 | Container runtime socket access is exposed to the MCP server |
| MCP-030 | Cloud CLI credential context is exposed to the MCP server |
| MCP-031 | Database client credential context is exposed to the MCP server |
| MCP-032 | Package registry credential context is exposed to the MCP server |

## Change-Control Utilities

| Utility | Purpose |
| --- | --- |
| `scripts/compare_allowed_tools.py` | Compares allowed tool lists between a baseline and current config, then flags added high-impact tools and wildcard approvals |
| `examples/severity-overrides.json` | Demonstrates reviewed local severity policy for production and sandbox exceptions |

## Example Output

```text
# MCP Agent Security Audit

Risk score: 82 / 100

| Severity | Rule | Server | Finding |
| --- | --- | --- | --- |
| critical | MCP-005 | shell | Shell or evaluator command can execute arbitrary code |
| high | MCP-003 | github | Secret-like environment variable is configured inline |
| medium | MCP-004 | filesystem | Package runner is used without an obvious package version pin |
```

## Repository Map

| Path | Purpose |
| --- | --- |
| `src/mcp_agent_security_kit/audit.py` | MCP configuration audit CLI |
| `examples/mcp-config-risky.json` | Intentionally risky sample configuration |
| `examples/mcp-config-safer.json` | Safer sample configuration |
| `docs/threat-model.md` | MCP and agentic tool threat model |
| `docs/threat-scenarios.md` | Concrete MCP abuse scenarios, controls, evidence, and monitoring signals |
| `docs/agent-identity-model.md` | Identity and authorization model for MCP-enabled agents |
| `docs/control-matrix.md` | Control matrix for identity, tools, logging, and governance |
| `docs/launch-checklist.md` | Practical rollout checklist |
| `docs/runtime-monitoring.md` | Runtime monitoring model for MCP tool calls, policy decisions, drift, and incident evidence |
| `docs/json-output-contract.md` | JSON output contract and integration guidance |
| `docs/allowed-tool-drift.md` | Allowed-tool baseline comparison workflow for CI and change control |
| `docs/owner-remediation-summary.md` | Owner-grouped remediation workflow for routing findings to accountable teams |
| `docs/broad-auth-scopes.md` | Least-privilege review guidance for OAuth scopes and provider permissions |
| `docs/credential-path-exposure.md` | Review guidance for preventing MCP filesystem grants from exposing local credential stores |
| `docs/env-file-exposure.md` | Review guidance for preventing `.env` and secret-bearing env files from being passed into MCP servers |
| `docs/browser-profile-exposure.md` | Review guidance for preventing browser profile, cookie, and storage-state exposure to MCP browser tools |
| `docs/browser-debugging-exposure.md` | Review guidance for preventing DevTools, CDP, and remote debugging endpoints from becoming agent authority boundaries |
| `docs/external-action-approval.md` | Review guidance for keeping external write, messaging, deployment, and merge tools behind confirmation and policy controls |
| `docs/cloud-metadata-exposure.md` | Review guidance for preventing agent-accessible network tools from reaching cloud instance metadata endpoints |
| `docs/kubernetes-service-account-exposure.md` | Review guidance for preventing Kubernetes service account tokens and in-cluster API access from becoming agent authority boundaries |
| `docs/ssh-agent-socket-exposure.md` | Review guidance for preventing SSH agent sockets and forwarded agent pipes from becoming agent authority boundaries |
| `docs/git-credential-helper-exposure.md` | Review guidance for preventing Git credential helpers, askpass helpers, and credential files from becoming agent authority boundaries |
| `docs/container-runtime-socket-exposure.md` | Review guidance for preventing Podman, containerd, CRI-O, cri-dockerd, and BuildKit sockets from becoming agent authority boundaries |
| `docs/cloud-cli-credential-context.md` | Review guidance for preventing AWS, Google Cloud, Azure, and OCI CLI credential context from becoming agent authority boundaries |
| `docs/database-client-credential-context.md` | Review guidance for preventing database passwords, DSNs, option files, and profile directories from becoming agent authority boundaries |
| `docs/package-registry-credential-context.md` | Review guidance for preventing package manager tokens, config files, and registry credentials from becoming agent authority boundaries |
| `docs/severity-overrides.md` | Local severity override policy workflow for adapting rule severities without suppressing evidence |
| `schema/audit-output.schema.json` | Machine-readable schema for audit JSON reports |
| `scripts/validate_json_output.py` | Dependency-free JSON report contract validator |

## Security Position

This tool is a configuration review helper. It does not replace code review, penetration testing, architecture review, vendor due diligence, or runtime monitoring. Use it as a fast first pass before connecting agents to sensitive systems.

## Contributing

Contributions are welcome, especially:

- new MCP configuration examples,
- additional audit rules,
- mappings to security frameworks,
- CI integrations,
- real-world hardening notes.

Please keep examples sanitized. Do not commit real tokens, internal URLs, private hostnames, or customer data.

# MCP Threat Scenario Library

This library gives reviewers concrete abuse cases to test before connecting agents to MCP servers. Use it with the audit CLI, architecture review, red-team exercises, and production monitoring design.

## Review Method

For each enabled MCP server, record:

- server owner and risk owner,
- data classes reachable through the server,
- tool names and descriptions,
- read, write, execute, network, and credential capabilities,
- approval rules and auto-approval settings,
- secrets and identity path,
- logs that prove what the agent attempted and what the server did.

Then test the scenarios below against the configured tool boundary.

## Scenario Matrix

| ID | Scenario | Abuse Path | Primary Controls | Detection Evidence |
| --- | --- | --- | --- | --- |
| TS-001 | Indirect prompt injection reaches a sensitive tool | A retrieved document tells the agent to call a filesystem, email, browser, or shell tool outside the task. | Treat retrieved content as untrusted, bind tool calls to user intent, require confirmation for high-impact tools. | Tool-call trace, retrieved source ID, approval decision, blocked action reason. |
| TS-002 | Tool description poisoning biases planning | A server card or tool description contains instructions that override developer or user intent. | Scan server metadata before approval, strip instruction-like text from descriptions, require signed or reviewed server cards. | Server-card scan result, metadata diff, tool selection trace. |
| TS-003 | Wildcard auto-approval enables unbounded action | `alwaysAllow`, `allowedTools`, or similar settings include `*`, `all`, or nested wildcard permissions. | Ban wildcard approval, require explicit tool names, separate read-only and write-capable tools. | MCP-017 finding, policy decision log, approval configuration diff. |
| TS-004 | Local command wrapper exposes arbitrary execution | MCP config starts `bash`, `cmd`, `powershell`, `python -c`, `node -e`, or a broad script wrapper. | Replace evaluator commands with narrow wrappers, sandbox execution, review command arguments. | MCP-005 finding, process command log, wrapper code review record. |
| TS-005 | Docker socket grants host control | A containerized MCP server mounts `/var/run/docker.sock` or Windows Docker engine pipe. | Do not expose the Docker socket; use a narrow broker or isolated build service. | MCP-016 finding, container runtime config, host event logs. |
| TS-006 | Inline credential leaks through config or logs | Tokens appear in env, headers, URL userinfo, query params, or command arguments. | Inject secrets at runtime, use secret manager references, redact logs, rotate exposed credentials. | MCP-003, MCP-011, MCP-012, MCP-013, or MCP-014 finding; secret rotation ticket. |
| TS-007 | Disabled TLS validation hides interception | MCP client or wrapper disables certificate validation. | Keep TLS verification enabled, fix trust-store issues, pin internal CA where appropriate. | MCP-015 finding, client config, TLS error history. |
| TS-008 | Broad filesystem access enables data spill | Filesystem tool grants `/`, home directory, drive root, or sensitive system paths. | Scope to a project directory, prefer read-only mode, deny hidden credential paths. | MCP-007 and MCP-010 findings, file access telemetry, path allowlist. |
| TS-009 | Remote MCP endpoint lacks authentication | Agent connects to an HTTP/HTTPS MCP endpoint without a clear auth signal. | Require authenticated transport, per-agent identity, token rotation, and least privilege. | MCP-001 or MCP-002 finding, access logs, token issuance record. |
| TS-010 | Cross-tool toxic flow creates a combined impact | One tool reads credentials and another sends data externally, creating a complete exfiltration path. | Analyze tool combinations, limit tool sets by task, block risky pairings without human approval. | Tool graph, sequence trace, egress logs, combined-risk review. |
| TS-011 | Memory write stores untrusted instructions | A tool writes retrieved hostile content into long-term memory where later tasks treat it as trusted. | Label memory provenance, separate facts from instructions, require review for persistent memory writes. | Memory write log, source trust label, later retrieval trace. |
| TS-012 | Approval prompt is not bound to final action | User approves a benign summary, but the agent changes tool arguments before execution. | Bind approval to tool name, arguments, target resource, data class, and expiration. | Approval record hash, final tool-call arguments, mismatch alert. |

## Scenario Test Template

| Field | Response |
| --- | --- |
| Scenario ID | |
| MCP server | |
| Tool or capability | |
| Data class in scope | |
| Expected safe behavior | |
| Test input or fixture | |
| Observed behavior | |
| Control result | Pass / fail / partial |
| Evidence captured | |
| Remediation owner | |
| Retest date | |

## Production Monitoring Signals

| Signal | Why It Matters |
| --- | --- |
| Tool calls denied by policy | Confirms that preventive controls are active and identifies risky prompts. |
| Tool calls with changed arguments after approval | Detects approval binding gaps. |
| New or changed server-card metadata | Detects tool description drift and potential poisoning. |
| Secret-like strings in MCP config or logs | Indicates credential exposure or unsafe configuration. |
| High-impact tool calls from low-trust context | Shows that retrieved content or external input may be driving action. |
| Cross-tool sequences involving credential read and network egress | Reveals combined-risk chains that single-rule checks may understate. |

## Review Cadence

- Run configuration audit before onboarding an MCP server.
- Re-run after server updates, tool list changes, approval rule changes, runtime wrapper changes, or identity changes.
- Re-run after any incident involving prompt injection, data leakage, unexpected tool use, or credential exposure.
- Keep scenario results with architecture review and deployment approval evidence.

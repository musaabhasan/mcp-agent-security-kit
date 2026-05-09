# Secure MCP Server Onboarding Checklist

Use this checklist when introducing a new MCP server into an agent environment. It is intended for security, platform, product, and operations teams that need a repeatable path from request intake to monitored production use.

## 1. Intake And Ownership

| Check | Evidence | Owner | Status |
| --- | --- | --- | --- |
| Business purpose is documented and tied to an approved workflow | Use-case summary or change request |  |  |
| Tool owner and risk owner are named | Owner metadata in configuration or review record |  |  |
| Environment scope is defined | Sandbox / development / staging / production |  |  |
| Data classifications are identified | Data inventory or data-flow record |  |  |
| User groups and agent roles are listed | Access request or identity review |  |  |
| Review expiry date is set | Re-review or recertification date |  |  |

## 2. Configuration Hygiene

| Check | Evidence | Owner | Status |
| --- | --- | --- | --- |
| Package versions or container images are pinned | Lock file, version pin, or image digest |  |  |
| No inline secrets appear in env, args, headers, URLs, or config files | Audit output and secret scan |  |  |
| Remote servers use TLS and authenticated endpoints | Endpoint configuration |  |  |
| Filesystem grants are narrow and avoid credential stores | Config review and path allowlist |  |  |
| Auto-approval uses explicit tool names, not wildcards | Allowed-tool baseline |  |  |
| Server metadata includes owner, risk owner, and environment | MCP configuration metadata |  |  |

Recommended validation:

```bash
python -m mcp_agent_security_kit.audit path/to/mcp-config.json --fail-on high
python -m mcp_agent_security_kit.audit path/to/mcp-config.json --format json --output reports/mcp-audit.json
python scripts/validate_json_output.py reports/mcp-audit.json
```

## 3. Identity And Least Privilege

| Check | Evidence | Owner | Status |
| --- | --- | --- | --- |
| Tool identity is separate from administrator identities | Service account or OAuth app record |  |  |
| Permission scope matches the business purpose | Scope review or access ticket |  |  |
| Long-lived credentials are avoided where short-lived credentials are available | Credential design record |  |  |
| High-impact tools require confirmation or dual approval | Tool permission worksheet |  |  |
| Privileged access has an expiry or recertification cadence | Access review schedule |  |  |
| Break-glass access is documented and logged | Break-glass procedure |  |  |

## 4. Runtime Boundaries

| Check | Evidence | Owner | Status |
| --- | --- | --- | --- |
| Server runs with the minimum OS/container privileges | Runtime manifest or deployment spec |  |  |
| Network egress is restricted to approved destinations | Firewall, proxy, or egress policy |  |  |
| Cloud metadata endpoints are blocked unless explicitly required | Egress or metadata policy |  |  |
| Command execution is sandboxed and time-limited | Runtime policy or wrapper config |  |  |
| File writes are isolated from source, secrets, and production data | Workspace boundary |  |  |
| Resource limits prevent runaway execution | CPU, memory, timeout, and concurrency settings |  |  |

## 5. Testing Before Approval

| Test | Expected outcome | Evidence | Result |
| --- | --- | --- | --- |
| Safe-path audit | No high or critical findings remain open | Audit report |  |
| Prompt-injection simulation | Tool does not bypass policy or approval gates | Test record |  |
| Credential exposure test | Tool cannot read credential paths, env files, helpers, or sockets | Test evidence |  |
| External action test | Confirmation, policy decision, and logs are produced | Tool-call log |  |
| Denial-path test | Blocked requests are denied safely and logged | Policy log |  |
| Rollback test | Configuration can be reverted to the approved baseline | Rollback evidence |  |

## 6. Monitoring And Evidence

| Signal | Minimum expectation | Owner | Status |
| --- | --- | --- | --- |
| Tool invocation logging | Who/what called the tool, when, arguments summary, result, and approval status |  |  |
| Configuration drift detection | Baseline vs current allowed-tool comparison |  |  |
| Security event triggers | Credential access, denied high-risk calls, wildcard approval changes, external actions |  |  |
| Owner remediation routing | Findings grouped by owner or risk owner |  |  |
| Evidence retention | Audit reports, approvals, logs, and incident evidence stored for the approved period |  |  |
| Incident playbook mapping | Containment, credential rotation, preservation, and recovery actions are ready |  |  |

## 7. Release Decision

| Decision | When to use |
| --- | --- |
| Approve sandbox only | Tool is valuable but needs more evidence before production use. |
| Approve production with restrictions | Controls are sufficient and restrictions are documented. |
| Hold | Ownership, scope, audit findings, logging, or testing evidence is incomplete. |
| Reject | Tool requires unsafe authority or cannot be constrained to the approved purpose. |

| Final decision | Restrictions | Owner | Review date | Evidence reference |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## 8. Post-Launch Review

Review the MCP server after 30 days and then on the approved cadence. Confirm:

- No new high-impact tools were added without review.
- No wildcard auto-approval or broad filesystem grant was introduced.
- Audit results remain below the approved severity threshold.
- Tool logs show expected use patterns.
- Owner metadata, permission scopes, and credential design remain current.
- Open findings have accountable remediation dates.

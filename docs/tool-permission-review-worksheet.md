# MCP Tool Permission Review Worksheet

Use this worksheet before approving a new MCP tool, expanding tool permissions, enabling automatic approval, or connecting an agent to a sensitive application. It turns tool access into a reviewable security decision rather than an informal convenience setting.

## Review Header

| Field | Value |
| --- | --- |
| MCP server or tool name |  |
| Tool owner |  |
| Business owner |  |
| Environment | Sandbox / Development / Staging / Production |
| Proposed permission change |  |
| Review date |  |
| Reviewer |  |
| Related config path |  |

## Tool Authority Classification

| Authority type | Questions | Classification |
| --- | --- | --- |
| Read authority | Can the tool read files, records, tickets, messages, repositories, databases, browser state, logs, or secrets? | None / Limited / Broad / Sensitive |
| Write authority | Can it create, edit, delete, publish, send, merge, deploy, grant access, or trigger workflows? | None / Low impact / High impact / Critical |
| Execution authority | Can it run scripts, shell commands, package managers, containers, notebooks, CI jobs, or arbitrary code? | None / Restricted / Broad |
| Network authority | Can it call internal URLs, cloud metadata endpoints, admin APIs, SaaS APIs, or arbitrary domains? | None / Allowlisted / Broad |
| Credential authority | Can it access OAuth tokens, SSH agents, cloud profiles, database credentials, package tokens, or CI/CD secrets? | None / Scoped / High risk |
| User impersonation | Does it act as the end user, a shared service account, or a privileged automation identity? | None / User / Service / Privileged |

## Approval Gate

| Condition | Required control | Status |
| --- | --- | --- |
| Tool can perform external actions | Human confirmation for high-impact actions and policy evaluation before execution |  |
| Tool can read sensitive data | Data classification, owner approval, masking rules, and access logging |  |
| Tool can modify production resources | Change-control linkage, rollback plan, and dual approval for destructive actions |  |
| Tool can run code or containers | Execution sandbox, command allowlist, timeout, resource limits, and artifact capture |  |
| Tool can access credentials | Secret injection boundary, no inline credentials, rotation plan, and credential owner approval |  |
| Tool can call arbitrary network targets | Egress allowlist, cloud metadata blocking, SSRF review, and telemetry |  |
| Tool is proposed for auto-approval | Explicit tool list, no wildcard approvals, severity review, and monitoring triggers |  |

## Permission Minimization

| Permission requested | Business justification | Narrower alternative | Approved scope | Expiry or review date |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

Review questions:

- Can the tool operate read-only for the initial pilot?
- Can the scope be restricted to a single repository, project, queue, dataset, tenant, or environment?
- Can write operations be split into separate tools with stricter confirmation?
- Can sensitive data be replaced with summaries, hashes, redacted records, or synthetic test data?
- Can credentials be provided through short-lived tokens instead of long-lived profiles?

## Logging And Evidence

| Evidence | Required detail | Owner | Ready? |
| --- | --- | --- | --- |
| Tool invocation log | Timestamp, user or agent identity, tool name, arguments summary, approval decision, and result status |  |  |
| Policy decision log | Rule decision, risk reason, approval path, and override owner |  |  |
| Output handling record | Where returned data is stored, displayed, masked, or exported |  |  |
| Error and denial log | Failed calls, denied actions, policy blocks, and suspicious retries |  |  |
| Configuration baseline | Approved server config, allowed tools, version pins, owner metadata, and review date |  |  |
| Incident trigger mapping | Conditions that create a security event, privacy event, or operational incident |  |  |

## Test Plan

| Scenario | Expected control | Evidence reference | Result |
| --- | --- | --- | --- |
| Allowed read-only operation | Completes without exposing hidden data |  |  |
| Denied sensitive path or credential access | Request is blocked and logged |  |  |
| High-impact write operation | Requires confirmation and records approval |  |  |
| Prompt-injection attempt | Tool does not bypass policy or approval gates |  |  |
| Tool failure or timeout | Fails closed and produces diagnostic evidence |  |  |
| Rollback test | Changes can be reversed or contained |  |  |

## Decision Record

| Decision | Criteria |
| --- | --- |
| Approve | Scope is minimized, controls are operating, evidence is retained, and monitoring is ready. |
| Conditionally approve | Limited pilot is acceptable with explicit restrictions, due dates, and owner follow-up. |
| Hold | Required control, logging, ownership, or test evidence is missing. |
| Reject | Tool authority is outside risk appetite or cannot be constrained safely. |

| Final decision | Owner | Restrictions | Expiry or next review | Evidence reference |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Re-Review Triggers

Repeat this review when:

- The tool gains write, execution, credential, network, or production authority.
- The MCP server command, package, container image, endpoint, or runtime changes.
- Automatic approval settings change.
- A new data classification, repository, tenant, project, or environment is added.
- A prompt-injection, tool misuse, data exposure, credential exposure, or policy-bypass incident occurs.
- Audit logs, retention settings, or monitoring coverage change.

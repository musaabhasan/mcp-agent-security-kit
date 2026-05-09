# MCP Audit Evidence Retention Guide

Use this guide to decide what MCP security evidence should be retained after audits, release gates, incidents, and recurring reviews. It focuses on keeping enough evidence to support accountability without turning audit archives into uncontrolled stores of sensitive configuration data.

## Evidence Classes

| Evidence class | Examples | Retention purpose | Sensitivity |
| --- | --- | --- | --- |
| Audit reports | Markdown, JSON, SARIF, CI summaries, finding lists | Prove review occurred and track remediation | Medium to high |
| Configuration baselines | Approved MCP config, allowed-tool baseline, severity override policy | Compare drift and support change control | Medium |
| Finding remediation records | Owner summaries, risk-owner routing, closure notes, exception approvals | Show accountability and closure | Medium |
| Tool-permission approvals | Permission worksheet, auto-approval decision, scope justification | Explain why tool authority was granted | Medium |
| Runtime evidence | Tool invocation logs, denied actions, policy decisions, approval traces | Investigate misuse and validate controls | High |
| Credential exposure evidence | Redacted finding proof, affected path, credential type, rotation record | Support containment and recovery | High |
| Incident evidence | Timelines, preserved logs, containment, rotation, recovery gates, post-incident notes | Support incident response and audit | High |

## Retention Matrix

| Evidence | Suggested minimum | Owner | Storage expectation | Deletion or archive trigger |
| --- | --- | --- | --- | --- |
| Clean audit report for low-risk sandbox use | 90 days | Tool owner | Project evidence folder or CI artifact archive | Next clean review completes |
| Production audit report | 1 year | Security owner | Controlled security evidence repository | Superseded by reviewed baseline and period met |
| JSON/SARIF output used by dashboards | 1 year | Security engineering | Artifact store with access controls | Dashboard record superseded and period met |
| Approved MCP configuration baseline | Life of active baseline plus 1 year | Platform owner | Version-controlled repository | Baseline retired and audit window closed |
| Allowed-tool drift comparison | 1 year | Platform owner | CI artifact store or change ticket | Next periodic review completes |
| Severity override policy | Life of active policy plus 2 years | Risk owner | Version-controlled repository | Policy retired and review window closed |
| Tool permission worksheet | Life of tool permission plus 1 year | Tool owner | Governance or change-control repository | Tool permission removed and period met |
| Denied high-risk tool call logs | 1 year or incident policy if escalated | Security operations | Central logging with restricted access | No investigation or legal hold remains |
| Credential exposure evidence | Incident policy, usually 3 to 5 years | Incident owner | Incident system with redacted evidence | Incident closed and retention period met |
| Credential rotation proof | Life of affected credential plus 1 year | Credential owner | Secret-management or ticketing system | Credential retired and retention met |
| Incident response record | Incident policy, usually 3 to 5 years | Incident owner | Incident management system | Incident closed and retention period met |

## Minimization Rules

- Store redacted evidence by default; avoid retaining full secret values, tokens, cookies, private keys, or full connection strings.
- Keep enough path, environment, server, rule, and timestamp detail to support remediation without exposing unnecessary data.
- Do not copy raw MCP configuration into broad project wikis if it contains internal hostnames, identity hints, tenant IDs, or sensitive paths.
- Prefer immutable hashes for artifact integrity rather than retaining duplicate sensitive copies.
- Keep JSON/SARIF reports in a controlled artifact store when they include environment names, server names, or sensitive file paths.
- Apply legal hold or incident retention overrides before normal deletion.

## Redaction Guidance

| Data element | Recommended handling |
| --- | --- |
| Secret values | Replace with `[redacted]`; retain secret type and owning system. |
| Tokens and keys | Store hash or ticket reference, not the token itself. |
| Internal URLs | Retain hostname class or service name unless full URL is required for incident evidence. |
| User identifiers | Retain role, team, or pseudonymous identifier unless identity is required for investigation. |
| Local paths | Retain path category and filename where possible; restrict full paths when they expose usernames or private project names. |
| Command arguments | Retain sanitized command and risk-relevant flags; remove embedded credentials or private data. |

## Evidence Package Checklist

| Item | Included? | Notes |
| --- | --- | --- |
| Audit command and tool version |  |  |
| Input configuration reference or commit SHA |  |  |
| Markdown or JSON report |  |  |
| SARIF upload or code-scanning reference |  |  |
| Owner remediation summary |  |  |
| Severity override policy, if used |  |  |
| Allowed-tool baseline comparison, if used |  |  |
| Approval decision and restrictions |  |  |
| Open findings and due dates |  |  |
| Retention and deletion date |  |  |

## Review Questions

- Is the retained evidence sufficient to reconstruct the security decision?
- Does any evidence include sensitive data that should be redacted or stored elsewhere?
- Are open high or critical findings linked to accountable owners and due dates?
- Are recurring CI artifacts expiring before audit or incident-response needs are met?
- Are stale audit reports being mistaken for current approval evidence?
- Are severity overrides retained with rationale so future reviewers can understand the decision?

## Closure Record

| Evidence package | Owner | Retention met? | Deleted or archived by | Date | Reference |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

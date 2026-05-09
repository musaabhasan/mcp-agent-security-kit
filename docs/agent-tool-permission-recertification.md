# Agent Tool Permission Recertification Workflow

Use this workflow after an MCP server or agent tool has already been approved. Initial approval is not enough: tool permissions drift, owners change, integrations gain new scopes, credentials rotate, and high-impact tools become more dangerous when agents learn new workflows.

Run recertification at a fixed cadence, after major tool changes, after incidents, and before expanding an agent to new users, departments, repositories, environments, or data classes.

## Recertification Header

| Field | Value |
| --- | --- |
| Agent or assistant |  |
| MCP server or tool group |  |
| Environment | Development / Test / Production |
| Business owner |  |
| Security owner |  |
| Technical owner |  |
| Current approved baseline |  |
| Current configuration reference |  |
| Review date |  |
| Next review due |  |

## Tool Inventory Review

| Tool | Current Permission | Approved Baseline | Drift? | Owner | Decision |
| --- | --- | --- | --- | --- | --- |
|  | Read |  |  |  | Keep / Restrict / Remove |
|  | Write |  |  |  | Keep / Restrict / Remove |
|  | Execute |  |  |  | Keep / Restrict / Remove |
|  | External action |  |  |  | Keep / Restrict / Remove |
|  | Credential access |  |  |  | Keep / Restrict / Remove |

## Recertification Checks

| Check | Evidence | Status |
| --- | --- | --- |
| Business purpose is still valid | Owner attestation |  |
| Tool owner and risk owner are still assigned | Owner record |  |
| Current configuration matches approved allowed-tool baseline | Allowed-tool drift report |  |
| Added tools are reviewed before use | Change request |  |
| Wildcard tool approval is absent or formally risk-accepted | Configuration review |  |
| High-impact actions require human approval | Policy evidence |  |
| Read/write/delete/execute boundaries remain least privilege | Permission review |  |
| Network scope excludes metadata endpoints and unintended internal services | Network review |  |
| Credential-bearing paths, sockets, and profiles are not exposed | Audit report |  |
| Tool calls, policy decisions, approvals, and denials are logged | Runtime telemetry sample |  |
| Incident response and credential rotation paths are current | Playbook evidence |  |

## High-Impact Permission Decision Matrix

| Permission Type | Examples | Default Decision | Required Evidence |
| --- | --- | --- | --- |
| External communication | Email, chat, issue comments, ticket updates | Human approval required | Approval log and recipient scope |
| Source-control writes | Branches, commits, PRs, releases, tags | Human approval required | Repository scope and reviewer evidence |
| Deployment actions | CI/CD triggers, infrastructure changes | Dual approval or block | Change record and rollback plan |
| Data modification | Database writes, CRM changes, LMS updates | Human approval required | Field-level scope and audit trail |
| File deletion or movement | Workspace cleanup, evidence deletion, bulk moves | Block unless explicitly scoped | Dry-run evidence and recovery path |
| Credential operations | Token creation, secret reads, key rotation | Block or privileged review | Secret owner approval |
| Browser/session access | Cookies, local storage, profile paths, DevTools | Restrict by profile and task | Session boundary evidence |
| Runtime execution | Shell, package runners, containers, notebooks | Sandbox and approval required | Runtime isolation evidence |

## Evidence To Retain

- Approved baseline and current allowed-tool comparison.
- Current MCP configuration hash or immutable reference.
- Audit report with rule findings and owner summary.
- Runtime telemetry sample for tool call, denial, and approval events.
- Human approval policy and sample approval records.
- Credential exposure review for environment variables, headers, paths, sockets, profiles, and cloud CLI context.
- Incident response owner and credential rotation path.
- Decision record for keep, restrict, remove, or risk accept.

## Recertification Outcomes

| Outcome | Meaning | Required Follow-Up |
| --- | --- | --- |
| Keep | Tool still matches business need and approved baseline | Record next review date |
| Restrict | Tool remains needed but requires narrower scope or stronger approval | Update configuration and verify drift closure |
| Remove | Tool is no longer justified or is too risky | Remove from configuration and rotate exposed credentials if needed |
| Risk accept | Tool remains risky but temporarily required | Named owner, expiry date, compensating controls |
| Hold | Evidence is incomplete | Block expansion or production use until resolved |

## Trigger-Based Review

Run an out-of-cycle recertification when:

- a tool is added, renamed, or granted broader scope,
- an agent moves from test to production,
- new users, departments, repositories, tenants, or data classes are added,
- a credential, token, socket, browser profile, or cloud CLI context is exposed,
- runtime telemetry shows denied or unexpected tool calls,
- an incident, near miss, or prompt injection report involves tool use,
- the business owner, security owner, or technical owner changes.

## Closure Checklist

- Current configuration was compared against the approved baseline.
- Added or changed tools have owner approval.
- High-impact tools have approval and logging evidence.
- Credential and local-path exposure findings are reviewed.
- Runtime monitoring exists for tool calls and policy decisions.
- Any exceptions have owner, expiry, and compensating controls.
- Removed tools are no longer callable by the agent.
- Next review date is recorded.

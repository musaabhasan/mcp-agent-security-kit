# MCP Server Change Approval Workflow

MCP server configuration changes can quietly expand agent authority. A version bump, new tool, transport change, OAuth scope update, or runtime mount can turn a previously acceptable server into a sensitive access path. Use this workflow before approving changes to MCP servers, tool definitions, credentials, transports, runtime boundaries, or auto-approval rules.

## Change Intake

| Field | Response |
| --- | --- |
| Change ID |  |
| MCP server name |  |
| Business owner |  |
| Technical owner |  |
| Requester |  |
| Target environment | Development / test / staging / production |
| Change type | Version / tool / transport / auth / filesystem / network / runtime / policy / owner / decommission |
| Proposed release date |  |
| Related baseline config |  |
| Related audit report |  |

## Change Types and Required Review

| Change Type | Examples | Required Review |
| --- | --- | --- |
| Server package or image update | npm package version, container digest, Python package, binary path | Supply-chain review, changelog review, digest or version pinning, rollback package |
| Tool capability change | New tool, removed tool, changed tool description, broader parameters | Allowed-tool drift comparison, permission review, prompt-to-tool abuse scenarios |
| Authentication change | New OAuth scopes, token audience, service account, API key, delegated user mode | Least-privilege review, owner approval, credential rotation plan |
| Transport change | Local stdio to HTTP/SSE, new URL, TLS settings, headers, proxy, network route | TLS, authentication, network allow-list, metadata endpoint exposure review |
| Filesystem or path change | New mounts, writable directories, home directory, credential paths | Credential path exposure review, read-only enforcement, path minimization |
| Runtime boundary change | Container privilege, host networking, socket mounts, Kubernetes service account | Container, Kubernetes, CI/CD, and host escape exposure review |
| Auto-approval policy change | Added wildcard, external action auto-approval, fewer confirmations | Human approval gate, audit logging, policy simulation |
| Logging or evidence change | Disabled tool-call logs, changed retention, redaction adjustment | Audit evidence review, retention review, incident reconstruction impact |
| Owner or risk metadata change | Missing owner, changed risk owner, ownership transfer | Owner attestation, recertification date, escalation route |

## Pre-Approval Checklist

| Check | Required Evidence | Status |
| --- | --- | --- |
| Baseline and proposed config are both available | Baseline JSON, proposed JSON, diff reference | Ready / gap |
| Automated audit was run on proposed config | CLI report, JSON or SARIF output | Ready / gap |
| Allowed-tool drift was reviewed | `compare_allowed_tools.py` output or manual tool-diff record | Ready / gap |
| High-impact tools have human approval gates | Tool permission worksheet or policy evidence | Ready / gap |
| Credential and auth scope changes are least privilege | Scope list, owner approval, credential rotation plan | Ready / gap |
| Transport exposure is bounded | TLS/auth evidence, network route, metadata endpoint control | Ready / gap |
| Runtime boundaries are documented | Container flags, mounts, service account, host access, socket exposure | Ready / gap |
| Rollback path is tested | Previous package/image, config rollback, credential rollback, owner | Ready / gap |
| Monitoring and alerting are updated | Tool-call telemetry, drift signal, incident trigger, owner queue | Ready / gap |

## Diff Review Questions

Ask these questions before approving the change:

- Does the change add a tool that can write, delete, deploy, send, merge, approve, or trigger an external workflow?
- Does a tool description or parameter schema become broad enough for prompt injection to route unintended actions?
- Does the server gain access to home directories, credential files, browser profiles, SSH agents, Docker sockets, cloud CLI profiles, database clients, package registries, or CI/CD credentials?
- Does a local-only server become remote, network reachable, or dependent on HTTP headers for authentication?
- Does the change introduce wildcard auto-approval or remove confirmation for external actions?
- Does the runtime boundary move from a sandbox to a privileged container, host network, Kubernetes service account, or shared workspace?
- Does the update change evidence retention, redaction, or tool-call telemetry in a way that weakens incident reconstruction?
- Does the rollback plan cover configuration, package or image version, credentials, and user communications?

## Approval Matrix

| Risk Signal | Minimum Approval |
| --- | --- |
| Documentation-only or owner metadata update | Technical owner |
| Read-only tool addition with no sensitive data | Technical owner and risk owner |
| Sensitive read capability | Security reviewer and business owner |
| External write, messaging, deployment, merge, or workflow action | Security reviewer, business owner, and human-approval policy owner |
| Auth scope, token, service account, or credential boundary change | Security reviewer and identity owner |
| Transport becomes remote or network reachable | Security reviewer and platform owner |
| Host, container, Kubernetes, CI/CD, or credential context exposure | Security reviewer and infrastructure owner |
| Emergency change | Duty manager approval, immediate evidence capture, post-change review within 2 business days |

## Evidence Package

Retain the following with the change ticket:

- baseline configuration hash,
- proposed configuration hash,
- configuration diff,
- automated audit report,
- allowed-tool drift report,
- tool permission worksheet updates,
- owner approval record,
- credential rotation or scope evidence,
- runtime boundary review,
- rollback test evidence,
- monitoring update evidence,
- post-release validation result.

Do not store real tokens, internal secrets, private hostnames, or raw user data in general-purpose change records. Reference restricted evidence IDs instead.

## Post-Release Verification

| Verification | Pass Criteria |
| --- | --- |
| Audit rerun | No unapproved critical or high findings in production config |
| Allowed-tool baseline update | Approved baseline reflects the released tool list |
| Tool-call telemetry | New or changed tools emit expected audit events |
| Human approval gate | High-impact action requires confirmation or policy approval |
| Runtime boundary | No unexpected mounts, sockets, environment files, or cloud metadata paths |
| Rollback readiness | Previous config and credential state can be restored |
| Owner attestation | Business and technical owners accept the released state |

## Change Decision

| Field | Response |
| --- | --- |
| Decision | Approve / approve with conditions / hold / reject / emergency approve |
| Conditions |  |
| Residual risk owner |  |
| Expiration date for exception |  |
| Reviewer |  |
| Next recertification date |  |
| Evidence location |  |

## Failure and Rollback Triggers

Rollback or disable the server when:

- a new critical or high finding appears after release,
- unexpected tools are callable,
- tool-call logs are missing,
- the server can reach cloud metadata or credential paths outside the approved boundary,
- high-impact actions bypass confirmation,
- credential scope is broader than approved,
- owner cannot produce change evidence during review.

Prefer disabling the MCP server or removing the affected tool from the allowed list before rotating unrelated credentials or deleting audit evidence.

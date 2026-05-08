# Runtime Monitoring for MCP-Enabled Agents

Static configuration review should happen before an MCP server is connected to an
agent. Runtime monitoring is the second control layer: it confirms that real tool
calls, identities, approvals, data access, and network destinations continue to
match the approved design after launch.

## Monitoring Objectives

| Objective | Why it matters |
| --- | --- |
| Tool invocation visibility | Every tool call should be attributable to an agent, user, session, server, and policy decision. |
| Identity and authority correlation | Security teams need to know whether a tool acted with user credentials, service credentials, delegated OAuth tokens, or local process permissions. |
| Approval evidence | High-impact actions should preserve the request, approver, approval time, and decision context. |
| Data boundary enforcement | Sensitive files, records, prompts, embeddings, and outputs should not move into unapproved tools or endpoints. |
| Drift detection | MCP server manifests, command arguments, package versions, scopes, and remote URLs can change after initial review. |
| Incident reconstruction | Logs should support triage without storing unnecessary prompt content or secrets. |

## Recommended Event Model

Capture normalized events from agent orchestration, MCP clients, MCP servers, API
gateways, identity providers, and endpoint security tools.

| Field | Description |
| --- | --- |
| `event_id` | Stable unique identifier for the event. |
| `event_type` | One of `tool.requested`, `tool.approved`, `tool.executed`, `tool.denied`, `tool.failed`, `server.changed`, or `policy.changed`. |
| `observed_at` | UTC timestamp recorded by the monitoring system. |
| `agent_id` | Agent or assistant identifier. |
| `session_id` | Conversation, job, workflow, or task identifier. |
| `user_id` | Human user or service principal that initiated the activity. |
| `mcp_server` | MCP server name and version when available. |
| `tool_name` | Tool or method invoked by the agent. |
| `credential_context` | `user_delegated`, `service_account`, `local_process`, `ephemeral_token`, or `unknown`. |
| `policy_decision` | `allow`, `deny`, `require_approval`, or `allow_with_controls`. |
| `approval_id` | Approval reference for high-impact actions. |
| `resource_ref` | Redacted file, dataset, endpoint, ticket, repository, or system reference. |
| `data_classification` | Classification of the data touched by the tool call. |
| `egress_destination` | Remote host, domain, or service category reached by the tool. |
| `risk_score` | Numeric or categorical risk signal assigned by policy or detection logic. |
| `evidence_hash` | Hash of stored evidence where full content is retained in a controlled evidence store. |

Use stable identifiers instead of full prompt text wherever possible. When prompt
or output capture is required, apply data minimization, masking, retention limits,
and access controls.

## Detection Rules

| Detection | Signal | Suggested response |
| --- | --- | --- |
| High-risk tool without approval | `policy_decision=allow` for a tool that normally requires approval | Open an investigation, review policy history, and suspend the tool if the decision path is unexplained. |
| New or changed server manifest | Hash of server command, arguments, URL, package, or tool manifest changed | Require re-review before the server is available to production agents. |
| Unusual tool sequence | Agent calls a file, shell, browser, and external API tool in a sequence not seen in the approved workflow | Quarantine the session and inspect prompt injection or goal hijacking evidence. |
| Sensitive data egress | Classified data is sent to an unapproved remote server, SaaS endpoint, or personal workspace | Block egress, preserve evidence, and notify the data owner. |
| Credential exposure | Tool arguments, environment variables, or logs contain secret-like patterns | Rotate affected credentials and remove the secret from logs and configuration. |
| Excessive retry or burst activity | Tool calls exceed normal per-user, per-agent, or per-task volume | Rate-limit the session and check for automation loops or compromised instructions. |
| Policy bypass attempt | Denied actions are followed by semantically similar tool calls through another server | Escalate to security review and tighten equivalent-control mappings. |
| Unexpected local authority | A server executes with elevated OS privileges or broader filesystem access than approved | Disable the server and compare current runtime permissions with the approved baseline. |

## Sample Event

```json
{
  "event_id": "evt_2026_05_08_000184",
  "event_type": "tool.executed",
  "observed_at": "2026-05-08T11:42:15Z",
  "agent_id": "research-assistant-prod",
  "session_id": "case-48392",
  "user_id": "analyst@example.org",
  "mcp_server": "filesystem@1.2.4",
  "tool_name": "read_file",
  "credential_context": "user_delegated",
  "policy_decision": "allow_with_controls",
  "approval_id": null,
  "resource_ref": "sha256:7c6d6f2f...",
  "data_classification": "internal",
  "egress_destination": null,
  "risk_score": "medium",
  "evidence_hash": "sha256:9f23d92a..."
}
```

## Implementation Checklist

- Define a canonical MCP runtime event schema before production launch.
- Correlate agent sessions with identity provider logs and approval workflow records.
- Maintain a baseline hash for each approved MCP server manifest and command line.
- Log policy decisions separately from tool execution results.
- Mask secrets, personal data, and sensitive prompt fragments before indexing logs.
- Route high-risk detections into the existing security incident workflow.
- Review detection tuning after tabletop exercises and real pilot activity.
- Test recovery steps for disabling a single MCP server without shutting down the entire agent platform.

## Evidence and Retention

Runtime evidence should be useful for audit and incident response, but it should
not become an uncontrolled archive of sensitive prompts, file contents, or system
outputs. A balanced approach is to store structured metadata by default, preserve
content only for approved high-risk workflows, hash large evidence artifacts, and
apply retention periods that match the system's data classification and legal
requirements.

## Relationship to the Audit CLI

The audit CLI in this repository reviews configuration risk before deployment.
Runtime monitoring should reuse the same concepts after deployment:

- risky commands become execution telemetry signals,
- broad filesystem access becomes data boundary monitoring,
- missing ownership metadata becomes accountability enrichment,
- unencrypted remote servers become egress detection rules,
- package pinning findings become manifest drift checks.

Together, static audit and runtime monitoring give teams a practical control loop:
review the configuration, approve the operating boundary, observe real behavior,
and feed incidents or drift back into the next review.

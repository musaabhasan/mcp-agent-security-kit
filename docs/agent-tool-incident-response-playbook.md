# Agent Tool Incident Response Playbook

MCP incidents are rarely only prompt incidents. They often involve tool execution, retrieved context, credentials, filesystem access, browser state, external APIs, and downstream systems. This playbook helps responders preserve evidence and contain risk when an agent-accessible MCP server behaves unexpectedly or is suspected of being abused.

## Activation Triggers

Use this playbook when any of the following occurs:

- prompt injection causes a tool to run outside the intended task,
- a tool accesses files, credentials, browser profiles, containers, cloud APIs, databases, package registries, or CI/CD tokens unexpectedly,
- an external action is sent, published, merged, deployed, uploaded, or deleted without the expected approval,
- RAG context or tool output appears poisoned or mismatched,
- MCP audit findings are introduced after a configuration change,
- a user reports a sensitive answer or unauthorized downstream action.

## First 30 Minutes

1. Freeze the current MCP server configuration, prompt version, model/provider version, tool allowlist, and severity override policy.
2. Disable the affected tool or MCP server from production traffic.
3. Preserve audit logs, tool call traces, prompts, retrieved context, tool outputs, approval decisions, downstream API calls, and generated files.
4. Rotate or revoke directly exposed credentials if the tool had access to secrets, cloud CLIs, CI/CD tokens, package registries, database clients, SSH agents, browser profiles, or Git helpers.
5. Capture the user group, agent identity, owner, risk owner, time window, and suspected trigger.

## Evidence To Preserve

| Evidence | Purpose |
| --- | --- |
| MCP server config | Reconstruct commands, args, env, mounts, URLs, auth scopes, and approval rules |
| Prompt and system instruction versions | Determine whether instructions permitted or blocked the behavior |
| Tool invocation trace | Identify arguments, outputs, timings, approvals, and denied actions |
| Retrieved context and source metadata | Detect RAG poisoning, stale context, or cross-scope retrieval |
| Credential inventory | Identify which keys, files, sockets, profiles, or tokens may need rotation |
| Downstream logs | Confirm whether writes, sends, deploys, package publishes, or data reads occurred |
| Audit output | Compare pre-incident and post-incident MCP findings |

## Containment Decisions

| Condition | Immediate action |
| --- | --- |
| Credential exposure | Revoke token, rotate secret, remove path/socket/env exposure, and re-run audit |
| External action misuse | Disable the tool, preserve downstream logs, and require manual approval for re-enable |
| RAG poisoning | Disable the source collection, rebuild index from approved sources, and rerun retrieval tests |
| Browser/session exposure | Destroy the profile, invalidate sessions, and move to isolated ephemeral profiles |
| Container/cloud/CI authority exposure | Remove runtime socket/profile/token access and broker privileged actions |
| Repeated prompt injection success | Tighten allowlists, add confirmation gates, and add regression scenarios |

## Recovery Gates

Do not re-enable the MCP server until:

- all high and critical findings are resolved or formally accepted,
- credentials and sessions exposed during the incident are rotated or invalidated,
- external actions are reviewed for user, legal, operational, and security impact,
- the owner and risk owner approve the updated config,
- regression scenarios are added for the failure mode,
- monitoring alerts are updated for recurrence indicators.

## Post-Incident Review Questions

- Which tool boundary failed: allowlist, auth scope, credential injection, filesystem scope, browser state, network scope, or human approval?
- Did the model follow a malicious instruction, or did the tool expose too much authority even when the model behaved normally?
- Could a lower-privilege broker have satisfied the business task?
- What evidence was missing during the first response?
- Which MCP audit rule, scenario, or policy should prevent recurrence?

# MCP And Agentic Tool Threat Model

## System Boundary

An MCP-enabled agent usually has four trust zones:

1. User and prompt input.
2. Model and orchestration runtime.
3. MCP client and tool configuration.
4. MCP servers and downstream systems.

Security failures often happen at the boundary between zones 2 and 4, where a natural-language instruction becomes a real tool call.

## Primary Assets

- User identity and delegated tokens.
- Service account credentials.
- Prompt, output, and tool-call logs.
- Local files and repositories.
- Business records accessed by tools.
- Tool configuration and server package supply chain.
- Approval and audit evidence.

## Threat Scenarios

| Scenario | Description | Control Theme |
| --- | --- | --- |
| Goal hijack | The agent is redirected away from its approved objective | System prompt hardening, task bounds, monitoring |
| Tool misuse | The model calls a valid tool for an invalid purpose | Tool allowlists, argument validation, human approval |
| Prompt injection through tool output | Retrieved content tells the agent to ignore policy or exfiltrate data | Source isolation, content labeling, output inspection |
| Token exposure | Tool credentials are placed in config, logs, or model-visible state | Secret management, log filtering, scoped tokens |
| Unsafe local execution | MCP config launches shells, evaluators, or broad file access | Narrow wrappers, read-only paths, sandboxing |
| Remote server impersonation | An agent connects to an untrusted or unauthenticated MCP endpoint | TLS, server identity, allowlists, auth |
| Supply chain drift | Package runners pull a changed server implementation at runtime | Version pins, checksums, reviewed mirrors |
| Cascading action failure | One tool action triggers downstream workflow changes | Approval gates, rollback, rate limits, circuit breakers |

## Design Principles

- Treat MCP configuration as privileged code.
- Keep raw tokens out of prompts and model-visible memory.
- Use separate identities for users, agents, and tools.
- Prefer read-only tools until a write action is explicitly justified.
- Validate tool arguments before execution.
- Inspect tool outputs before they are added back into agent context.
- Log prompts, tool calls, approvals, denials, and downstream actions.
- Require human approval for high-impact, external, or irreversible actions.

## Review Questions

- Which systems can this agent read or modify?
- Which identity is used for each tool call?
- Can the agent access secrets or local files?
- Can a retrieved document influence tool execution?
- Are tool packages pinned and reviewed?
- Can the team reconstruct a decision from logs?
- What is the rollback path if a tool call is wrong?

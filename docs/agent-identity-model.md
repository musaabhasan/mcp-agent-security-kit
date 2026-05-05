# Agent Identity Model

Agentic AI systems need a clear identity model before they receive access to MCP servers, local tools, APIs, files, or enterprise workflows. The core question is not only what the model can do, but which identity is used when the action reaches a real system.

## Identity Types

| Identity | Purpose | Security Concern |
| --- | --- | --- |
| Human user | Person requesting an action | User intent must not be confused with tool authorization |
| Agent runtime | Orchestrator executing the workflow | Runtime permissions can become broader than any single user needs |
| MCP client | Component connecting the agent to tools | Client configuration can silently expand tool authority |
| MCP server | Tool endpoint exposing actions or data | Server identity, package integrity, and auth controls must be verified |
| Downstream service account | Credential used against APIs or systems | Over-scoped tokens can turn prompt injection into system action |

## Recommended Pattern

Use separate identities for the user, the agent runtime, the MCP server, and downstream systems. Avoid giving the agent a single shared admin token that bypasses user-level authorization.

```text
user identity -> agent session -> MCP client policy -> MCP server -> downstream scoped credential
```

The agent should receive only the minimum claims required to make a decision, such as user id, tenant, group, role, approval state, and correlation id. Raw tokens should stay outside the model-visible prompt and memory path.

## Authorization Decisions

| Decision Point | Question | Evidence |
| --- | --- | --- |
| User request | Is the user allowed to request this workflow? | User group, role, policy decision |
| Agent policy | Is the agent allowed to perform this action? | Tool allowlist, task boundary |
| MCP server | Is this server approved for this environment? | Server inventory, owner, version |
| Tool arguments | Are the arguments safe and in scope? | Argument validation log |
| Downstream action | Is the target system action allowed for this user or service? | API authorization result |

## Common Anti-Patterns

- Using one admin API key for every user and every agent.
- Passing raw bearer tokens into prompts, memory, logs, or tool descriptions.
- Letting retrieved content choose tools or credentials.
- Treating an MCP server package name as a trust decision.
- Allowing local filesystem or shell tools without a named owner and approval gate.
- Assuming a session id is enough to authorize a tool call.

## Minimum Production Controls

- Map each tool to a user group, owner, and data classification.
- Use delegated user tokens where user-level access must be preserved.
- Use scoped service credentials only when the agent is acting as a service.
- Validate tool arguments before execution.
- Inspect tool outputs before adding them back into agent context.
- Log identity, session, tool name, arguments, approval state, downstream target, and outcome.
- Require human approval for privileged, external, irreversible, or high-impact actions.

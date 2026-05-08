# Broad Authentication Scope Detection

MCP servers often connect agents to APIs that were originally designed for human operators or backend services. A token that looks harmless in configuration can still grant broad administrative, deletion, repository, tenant, or billing authority once the agent starts calling tools.

Rule `MCP-019` flags scope and permission declarations that look broader than a specific read or workflow-bound grant.

## What The Rule Reviews

The auditor scans nested server configuration keys such as:

- `scope`
- `scopes`
- `oauthScope`
- `oauthScopes`
- `authScope`
- `authScopes`
- `permission`
- `permissions`
- `oauthPermissions`

It flags values that contain wildcard, administrative, owner, full-access, read-write, or deletion authority.

## Examples

Risky configuration:

```json
{
  "mcpServers": {
    "github-agent": {
      "url": "https://mcp.example.com/sse",
      "headers": {
        "Authorization": "Bearer ${MCP_REMOTE_TOKEN}"
      },
      "auth": {
        "oauthScopes": ["repo:read", "admin:org", "delete:packages"]
      }
    }
  }
}
```

Safer configuration:

```json
{
  "mcpServers": {
    "github-agent": {
      "url": "https://mcp.example.com/sse",
      "headers": {
        "Authorization": "Bearer ${MCP_REMOTE_TOKEN}"
      },
      "auth": {
        "oauthScopes": ["read:issues", "read:pull_requests"]
      }
    }
  }
}
```

## Review Questions

Before approving an MCP server with broad provider scopes, confirm:

- Which exact tool action requires the scope?
- Can the workflow use a read-only or resource-specific scope?
- Does the token belong to a service account with constrained ownership?
- Are write, delete, publish, billing, user-management, and admin actions separately approved?
- Is the token short-lived or brokered at runtime?
- Are tool calls logged with the scope, policy decision, and resource target?
- Does the agent need this scope in every environment, or only in a controlled maintenance workflow?

## Recommended Controls

| Risk | Control |
| --- | --- |
| Wildcard or full-access scopes | Replace with explicit resource and action scopes |
| Administrative scopes | Require security owner approval and production-only break-glass logging |
| Delete or destructive scopes | Require human approval and idempotency safeguards before execution |
| Read-write scopes | Split read and write tool profiles so routine tasks use read-only authority |
| Long-lived provider tokens | Broker short-lived credentials and bind them to task, user, and environment |
| Shared service accounts | Use named service identities with owner, purpose, and rotation metadata |

Broad scopes are not always wrong, but they should be visible, justified, monitored, and separated from routine low-risk agent workflows.

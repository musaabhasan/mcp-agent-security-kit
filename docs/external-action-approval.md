# External-Action Approval Guard

MCP servers often expose tools that can move beyond local retrieval and change an outside system. Examples include creating tickets, sending email, posting chat messages, merging pull requests, deploying services, publishing content, uploading files, or calling arbitrary HTTP endpoints.

These capabilities are useful, but they are higher risk when placed in automatic approval lists such as `alwaysAllow`, `allowedTools`, or equivalent client settings. A malicious prompt, poisoned retrieved document, compromised tool description, or mistaken agent plan can turn a convenience setting into an unintended external action.

## What MCP-023 Detects

`MCP-023` flags auto-approved tool names that look like external write, communication, deployment, merge, upload, or request capabilities.

Examples of tool names that should not normally be auto-approved:

- `send_email`
- `post_message`
- `create_ticket`
- `update_issue`
- `merge_pull_request`
- `deploy_service`
- `publish_page`
- `http_request`
- `upload_file`

Read-only tools such as `read_file`, `search_docs`, and `list_resources` are not flagged by this rule.

## Recommended Control Pattern

External-action tools should have three layers of control:

1. Require explicit confirmation before the tool executes.
2. Evaluate policy before execution, including destination, data sensitivity, user authority, and allowed business purpose.
3. Write an audit event that records the initiating user, agent session, tool name, input summary, decision, and final outcome.

The confirmation step should be close to the action. A broad approval granted at session start is weaker than a targeted approval that shows the exact destination and effect of the proposed action.

## Safer Configuration Direction

Keep auto-approval limited to low-impact retrieval tools:

```json
{
  "mcpServers": {
    "helpdesk-agent": {
      "owner": "platform",
      "riskOwner": "security",
      "command": "node",
      "args": ["server.js"],
      "alwaysAllow": ["search_docs", "read_ticket"]
    }
  }
}
```

Route external actions through a confirmation-aware server or policy broker:

```json
{
  "mcpServers": {
    "helpdesk-actions": {
      "owner": "platform",
      "riskOwner": "security",
      "command": "node",
      "args": ["action-server.js"],
      "policy": {
        "confirmationRequired": true,
        "auditRequired": true,
        "allowedDestinations": ["internal-helpdesk"]
      }
    }
  }
}
```

## Review Questions

- Which tools can create, update, publish, send, deploy, merge, upload, or call external services?
- Are any of those tools auto-approved?
- Does the user see the exact destination and effect before execution?
- Can a poisoned document or tool description alter the action target?
- Are denied and approved attempts both retained for incident review?
- Is there a separate policy path for production systems and external recipients?


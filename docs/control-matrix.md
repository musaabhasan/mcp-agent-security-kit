# MCP Agent Security Control Matrix

| Control Area | Control | Evidence |
| --- | --- | --- |
| Inventory | Maintain an inventory of MCP servers, owners, risk owners, data access, and environments | MCP server register |
| Identity | Use distinct identities for users, agents, service accounts, and tools | IAM design, token scope review |
| Authentication | Require authentication for remote MCP servers | Server config, gateway policy, token validation |
| Authorization | Map each tool to approved actions, data classes, and user groups | Tool permission matrix |
| Least privilege | Grant read-only and narrow path access by default | Config review, access test |
| Secrets | Store tokens in a secret manager or protected local environment | Secret references, vault policy |
| Package integrity | Pin MCP package versions and container images, preferably with immutable digests, and review server updates | Lock files, image digests, release review notes |
| Prompt injection | Label untrusted content and inspect tool outputs before reuse | Test records, blocked examples |
| Human approval | Require approval for high-impact, external, privileged, or irreversible actions | Approval logs |
| Monitoring | Log prompts, tool arguments, tool outputs, denials, approvals, and downstream actions | SIEM queries, trace samples |
| Rate limiting | Limit tool-call frequency and expensive workflows | Gateway policy, runtime config |
| Isolation | Run tools in restricted environments with narrow filesystem and network access | Sandbox config |
| Change control | Review MCP config changes before production rollout | Pull requests, change records |
| Incident response | Define containment steps for tool misuse and token exposure | Playbooks, tabletop records |

## Minimum Production Gate

Before production use, every MCP-enabled agent should have:

- named owner and risk owner,
- approved use case and data classification,
- tool inventory,
- authentication and authorization design,
- secret handling review,
- prompt injection test record,
- logging and retention decision,
- rollback and incident response plan.
